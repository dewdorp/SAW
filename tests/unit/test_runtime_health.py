"""Loopback health checks use the bundled Python TLS stack and disclose no response bodies."""
from __future__ import annotations

import importlib
import json
import socket
import ssl
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


@pytest.fixture
def health():
    return importlib.import_module('saw.devtools.runtime_health')


@contextmanager
def server(payload=b'{"status":"ok"}', *, status=200, tls=None, headers=None, body_interval=0, header_interval=0):
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append((self.command, self.path))
            self.send_response(status)
            for name, value in (headers or {}).items():
                self.send_header(name, value)
            if header_interval:
                self._headers_buffer.append(b'\r\n')
                for byte in b''.join(self._headers_buffer):
                    try:
                        self.wfile.write(bytes([byte]))
                        self.wfile.flush()
                        time.sleep(header_interval)
                    except OSError:
                        return
            else:
                self.end_headers()
            try:
                if body_interval:
                    for byte in payload:
                        self.wfile.write(bytes([byte]))
                        self.wfile.flush()
                        time.sleep(body_interval)
                else:
                    self.wfile.write(payload)
            except OSError:
                pass

        do_POST = do_GET

        def log_message(self, *_):
            pass

    listener = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    listener.daemon_threads = True
    if tls:
        listener.socket = tls.wrap_socket(listener.socket, server_side=True)
    thread = threading.Thread(target=listener.serve_forever, kwargs={'poll_interval': 0.02}, daemon=True)
    thread.start()
    try:
        yield listener.server_port, requests
    finally:
        listener.shutdown()
        listener.server_close()
        thread.join(timeout=3)


def tls_files(tmp_path, hostname='localhost'):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=1)).add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), False).sign(key, hashes.SHA256()))
    ca = tmp_path / (hostname + '.crt')
    secret = tmp_path / (hostname + '.key')
    ca.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    secret.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                        serialization.NoEncryption()))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(ca, secret)
    return context, ca


def test_actual_tls_checks_chain_hostname_and_exact_api_path(health, tmp_path):
    context, ca = tls_files(tmp_path)
    with server(tls=context) as (port, requests):
        assert health.check('api', port, ca)
        assert requests == [('GET', '/api/v1/health')]
        _, unrelated_ca = tls_files(tmp_path, 'unrelated.invalid')
        assert not health.check('api', port, unrelated_ca)
    mismatch, mismatch_ca = tls_files(tmp_path, 'wrong.invalid')
    with server(tls=mismatch) as (port, requests):
        assert not health.check('api', port, mismatch_ca)
        assert not requests


@pytest.mark.parametrize('payload', [b'{}', b'null', b'[]', b'{"status":true}', b'{"status":"error"}', b'not json'])
def test_api_rejects_invalid_success_body(health, tmp_path, payload):
    context, ca = tls_files(tmp_path)
    with server(payload, tls=context) as (port, _):
        assert not health.check('api', port, ca)


def test_actual_http_503_refusal_and_cli_never_expose_raw_body(health, capsys):
    with server(b'private-response-marker', status=503) as (port, _):
        assert health.main(['--kind', 'opensearch', '--port', str(port)]) == 1
    with socket.socket() as unused:
        unused.bind(('127.0.0.1', 0))
        refused_port = unused.getsockname()[1]
    assert not health.check('opensearch', refused_port)
    assert capsys.readouterr().out == 'failed\n'


@pytest.mark.parametrize('body, expected', [
    ({'cluster_name': 'saw', 'status': 'green'}, True),
    ({'cluster_name': 'saw', 'status': 'yellow'}, True),
    ({'cluster_name': 'saw', 'status': 'red'}, False),
    ({'cluster_name': 'other', 'status': 'green'}, False),
    ({'cluster_name': 'saw', 'status': True}, False),
    ([], False),
])
def test_actual_opensearch_body_and_path(health, body, expected):
    with server(json.dumps(body).encode()) as (port, requests):
        assert health.check('opensearch', port) is expected
        assert requests == [('GET', '/_cluster/health')]


@pytest.mark.parametrize('shards, expected', [
    ({'total': 2, 'successful': 1, 'failed': 0}, True),
    ({'total': 0, 'successful': 0, 'failed': 0}, True),
    ({'total': 2, 'successful': 1, 'failed': 1}, False),
    ({'total': 2, 'successful': 1, 'failed': False}, False),
    ({'total': 2, 'successful': 1, 'failed': '0'}, False),
    ({'failed': 0}, False),
    ({'total': -1, 'successful': 0, 'failed': 0}, False),
    ({'total': 1, 'successful': 2, 'failed': 0}, False),
    ([], False),
])
def test_actual_flush_post_validates_shards(health, shards, expected):
    with server(json.dumps({'_shards': shards}).encode()) as (port, requests):
        assert health.check('flush', port) is expected
        assert requests == [('POST', '/_flush?wait_if_ongoing=true')]


def test_proxy_variables_ignored_and_redirect_never_followed(health, monkeypatch):
    for name in ('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'all_proxy'):
        monkeypatch.setenv(name, 'http://127.0.0.1:1')
    monkeypatch.setenv('NO_PROXY', '')
    monkeypatch.setenv('no_proxy', '')
    good = b'{"cluster_name":"saw","status":"green"}'
    with server(good) as (target, requests):
        assert health.check('opensearch', target)
        with server(status=302, headers={'Location': f'http://127.0.0.1:{target}/_cluster/health'}) as (port, _):
            assert not health.check('opensearch', port)
        assert requests == [('GET', '/_cluster/health')]


def test_maximum_body_size_is_enforced_without_printing_content(health, capsys):
    with server(b' ' * (1024 * 1024) + b'{"cluster_name":"saw","status":"green"}') as (port, _):
        assert not health.check('opensearch', port)
    assert capsys.readouterr().out == ''


@pytest.mark.parametrize('args', [[], ['--kind', 'opensearch', '--port', '0'],
    ['--kind', 'opensearch', '--port', '65536'], ['--kind', 'opensearch', '--port', 'secret-port'],
    ['--kind', 'api', '--port', '443'], ['--kind', 'api', '--port', '443', '--ca', 'relative/private.crt'],
    ['--kind', 'opensearch', '--port', '80', '--url', 'https://private-marker.invalid'],
])
def test_cli_rejects_unsafe_arguments_with_fixed_message(health, capsys, args):
    assert health.main(args) == 1
    output = capsys.readouterr()
    assert output.out == 'failed\n'
    assert output.err == ''


def test_cli_module_returns_success_for_actual_http(tmp_path):
    with server(b'{"cluster_name":"saw","status":"green"}') as (port, _):
        result = subprocess.run([sys.executable, '-B', '-m', 'saw.devtools.runtime_health', '--kind', 'opensearch',
                                 '--port', str(port)], cwd=Path(__file__).resolve().parents[2], capture_output=True, timeout=10)
    assert result.returncode == 0
    assert result.stdout == b'ok\n' or result.stdout == b'ok\r\n'
    assert not result.stderr



def test_custom_tls_name_is_verified_but_socket_always_stays_on_loopback(health, tmp_path, monkeypatch):
    context, ca = tls_files(tmp_path, 'saw.example.invalid')
    connect = socket.create_connection
    destinations = []

    def local_only(address, *args, **kwargs):
        destinations.append(address)
        assert address[0] == '127.0.0.1'
        return connect(address, *args, **kwargs)

    with server(tls=context) as (port, requests):
        monkeypatch.setattr(socket, 'create_connection', local_only)
        assert health.check('api', port, ca, 'saw.example.invalid')
        assert not health.check('api', port, ca, 'different.example.invalid')
        assert destinations == [('127.0.0.1', port), ('127.0.0.1', port)]
        assert requests == [('GET', '/api/v1/health')]


@pytest.mark.parametrize('name', ['https://localhost', 'host:443/path', 'host\r\nInjected: value', 'a b', '../host', '', 'a' * 254])
def test_tls_name_refuses_url_control_and_invalid_dns(health, tmp_path, name):
    _, ca = tls_files(tmp_path)
    assert not health.check('api', 443, ca, name)



def test_slow_trickle_body_cannot_extend_total_api_budget(health):
    started = time.monotonic()
    with server(b'{"cluster_name":"saw","status":"green"}', body_interval=0.12) as (port, _):
        assert not health.check('opensearch', port)
    assert 2.5 <= time.monotonic() - started < 4.2


@pytest.mark.parametrize('constant', ['NaN', 'Infinity', '-Infinity'])
def test_nonstandard_json_constants_fail_closed(health, constant):
    body = ('{"cluster_name":"saw","status":"green","extra":' + constant + '}').encode()
    with server(body) as (port, _):
        assert not health.check('opensearch', port)



def test_slow_trickle_headers_cannot_extend_total_api_budget(health):
    started = time.monotonic()
    with server(b'{"cluster_name":"saw","status":"green"}', header_interval=0.12) as (port, _):
        assert not health.check('opensearch', port)
    assert 2.5 <= time.monotonic() - started < 4.2
