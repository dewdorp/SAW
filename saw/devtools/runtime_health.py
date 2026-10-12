"""Bounded loopback runtime probes using the bundled Python TLS stack.

Only fixed SAW endpoints are supported. A failed probe never prints certificate
paths, exception text, response bodies, or operational data.
"""
from __future__ import annotations

import argparse
import http.client
import ipaddress
import json
import re
import socket
import ssl
import threading
import time
from pathlib import Path

MAX_BODY_BYTES = 1024 * 1024


class _QuietParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise ValueError('invalid health probe arguments')


def _tls_name_valid(name: str) -> bool:
    if not isinstance(name, str) or not name or len(name) > 253 or '%' in name:
        return False
    try:
        ipaddress.ip_address(name)
        return True
    except ValueError:
        return all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', label)
                   for label in name.split('.'))


class _Budget:
    def __init__(self, timeout: int):
        self.deadline = time.monotonic() + timeout
        self.socket = None
        self.lock = threading.Lock()
        self.timer = threading.Timer(timeout, self._expire)
        self.timer.daemon = True
        self.timer.start()

    def remaining(self) -> float:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('health probe deadline')
        return remaining

    def attach(self, connected) -> None:
        with self.lock:
            connected.settimeout(self.remaining())
            self.socket = connected

    def _expire(self) -> None:
        # A trickling status line/header can bypass socket per-operation timeouts.
        # Shutdown interrupts any pending header, handshake or body read at the deadline.
        with self.lock:
            if self.socket is not None:
                try:
                    self.socket.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    def close(self) -> None:
        self.timer.cancel()
        with self.lock:
            self.socket = None


class _LoopbackHTTPConnection(http.client.HTTPConnection):
    def __init__(self, *args, budget: _Budget, **kwargs):
        self.budget = budget
        super().__init__(*args, **kwargs)

    def connect(self) -> None:
        self.sock = socket.create_connection(('127.0.0.1', self.port), self.budget.remaining())
        self.budget.attach(self.sock)


class _LoopbackHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, *args, budget: _Budget, **kwargs):
        self.budget = budget
        super().__init__(*args, **kwargs)

    def connect(self) -> None:
        # The TLS identity must never become a DNS/network destination.
        plain = socket.create_connection(('127.0.0.1', self.port), self.budget.remaining())
        self.sock = plain
        self.budget.attach(plain)
        self.sock = self._context.wrap_socket(plain, server_hostname=self.host, do_handshake_on_connect=False)
        self.budget.attach(self.sock)
        self.sock.do_handshake()


def _reject_json_constant(_value: str):
    raise ValueError('nonstandard JSON constant')


def _valid_body(kind: str, body: object) -> bool:
    if not isinstance(body, dict):
        return False
    if kind == 'api':
        return body.get('status') == 'ok'
    if kind == 'opensearch':
        return body.get('cluster_name') == 'saw' and body.get('status') in ('green', 'yellow')
    shards = body.get('_shards')
    if not isinstance(shards, dict):
        return False
    return (all(type(shards.get(field)) is int and shards[field] >= 0
                for field in ('total', 'successful', 'failed'))
            and shards['failed'] == 0 and shards['successful'] <= shards['total'])


def check(kind: str, port: int, ca: str | Path | None = None, tls_name: str = 'localhost') -> bool:
    """Return status only; no redirects, external destinations or environment proxies."""
    connection = None
    budget = None
    try:
        if kind not in ('api', 'opensearch', 'flush') or type(port) is not int or not 1 <= port <= 65535:
            return False
        timeout = 60 if kind == 'flush' else 3
        budget = _Budget(timeout)
        if kind == 'api':
            if ca is None or not Path(ca).is_absolute() or Path(ca).drive.startswith('\\\\') or not _tls_name_valid(tls_name):
                return False
            # Keep the platform's trust roots and explicitly add the installation CA.
            context = ssl.create_default_context()
            context.load_verify_locations(cafile=str(ca))
            connection = _LoopbackHTTPSConnection(tls_name, port, context=context, timeout=timeout, budget=budget)
            path = '/api/v1/health'
        else:
            connection = _LoopbackHTTPConnection('127.0.0.1', port, timeout=timeout, budget=budget)
            path = '/_flush?wait_if_ongoing=true' if kind == 'flush' else '/_cluster/health'
        connection.request('POST' if kind == 'flush' else 'GET', path, body=b'' if kind == 'flush' else None)
        with connection.getresponse() as response:
            if response.status != 200:
                return False
            raw = bytearray()
            while len(raw) <= MAX_BODY_BYTES:
                budget.socket.settimeout(budget.remaining())
                chunk = response.read1(min(65536, MAX_BODY_BYTES + 1 - len(raw)))
                raw.extend(chunk)
                if not chunk or response.isclosed():
                    break
        if len(raw) > MAX_BODY_BYTES:
            return False
        valid = _valid_body(kind, json.loads(raw.decode('utf-8'), parse_constant=_reject_json_constant))
        budget.remaining()
        return valid
    except Exception:
        # Health is a fail-closed boundary, including malformed/deep JSON and TLS errors.
        return False
    finally:
        if budget is not None:
            budget.close()
        if connection is not None:
            connection.close()


def main(argv: list[str] | None = None) -> int:
    parser = _QuietParser(add_help=False, allow_abbrev=False)
    parser.add_argument('--kind', choices=('api', 'opensearch', 'flush'), required=True)
    parser.add_argument('--port', type=int, required=True)
    parser.add_argument('--ca')
    parser.add_argument('--tls-name', default='localhost')
    try:
        args = parser.parse_args(argv)
        success = check(args.kind, args.port, args.ca, args.tls_name)
    except Exception:
        success = False
    print('ok' if success else 'failed')
    return 0 if success else 1


if __name__ == '__main__':
    raise SystemExit(main())
