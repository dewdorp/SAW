"""Common web server log formats: each is recognised by its own parser and keeps the fields analysis needs."""
import pytest

from saw.parsers.base import Failed, Parsed
from saw.parsers.registry import detect, parse_text
from saw.parsers.web import (
    ApacheErrorParser,
    HAProxyHttpParser,
    NginxErrorParser,
    VhostCombinedParser,
    WebJsonAccessParser,
)

VHOST = ('shop.example.test:443 198.51.100.9 - - [03/Nov/2026:10:00:01 +0900] "GET /cart?item=3 HTTP/1.1" 200 5120 '
         '"-" "Mozilla/5.0 (Windows NT 10.0)"')
HAPROXY = ('Nov  3 10:00:01 lb01 haproxy[2201]: 198.51.100.40:51234 [03/Nov/2026:10:00:01.123] fe_https~ be_shop/app01 '
           '0/0/1/12/13 500 2750 - - ---- 3/3/0/0/0 0/0 {shop.example.test|sqlmap/1.8.4#stable} "GET /product/view?id=1%27 HTTP/1.1"')
NGINX_JSON = ('{"time_iso8601":"2026-11-03T10:00:01+09:00","remote_addr":"10.60.7.19","request":"GET /export/a.csv HTTP/1.1",'
              '"status":200,"body_bytes_sent":2000000,"http_user_agent":"Mozilla/5.0","request_time":0.031,"host":"files.example.test"}')
CADDY = ('{"level":"info","ts":1793667601.5,"logger":"http.log.access","msg":"handled request","request":{"remote_ip":"10.70.1.5",'
         '"proto":"HTTP/2.0","method":"GET","host":"portal.example.test","uri":"/approval/list","headers":{"User-Agent":["Mozilla/5.0"]}},'
         '"size":1200,"status":200,"duration":0.004}')
APACHE_ERR = ('[Tue Nov 03 10:00:01.123456 2026] [security2:error] [pid 3121:tid 140221] [client 203.0.113.77:52110] '
              'ModSecurity: Access denied with code 403 (phase 2). [id "949110"] [msg "Inbound Anomaly Score Exceeded"] '
              '[hostname "shop.example.test"] [uri "/product/view"]')
APACHE_ERR_PLAIN = ('[Tue Nov 03 10:00:02.000001 2026] [authz_core:error] [pid 3121:tid 140221] [client 198.51.100.3:50000] '
                    'AH01630: client denied by server configuration: /var/www/shop/.htaccess')
NGINX_ERR = ('2026/11/03 10:00:01 [error] 2214#2214: *1201 open() "/usr/share/nginx/html/.env" failed (2: No such file or directory), '
             'client: 198.51.100.61, server: www.example.test, request: "GET /.env HTTP/1.1", host: "www.example.test"')


def test_vhost_combined_keeps_the_virtual_host_and_port():
    r = VhostCombinedParser().parse_line(VHOST)
    assert isinstance(r, Parsed)
    assert r.fields["hostname"] == "shop.example.test" and r.fields["dst_port"] == "443"
    assert r.fields["src_ip"] == "198.51.100.9" and r.fields["uri"] == "/cart?item=3" and r.fields["status_code"] == "200"
    # an address first is the plain combined format, not a virtual host
    assert isinstance(VhostCombinedParser().parse_line(VHOST.split(" ", 1)[1]), Failed)


def test_haproxy_http_log_reads_client_request_status_and_captured_headers():
    r = HAProxyHttpParser().parse_line(HAPROXY)
    assert isinstance(r, Parsed)
    f = r.fields
    assert (f["src_ip"], f["src_port"], f["status_code"], f["bytes_out"]) == ("198.51.100.40", "51234", "500", "2750")
    assert f["method"] == "GET" and f["uri"] == "/product/view?id=1%27"
    assert f["hostname"] == "shop.example.test" and f["user_agent"].startswith("sqlmap/")
    assert r.ext["backend"] == "be_shop" and r.ext["request_time"] == 0.013


@pytest.mark.parametrize("line,src,uri,ua", [(NGINX_JSON, "10.60.7.19", "/export/a.csv", "Mozilla/5.0"),
                                              (CADDY, "10.70.1.5", "/approval/list", "Mozilla/5.0")])
def test_json_access_logs_from_nginx_and_caddy(line, src, uri, ua):
    r = WebJsonAccessParser().parse_line(line)
    assert isinstance(r, Parsed)
    assert r.fields["src_ip"] == src and r.fields["uri"] == uri and r.fields["user_agent"] == ua
    assert r.fields["status_code"] == "200" and r.fields["method"] == "GET"


def test_json_without_a_request_is_not_called_a_web_access_log():
    assert isinstance(WebJsonAccessParser().parse_line('{"level":"info","msg":"started","pid":12}'), Failed)


def test_apache_error_log_with_modsecurity_becomes_a_waf_event():
    r = ApacheErrorParser().parse_line(APACHE_ERR)
    assert isinstance(r, Parsed)
    assert r.fields["data_source"] == "waf" and r.fields["action"] == "blocked" and r.fields["status_code"] == "403"
    assert r.fields["uri"] == "/product/view" and r.fields["src_ip"] == "203.0.113.77"
    assert r.ext["modsecurity_id"] == "949110"
    plain = ApacheErrorParser().parse_line(APACHE_ERR_PLAIN)
    assert plain.ext["error_code"] == "AH01630" and plain.ext["file_path"] == "/var/www/shop/.htaccess"
    assert "uri" not in plain.fields  # a file on the server is not the requested address


def test_nginx_error_log_reads_the_request_and_error_kind():
    r = NginxErrorParser().parse_line(NGINX_ERR)
    assert isinstance(r, Parsed)
    assert r.fields["src_ip"] == "198.51.100.61" and r.fields["uri"] == "/.env" and r.fields["hostname"] == "www.example.test"
    assert r.ext["error_kind"] == "file_not_found" and r.ext["server"] == "www.example.test"


@pytest.mark.parametrize("line,parser", [(VHOST, "apache_vhost_combined"), (HAPROXY, "haproxy_http"),
                                         (NGINX_JSON, "web_json_access"), (CADDY, "web_json_access"),
                                         (APACHE_ERR, "apache_error"), (NGINX_ERR, "nginx_error")])
def test_automatic_detection_picks_the_web_parser(line, parser):
    assert detect([line] * 5).parser_id == parser


def test_times_without_offsets_follow_the_assumed_zone_and_apache_error_time_is_read():
    ev = parse_text(APACHE_ERR_PLAIN)["events"][0]
    assert ev["timestamp"] == "2026-11-03T01:00:02.000Z"
    ev = parse_text(HAPROXY)["events"][0]
    assert ev["timestamp"] == "2026-11-03T01:00:01.123Z"
