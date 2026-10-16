"""Reports must render with a strict CSP that permits only their own stylesheet."""
import base64
import hashlib
import re
from tests.api.test_behavior import run
from tests.api.test_guidance import make_case


def test_behavior_report_csp_permits_exact_style_and_blocks_active_content(analyst):
    inv = make_case(analyst, 3)
    saved = run(analyst, inv)
    response = analyst.get(f"/investigations/{inv['id']}/behavior/{saved['id']}/report")
    assert response.status_code == 200
    styles = re.findall(r"<style>(.*?)</style>", response.text, re.S)
    assert len(styles) == 1
    digest = base64.b64encode(hashlib.sha256(styles[0].encode()).digest()).decode()
    csp = response.headers["content-security-policy"]
    assert "default-src 'none'" in csp
    assert f"style-src 'sha256-{digest}'" in csp
    assert "unsafe-inline" not in csp and "unsafe-eval" not in csp
    assert "frame-ancestors 'none'" in csp
    assert response.headers["cache-control"] == "no-store"
    assert "<script" not in response.text
