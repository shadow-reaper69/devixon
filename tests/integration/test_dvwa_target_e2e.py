"""
Integration test for DEVIXON URL Target Support:
Simulates a multi-application environment with CTFd on one port and DVWA on another port under /DVWA/.
Verifies:
- Requests reach the DVWA port
- Crawling starts at /DVWA/
- Discovered paths remain strictly under the permitted DVWA scope
- CTFd routes from the other port do not leak or appear in this assessment
- Reports show the exact target URL
"""

import threading
import time
import socket
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse
import pytest
from devixon.core.target import parse_canonical_target
from devixon.core.scope import ScopeProfile
from devixon.database.session import init_db, get_session
from devixon.database.repository import AssessmentRepository
from devixon.database.models import LiveHost, DiscoveredPath, InternalLink, Endpoint
from devixon.recon.base import ScanContext
from devixon.recon.pipeline import ReconPipeline
from devixon.reports.generator import ReportGenerator


def get_free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class CTFdMockHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<h1>CTFd Competition Platform</h1><a href='/challenges/crypto'>Crypto</a>")

    def log_message(self, format, *args):
        pass


class DVWAMockHandler(BaseHTTPRequestHandler):
    def __init__(self, *args, ctfd_port=None, **kwargs):
        self.ctfd_port = ctfd_port
        super().__init__(*args, **kwargs)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path in ("/DVWA/", "/DVWA/index.php", "/DVWA"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Server", "Apache/2.4.41 (Ubuntu)")
            self.end_headers()
            ctfd_link = f"http://127.0.0.1:{self.ctfd_port}/challenges"
            html = f"""
            <!DOCTYPE html>
            <html>
            <head><title>Damn Vulnerable Web Application (DVWA)</title></head>
            <body>
                <h1>DVWA Vulnerability Lab</h1>
                <a href="/DVWA/vulnerabilities/sqli/">SQL Injection Lab</a>
                <a href="/DVWA/setup.php">Setup & Check</a>
                <a href="{ctfd_link}">Link to CTFd Platform</a>
                <a href="/phpmyadmin/index.php">phpMyAdmin Outside Scope</a>
                <a href="/DVWA/../secret">Traversal Link</a>
                <script src="/DVWA/static/app.js"></script>
            </body>
            </html>
            """
            self.wfile.write(html.encode("utf-8"))

        elif path.startswith("/DVWA/vulnerabilities/sqli"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            html = """
            <html><body>
                <h2>Vulnerability: SQL Injection</h2>
                <form action="/DVWA/vulnerabilities/sqli/" method="GET">
                    <input type="text" name="id" value="1">
                    <input type="submit" name="Submit" value="Submit">
                </form>
            </body></html>
            """
            self.wfile.write(html.encode("utf-8"))

        elif path == "/DVWA/setup.php":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<h1>DVWA Database Setup</h1>")

        elif path == "/DVWA/robots.txt":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"User-agent: *\nDisallow: /DVWA/admin\n")

        elif path == "/DVWA/admin":
            self.send_response(403)
            self.end_headers()

        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass


@pytest.fixture(scope="module")
def multi_app_lab():
    init_db()
    ctfd_port = get_free_port()
    dvwa_port = get_free_port()

    # 1. Start CTFd mock
    ctfd_httpd = HTTPServer(("127.0.0.1", ctfd_port), CTFdMockHandler)
    t_ctfd = threading.Thread(target=ctfd_httpd.serve_forever, daemon=True)
    t_ctfd.start()

    # 2. Start DVWA mock
    def dvwa_handler_factory(*args, **kwargs):
        return DVWAMockHandler(*args, ctfd_port=ctfd_port, **kwargs)

    dvwa_httpd = HTTPServer(("127.0.0.1", dvwa_port), dvwa_handler_factory)
    t_dvwa = threading.Thread(target=dvwa_httpd.serve_forever, daemon=True)
    t_dvwa.start()

    time.sleep(0.5)

    yield {
        "ctfd_port": ctfd_port,
        "dvwa_port": dvwa_port,
        "dvwa_target": f"http://127.0.0.1:{dvwa_port}/DVWA/",
    }

    ctfd_httpd.shutdown()
    dvwa_httpd.shutdown()


@pytest.mark.asyncio
async def test_dvwa_target_pipeline_e2e(multi_app_lab, tmp_path):
    dvwa_target = multi_app_lab["dvwa_target"]
    dvwa_port = multi_app_lab["dvwa_port"]
    ctfd_port = multi_app_lab["ctfd_port"]

    target_model = parse_canonical_target(dvwa_target)
    assert target_model.port == dvwa_port
    assert target_model.base_path == "/DVWA/"
    assert target_model.service_identity == f"http://127.0.0.1:{dvwa_port}"

    # Configure scope specifically for dvwa_local_lab
    scope = ScopeProfile(
        name="dvwa_local_lab",
        primary_domain=dvwa_target,
        allowed_ips=["127.0.0.1"],
        allowed_ports=[dvwa_port],
        allowed_paths=["/DVWA/"],
        authorized_by_user=True,
    )

    session = get_session()
    repo = AssessmentRepository(session)
    assessment = repo.create_assessment(
        target=dvwa_target,
        scope_profile_json=scope.model_dump_json(),
        scan_profile="FULL",
    )
    assessment_id = assessment.id
    session.close()

    ctx = ScanContext(
        assessment_id=assessment_id,
        target=dvwa_target,
        scope_profile=scope,
        scan_profile="FULL",
        target_model=target_model,
    )

    pipeline = ReconPipeline(ctx)
    await pipeline.execute_all()

    # Verify Database Persistence
    session = get_session()
    try:
        # 1. Live hosts reached port dvwa_port
        hosts = session.query(LiveHost).filter_by(assessment_id=assessment_id).all()
        assert len(hosts) >= 1
        live_urls = [h.url for h in hosts]
        assert any(str(dvwa_port) in u for u in live_urls)
        # Ensure CTFd port does not appear in live hosts
        assert not any(str(ctfd_port) in u for u in live_urls)

        # 2. Crawling started at /DVWA/ and extracted links
        links = session.query(InternalLink).filter_by(assessment_id=assessment_id).all()
        assert len(links) >= 1

        # The out-of-scope link to CTFd must be marked is_internal=False
        ctfd_links = [l for l in links if str(ctfd_port) in l.destination_url]
        for l in ctfd_links:
            assert l.is_internal is False

        # Out-of-scope path /phpmyadmin must be marked is_internal=False
        phpmyadmin_links = [l for l in links if "phpmyadmin" in l.destination_url]
        for l in phpmyadmin_links:
            assert l.is_internal is False

        # 3. Discovered paths remain under /DVWA/
        paths = session.query(DiscoveredPath).filter_by(assessment_id=assessment_id).all()
        for p in paths:
            assert p.path.startswith("/DVWA"), f"Path leaked outside /DVWA: {p.path}"

        # 4. Endpoints extracted
        endpoints = session.query(Endpoint).filter_by(assessment_id=assessment_id).all()
        for ep in endpoints:
            assert str(ctfd_port) not in ep.url
            assert "challenges" not in ep.url
            assert ep.path.startswith("/DVWA")

    finally:
        session.close()

    # 5. Verify Report Generation shows the exact target URL
    report_gen = ReportGenerator()
    md_path = tmp_path / "dvwa_report.md"
    html_path = tmp_path / "dvwa_report.html"

    report_gen.generate_markdown(assessment, [], [], md_path)
    report_gen.generate_html(assessment, [], [], html_path)

    md_content = md_path.read_text(encoding="utf-8")
    html_content = html_path.read_text(encoding="utf-8")

    assert dvwa_target in md_content
    assert dvwa_target in html_content
    assert f"**Target**: `{dvwa_target}`" in md_content
    assert str(ctfd_port) not in md_content
