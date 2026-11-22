"""
End-to-End Integration Tests for DEVIXON Reconnaissance Pipeline.
Spins up a real local HTTP server to verify that the crawler, live host prober,
internal link extractor, path discoverer, and parameter extractor collect real data
and persist to SQLite.
"""

import threading
import time
import socket
from http.server import HTTPServer, BaseHTTPRequestHandler
import pytest
from devixon.core.scope import ScopeProfile
from devixon.database.session import init_db, get_session
from devixon.database.repository import AssessmentRepository
from devixon.database.models import (
    LiveHost,
    DiscoveredPath,
    InternalLink,
    Endpoint,
    Parameter,
    Subdomain,
)
from devixon.recon.base import ScanContext
from devixon.recon.pipeline import ReconPipeline


class MockTargetServer(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/" or self.path == "/index.html":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Server", "DEVIXON-TestServer/1.0")
            self.send_header("X-Powered-By", "MockEngine")
            self.end_headers()
            html = """
            <!DOCTYPE html>
            <html>
            <head><title>Test Target Application</title></head>
            <body>
                <h1>Welcome to Authorized Test App</h1>
                <a href="/dashboard">Dashboard</a>
                <a href="/users?page=1&limit=25">Users Directory</a>
                <a href="https://external-thirdparty.com/tracker">Out of scope link</a>
                <form action="/login" method="POST">
                    <input type="text" name="user">
                </form>
                <script src="/static/app.js"></script>
            </body>
            </html>
            """
            self.wfile.write(html.encode("utf-8"))

        elif self.path.startswith("/dashboard"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<h1>Dashboard Protected Area</h1>")

        elif self.path.startswith("/users"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"users": ["alice", "bob"]}')

        elif self.path == "/robots.txt":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"User-agent: *\nDisallow: /admin\n")

        elif self.path == "/admin":
            self.send_response(403)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<h1>403 Forbidden - Admin Access</h1>")

        elif self.path == "/static/app.js":
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.end_headers()
            js_code = """
            const apiBase = "/api/v1/auth";
            console.log("App initialized with route: " + apiBase);
            //# sourceMappingURL=/static/app.js.map
            """
            self.wfile.write(js_code.encode("utf-8"))

        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass  # Suppress stdout noise during tests


@pytest.fixture(scope="module")
def local_http_server():
    # Find free port
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("", 0))
    port = s.getsockname()[1]
    s.close()

    server = HTTPServer(("127.0.0.1", port), MockTargetServer)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.1)

    yield f"127.0.0.1:{port}"

    server.shutdown()
    server.server_close()


@pytest.mark.asyncio
async def test_full_recon_pipeline_e2e(tmp_path, local_http_server):
    db_file = tmp_path / "test_recon_e2e.db"
    init_db(str(db_file))
    session = get_session(str(db_file))
    repo = AssessmentRepository(session)

    target_host = local_http_server
    scope = ScopeProfile(
        primary_domain=target_host,
        allowed_domains=[target_host],
        authorized_by_user=True,
    )

    assessment = repo.create_assessment(
        target=target_host,
        scope_profile_json=scope.model_dump_json(),
        scan_profile="FULL",
    )

    ctx = ScanContext(
        assessment_id=assessment.id,
        target=target_host,
        scope_profile=scope,
        scan_profile="FULL",
    )

    pipeline = ReconPipeline(ctx)
    await pipeline.execute_all()

    # 1. Verify Subdomain status for IP/localhost
    subdomains = session.query(Subdomain).filter(Subdomain.assessment_id == assessment.id).all()
    assert len(subdomains) >= 1
    assert subdomains[0].resolution_status == "NOT_APPLICABLE"

    # 2. Verify LiveHost discovery
    live_hosts = session.query(LiveHost).filter(LiveHost.assessment_id == assessment.id).all()
    assert len(live_hosts) >= 1
    host_urls = [lh.url for lh in live_hosts]
    assert any("http://" in u for u in host_urls)
    assert any("Test Target Application" in (lh.title or "") for lh in live_hosts)

    # 3. Verify InternalLink discovery
    links = session.query(InternalLink).filter(InternalLink.assessment_id == assessment.id).all()
    assert len(links) >= 1
    dests = [lk.destination_url for lk in links]
    # Check that in-scope links were found
    assert any("/dashboard" in d for d in dests)
    assert any("/users" in d for d in dests)
    assert any("/login" in d for d in dests)
    assert any("/static/app.js" in d for d in dests)
    # Check external link classification
    ext_link = next((lk for lk in links if "external-thirdparty.com" in lk.destination_url), None)
    assert ext_link is not None
    assert ext_link.is_internal is False

    # 4. Verify DiscoveredPath discovery
    paths = session.query(DiscoveredPath).filter(DiscoveredPath.assessment_id == assessment.id).all()
    discovered_routes = [p.path for p in paths]
    assert "/robots.txt" in discovered_routes
    assert "/admin" in discovered_routes

    # 5. Verify Endpoints & Parameters
    endpoints = session.query(Endpoint).filter(Endpoint.assessment_id == assessment.id).all()
    assert len(endpoints) >= 1

    params = session.query(Parameter).filter(Parameter.assessment_id == assessment.id).all()
    param_names = [p.name for p in params]
    assert "page" in param_names
    assert "limit" in param_names

    session.close()
