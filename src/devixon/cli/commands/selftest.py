"""
CLI Self-Test Suite.
Verifies target normalization, scope engine, database transactions, CVSS calculations, and pipeline readiness.
"""

import typer
from rich.console import Console
from devixon.core.scope import ScopeProfile, normalize_target
from devixon.security.cvss import calculate_cvss_base
from devixon.database.session import init_db, get_session
from devixon.database.repository import AssessmentRepository
from devixon.database.models import Assessment

console = Console()


def selftest_command():
    """Run comprehensive internal self-tests."""
    console.print("\n[bold cyan]DEVIXON SELF-TEST SUITE[/bold cyan]\n")
    passed = 0
    total = 0

    def check(name: str, cond: bool):
        nonlocal passed, total
        total += 1
        if cond:
            passed += 1
            console.print(f" [green]PASS[/green]  {name}")
        else:
            console.print(f" [red]FAIL[/red]  {name}")

    # 1. Target Normalization Tests
    check("Target URL stripping", normalize_target("https://api.example.com:8443/v1/test") == "api.example.com")
    check("Target lowercase normalization", normalize_target("SUB.EXAMPLE.COM") == "sub.example.com")

    # 2. Scope Engine Tests
    scope = ScopeProfile(
        primary_domain="example.com",
        allowed_domains=["*.example.com"],
        allowed_ips=["192.168.1.0/24"],
        excluded_targets=["admin.example.com"],
        excluded_paths=["/logout"],
        authorized_by_user=True,
    )
    in_s, _ = scope.is_in_scope("app.example.com")
    check("Scope wildcard subdomain match", in_s)

    in_s, _ = scope.is_in_scope("admin.example.com")
    check("Scope explicit exclusion enforcement", not in_s)

    in_s, _ = scope.is_in_scope("192.168.1.50")
    check("Scope CIDR IP range match", in_s)

    in_s, _ = scope.is_in_scope("example.com", path="/logout")
    check("Scope excluded path block", not in_s)

    # 3. CVSS Calculation Tests
    score, sev, vec = calculate_cvss_base(c="H", i="H", a="H")
    check("CVSS High Impact Calculation (Critical)", score >= 9.0 and sev == "CRITICAL")

    # 4. Database Transaction Tests
    init_db()
    session = get_session()
    repo = AssessmentRepository(session)
    ass = repo.create_assessment("selftest.local", scope.model_dump_json(), "QUICK")
    check("Database assessment record creation", ass.id is not None)
    repo.update_status(ass.id, "COMPLETED")
    check("Database assessment status update", repo.get_assessment(ass.id).status == "COMPLETED")
    session.close()

    console.print(f"\n[bold]{passed}/{total} tests passed.[/bold]\n")
    if passed == total:
        console.print("[bold green]All internal self-tests passed successfully![/bold green]\n")
    else:
        raise typer.Exit(1)
