"""The `hunt` command synthesizes a valid, authorized scope from a bare URL."""

from venom.cli import build_parser, build_hunt_scope
from venom.core.scope import Scope


def _args(argv):
    return build_parser().parse_args(argv)


def test_hunt_minimal_scope_is_valid():
    scope = build_hunt_scope(_args(["hunt", "https://t.example.net/"]))
    s = Scope.from_dict(scope)            # must validate
    s.validate_window()                    # within authorized window
    assert s.authorized_base_urls == ["https://t.example.net"]
    assert s.discovery["enabled"] and not s.allow_destructive
    assert not s.identities


def test_hunt_full_scope_with_login_email_and_objective():
    scope = build_hunt_scope(_args([
        "hunt", "https://t.example.net",
        "--login", "wiener:peter",
        "--email-client", "https://exploit-abc.exploit-server.net/email",
        "--delete-user", "carlos",
        "--objective", "reach admin"]))
    s = Scope.from_dict(scope)
    s.validate_window()
    assert s.identities[0]["auth"]["username"] == "wiener"
    assert s.identities[0]["auth"]["password"] == "peter"
    assert s.email_client_url.endswith("/email")
    # email host added to authorized scope so cross-host inbox reads are permitted
    assert any("exploit-server.net" in b for b in s.authorized_base_urls)
    assert s.objective_delete_user == "carlos"
    assert s.allow_destructive            # implied by a destructive objective
    assert s.objective["description"] == "reach admin"
