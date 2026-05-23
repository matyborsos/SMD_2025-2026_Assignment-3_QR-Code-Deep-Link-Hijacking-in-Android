"""
Unit tests for the SMD manifest auditor.

They assert that every rule family fires on the deliberately vulnerable
fixture, and that the hardened fixture is clean of HIGH/CRITICAL findings.

Run from the /auditor folder with:  pytest -q
"""
import os
import sys

import pytest

# Make auditor.py importable when tests are run from anywhere.
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import auditor  # noqa: E402

SAMPLES = os.path.join(ROOT, "samples")


def audit_file(name):
    path = os.path.join(SAMPLES, name)
    xml = auditor.read_local_manifest(path)
    return auditor.audit_manifest(xml, f"manifest:{path}")


@pytest.fixture(scope="module")
def vuln():
    return audit_file("vulnerable_AndroidManifest.xml")


@pytest.fixture(scope="module")
def hardened():
    return audit_file("hardened_AndroidManifest.xml")


def rule_ids(result):
    return {f.rule_id for f in result.findings}


# --------------------------- vulnerable fixture --------------------------- #
def test_vuln_custom_scheme_deep_link(vuln):
    assert "DL001" in rule_ids(vuln)


def test_vuln_missing_autoverify(vuln):
    assert "DL002" in rule_ids(vuln)


def test_vuln_exported_without_permission(vuln):
    assert "EX001" in rule_ids(vuln)


def test_vuln_implicit_export(vuln):
    assert "EX002" in rule_ids(vuln)


def test_vuln_browsable_on_sensitive(vuln):
    assert "BR001" in rule_ids(vuln)


def test_vuln_app_hardening(vuln):
    # debuggable + allowBackup + cleartext
    assert {"APP001", "APP002", "APP003"}.issubset(rule_ids(vuln))


def test_vuln_provider_is_critical(vuln):
    provider = [f for f in vuln.findings
                if f.rule_id == "EX001" and "provider" in f.component]
    assert provider and provider[0].severity == "CRITICAL"


def test_vuln_overall_rating(vuln):
    assert vuln.risk_rating() in ("HIGH", "CRITICAL")
    assert vuln.max_severity() == "CRITICAL"


def test_launcher_not_flagged_as_exported(vuln):
    # MainActivity is a launcher; it must not appear in EX001/EX002.
    offenders = [f for f in vuln.findings
                 if f.rule_id in ("EX001", "EX002") and "MainActivity" in f.component]
    assert offenders == []


# ---------------------------- hardened fixture ---------------------------- #
def test_hardened_has_no_high_or_critical(hardened):
    high = [f for f in hardened.findings
            if auditor.SEVERITY_ORDER[f.severity] >= auditor.SEVERITY_ORDER["HIGH"]]
    assert high == [], f"unexpected serious findings: {[f.rule_id for f in high]}"


def test_hardened_no_custom_scheme(hardened):
    assert "DL001" not in rule_ids(hardened)


def test_hardened_no_unverified_applink(hardened):
    assert "DL002" not in rule_ids(hardened)


def test_hardened_rating_is_low_or_clean(hardened):
    assert hardened.risk_rating() in ("CLEAN", "LOW")


# ------------------------------- scoring ---------------------------------- #
def test_risk_score_is_capped(vuln):
    assert 0 <= vuln.risk_score() <= 100


def test_json_serialisation(vuln):
    d = auditor.result_to_dict(vuln)
    assert d["summary"]["total"] == len(vuln.findings)
    assert "risk_rating" in d["summary"]
    assert all("recommendation" in f for f in d["findings"])
