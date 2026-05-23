#!/usr/bin/env python3
"""
SMD Manifest Auditor
====================
Defensive static auditor for Android deep-link / intent hijacking risks
(Security of Mobile Devices, Assignment 3 - Phase 3).

It obtains an app's AndroidManifest.xml either from a local decoded file or
from a connected device/emulator (adb + apkanalyzer), then applies a small set
of rules and prints a severity report (human-readable and/or JSON).

Rule families implemented (matching the project plan):
  1. Exported components without a permission guard
  2. Custom-scheme deep links (no cryptographic origin verification)
  3. http/https deep links missing android:autoVerify (unverified App Links)
  4. BROWSABLE deep links on sensitive components (oauth/login/pay/...)
Plus a couple of bonus application-level hardening checks (debuggable,
allowBackup, cleartext traffic).

The tool uses only the Python standard library; adb/apkanalyzer are only
required for the device modes.

Usage examples
--------------
  # offline: audit a decoded manifest you already have
  python3 auditor.py --manifest samples/vulnerable_AndroidManifest.xml

  # audit one installed app on a connected device
  python3 auditor.py --package com.smd.poc

  # audit every third-party app on the device, write JSON
  python3 auditor.py --all --json report.json

This is a defensive analysis tool for use on apps you own or are authorised to
test. Use it only in an isolated lab environment.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from typing import Optional
from xml.etree import ElementTree as ET

ANDROID_NS = "http://schemas.android.com/apk/res/android"
LAUNCHER_ACTION = "android.intent.action.MAIN"
LAUNCHER_CATEGORY = "android.intent.category.LAUNCHER"
BROWSABLE = "android.intent.category.BROWSABLE"
WEB_SCHEMES = {"http", "https"}

# Component names that handle security-relevant flows. If one of these is
# reachable through a deep link, the impact of a hijack is much higher.
SENSITIVE_PATTERNS = [
    "oauth", "callback", "login", "signin", "sign_in", "auth", "token",
    "sso", "account", "reset", "verify", "otp", "admin", "internal",
    "debug", "pay", "payment", "wallet", "secret", "session",
]

# Ordering and scoring for severities.
SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
SEVERITY_WEIGHT = {"CRITICAL": 40, "HIGH": 20, "MEDIUM": 8, "LOW": 3, "INFO": 0}

ANSI = {
    "CRITICAL": "\033[1;37;41m",  # white on red
    "HIGH": "\033[1;31m",         # red
    "MEDIUM": "\033[1;33m",       # yellow
    "LOW": "\033[1;36m",          # cyan
    "INFO": "\033[1;90m",         # grey
    "BOLD": "\033[1m",
    "DIM": "\033[2m",
    "RESET": "\033[0m",
}


# --------------------------------------------------------------------------- #
#  Data model
# --------------------------------------------------------------------------- #
@dataclass
class Finding:
    rule_id: str
    family: str
    severity: str
    title: str
    component: str
    evidence: str
    description: str
    recommendation: str


@dataclass
class AuditResult:
    package: str
    source: str
    findings: list = field(default_factory=list)

    # ---- summary helpers ----
    def counts(self) -> dict:
        c = {s: 0 for s in SEVERITY_ORDER}
        for f in self.findings:
            c[f.severity] += 1
        return c

    def risk_score(self) -> int:
        score = sum(SEVERITY_WEIGHT[f.severity] for f in self.findings)
        return min(score, 100)

    def risk_rating(self) -> str:
        s = self.risk_score()
        if s == 0:
            return "CLEAN"
        if s < 20:
            return "LOW"
        if s < 50:
            return "MEDIUM"
        if s < 80:
            return "HIGH"
        return "CRITICAL"

    def max_severity(self) -> Optional[str]:
        if not self.findings:
            return None
        return max(self.findings, key=lambda f: SEVERITY_ORDER[f.severity]).severity


# --------------------------------------------------------------------------- #
#  Manifest acquisition
# --------------------------------------------------------------------------- #
def read_local_manifest(path: str) -> str:
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def _run(cmd: list) -> str:
    """Run a command and return stdout, raising a friendly error on failure."""
    try:
        out = subprocess.run(
            cmd, check=True, capture_output=True, text=True
        )
    except FileNotFoundError:
        raise RuntimeError(
            f"'{cmd[0]}' was not found on PATH. Install the Android SDK "
            f"platform-tools / build-tools and make sure '{cmd[0]}' is reachable."
        )
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(
            f"Command failed: {' '.join(cmd)}\n{exc.stderr.strip()}"
        )
    return out.stdout


def adb_base(serial: Optional[str]) -> list:
    return ["adb"] + (["-s", serial] if serial else [])


def list_device_packages(serial: Optional[str], include_system: bool) -> list:
    flag = [] if include_system else ["-3"]
    out = _run(adb_base(serial) + ["shell", "pm", "list", "packages", *flag])
    pkgs = []
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("package:"):
            pkgs.append(line[len("package:"):].strip())
    return sorted(pkgs)


def pull_manifest_from_device(pkg: str, serial: Optional[str]) -> str:
    """Resolve the base APK for a package, pull it, decode its manifest."""
    if not shutil.which("apkanalyzer"):
        raise RuntimeError(
            "'apkanalyzer' was not found on PATH. It ships with the Android SDK "
            "cmdline-tools (cmdline-tools/latest/bin)."
        )
    path_out = _run(adb_base(serial) + ["shell", "pm", "path", pkg])
    apk_paths = [
        ln.strip()[len("package:"):]
        for ln in path_out.splitlines()
        if ln.strip().startswith("package:")
    ]
    base = next((p for p in apk_paths if p.endswith("base.apk")), None) or (
        apk_paths[0] if apk_paths else None
    )
    if not base:
        raise RuntimeError(f"Could not resolve an APK path for package '{pkg}'.")

    tmpdir = tempfile.mkdtemp(prefix="smd-audit-")
    local_apk = os.path.join(tmpdir, f"{pkg}.apk")
    try:
        _run(adb_base(serial) + ["pull", base, local_apk])
        return _run(["apkanalyzer", "manifest", "print", local_apk])
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# --------------------------------------------------------------------------- #
#  Parsing helpers
# --------------------------------------------------------------------------- #
def aattr(el: ET.Element, name: str, default=None):
    """Read an android:* attribute regardless of namespace resolution."""
    val = el.get(f"{{{ANDROID_NS}}}{name}")
    if val is None:
        val = el.get("android:" + name)
    if val is None:
        val = el.get(name)
    return default if val is None else val


def _is_true(value: Optional[str]) -> bool:
    return str(value).strip().lower() == "true"


def short_name(pkg: str, name: Optional[str]) -> str:
    if not name:
        return "(unnamed)"
    if name.startswith(".") or "." not in name:
        return name
    if pkg and name.startswith(pkg + "."):
        return name[len(pkg):]  # keep leading dot
    return name


def is_sensitive(name: Optional[str]) -> bool:
    if not name:
        return False
    low = name.lower()
    return any(p in low for p in SENSITIVE_PATTERNS)


# --------------------------------------------------------------------------- #
#  The rule engine
# --------------------------------------------------------------------------- #
def audit_manifest(xml_text: str, source: str, include_extras: bool = True) -> AuditResult:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise RuntimeError(f"Could not parse manifest XML from {source}: {exc}")

    pkg = root.get("package", "") or aattr(root, "package", "") or ""
    result = AuditResult(package=pkg or "(unknown package)", source=source)

    app = root.find("application")
    if app is None:
        result.findings.append(Finding(
            rule_id="GEN001", family="General", severity="INFO",
            title="No <application> element found",
            component="manifest", evidence=source,
            description="The manifest has no <application> block; nothing to audit.",
            recommendation="Verify this is a valid decoded AndroidManifest.xml.",
        ))
        return result

    # -- application-level hardening (bonus) --
    if include_extras:
        _check_application(app, result)

    # -- per-component checks --
    component_tags = ("activity", "activity-alias", "service", "receiver", "provider")
    for tag in component_tags:
        for comp in app.findall(tag):
            _check_component(pkg, tag, comp, result)

    return result


def _check_application(app: ET.Element, result: AuditResult) -> None:
    if _is_true(aattr(app, "debuggable")):
        result.findings.append(Finding(
            rule_id="APP001", family="App hardening", severity="HIGH",
            title="Application is debuggable",
            component="application",
            evidence='android:debuggable="true"',
            description="A debuggable app lets anyone attach a debugger and read "
                        "memory, tokens and intent extras at runtime.",
            recommendation="Remove android:debuggable or set it to false in release builds.",
        ))

    backup = aattr(app, "allowBackup")
    if backup is None or _is_true(backup):
        result.findings.append(Finding(
            rule_id="APP002", family="App hardening", severity="LOW",
            title="Backup of app data is allowed",
            component="application",
            evidence=f'android:allowBackup={backup if backup is not None else "(default true)"}',
            description="allowBackup lets adb back up private app data, which can "
                        "include cached deep-link tokens.",
            recommendation='Set android:allowBackup="false" unless backup is required.',
        ))

    if _is_true(aattr(app, "usesCleartextTraffic")):
        result.findings.append(Finding(
            rule_id="APP003", family="App hardening", severity="MEDIUM",
            title="Cleartext (HTTP) traffic is permitted",
            component="application",
            evidence='android:usesCleartextTraffic="true"',
            description="Cleartext traffic lets a network attacker observe or "
                        "tamper with OAuth redirects and deep-link callbacks.",
            recommendation="Disable cleartext traffic and use HTTPS with a network "
                           "security config.",
        ))


def _component_export_state(tag: str, comp: ET.Element, has_filter: bool):
    """Return (is_exported, is_explicit) for a component."""
    exported_attr = aattr(comp, "exported")
    if exported_attr is not None:
        return _is_true(exported_attr), True
    # No explicit attribute: implicitly exported if it declares intent-filters.
    # Providers historically defaulted to exported on old SDKs.
    return (has_filter or tag == "provider"), False


def _filter_info(f: ET.Element) -> dict:
    actions = {aattr(a, "name") for a in f.findall("action")}
    cats = {aattr(c, "name") for c in f.findall("category")}
    schemes = {aattr(d, "scheme") for d in f.findall("data") if aattr(d, "scheme")}
    hosts = {aattr(d, "host") for d in f.findall("data") if aattr(d, "host")}
    browsable = BROWSABLE in cats
    auto_verify = _is_true(aattr(f, "autoVerify"))
    is_launcher = LAUNCHER_ACTION in actions and LAUNCHER_CATEGORY in cats
    is_web = bool(schemes) and all(s in WEB_SCHEMES for s in schemes)
    # A verified App Link (https + autoVerify) is the *recommended* secure
    # pattern, so a component is allowed to be exported because of it.
    verified_applink = browsable and is_web and auto_verify
    return {
        "actions": actions, "cats": cats, "schemes": schemes, "hosts": hosts,
        "browsable": browsable, "auto_verify": auto_verify,
        "is_launcher": is_launcher, "verified_applink": verified_applink,
    }


def _check_component(pkg: str, tag: str, comp: ET.Element, result: AuditResult) -> None:
    name = aattr(comp, "name")
    label = f"{tag} {short_name(pkg, name)}"
    permission = aattr(comp, "permission")
    filters = comp.findall("intent-filter")
    has_filter = len(filters) > 0
    exported, explicit = _component_export_state(tag, comp, has_filter)

    infos = [_filter_info(f) for f in filters]
    is_launcher = any(i["is_launcher"] for i in infos)
    # A component's export is "legitimate" only if every filter is either the
    # launcher or a verified App Link; anything else (no filter, custom action,
    # custom scheme, unverified web link) means it is needlessly exposed.
    legit_export = has_filter and all(
        i["is_launcher"] or i["verified_applink"] for i in infos
    )

    # ---- Family 1: exported without a permission guard ----
    if exported and not permission and not legit_export:
        sev = "CRITICAL" if tag == "provider" else "HIGH"
        result.findings.append(Finding(
            rule_id="EX001", family="Exported components", severity=sev,
            title="Exported component has no permission guard",
            component=label,
            evidence=f'exported={"true" if explicit else "implicit"}, permission=none',
            description="An exported component with no android:permission can be "
                        "launched by any other app, enabling intent injection into "
                        "internal screens.",
            recommendation="Set android:exported=\"false\" if it is internal, or "
                           "guard it with a signature-level android:permission.",
        ))

    # ---- Exported without an explicit android:exported flag ----
    if has_filter and not explicit and not is_launcher:
        result.findings.append(Finding(
            rule_id="EX002", family="Exported components", severity="MEDIUM",
            title="Component is implicitly exported (no explicit android:exported)",
            component=label,
            evidence="intent-filter present, android:exported not declared",
            description="Components with an intent-filter but no explicit "
                        "android:exported are exported by default on older targets "
                        "and ambiguous on Android 12+.",
            recommendation="Always declare android:exported explicitly.",
        ))

    # ---- Deep-link families (per intent-filter) ----
    for i in infos:
        browsable = i["browsable"]
        schemes = i["schemes"]
        hosts = i["hosts"]
        host_str = (", host=" + ",".join(sorted(h for h in hosts if h))) if hosts else ""

        for scheme in schemes:
            if scheme in WEB_SCHEMES:
                # Family 3: web deep link missing autoVerify
                if browsable and not i["auto_verify"]:
                    result.findings.append(Finding(
                        rule_id="DL002", family="Deep links", severity="MEDIUM",
                        title="Web deep link is not a verified App Link "
                              "(missing android:autoVerify)",
                        component=label,
                        evidence=f'scheme="{scheme}"{host_str}, autoVerify=false, BROWSABLE',
                        description="Without autoVerify the http/https link is not a "
                                    "verified App Link, so other apps can register the "
                                    "same host and intercept it via the chooser.",
                        recommendation='Add android:autoVerify="true" and publish a '
                                       "Digital Asset Links (assetlinks.json) file.",
                    ))
            else:
                # Family 2: custom-scheme deep link
                if browsable or exported:
                    result.findings.append(Finding(
                        rule_id="DL001", family="Deep links", severity="HIGH",
                        title="Custom-scheme deep link without origin verification",
                        component=label,
                        evidence=f'scheme="{scheme}"{host_str}, '
                                 f'{"BROWSABLE" if browsable else "exported"}',
                        description="Custom URI schemes have no cryptographic origin "
                                    "verification, so any app can register the same "
                                    "scheme and hijack the link (scheme collision).",
                        recommendation="Replace the custom scheme with a verified "
                                       "https App Link (autoVerify + assetlinks.json).",
                    ))

        # ---- Family 4: BROWSABLE deep link on a sensitive component ----
        # (a properly verified App Link is exempt - it cannot be hijacked)
        if browsable and schemes and is_sensitive(name) and not i["verified_applink"]:
            result.findings.append(Finding(
                rule_id="BR001", family="Sensitive deep links", severity="CRITICAL",
                title="Sensitive component is reachable via an unverified deep link",
                component=label,
                evidence=f'name matches sensitive pattern, schemes={sorted(schemes)}',
                description="A security-relevant component (auth / OAuth callback / "
                            "payment / internal) reachable from an unverified "
                            "browser-triggered deep link is a direct "
                            "account-takeover / hijack vector.",
                recommendation="Remove BROWSABLE from this component, require a "
                               "verified App Link, and validate the caller / state.",
            ))


# --------------------------------------------------------------------------- #
#  Reporting
# --------------------------------------------------------------------------- #
def _c(text: str, key: str, use_color: bool) -> str:
    if not use_color:
        return text
    return f"{ANSI.get(key, '')}{text}{ANSI['RESET']}"


def render_text(result: AuditResult, use_color: bool) -> str:
    lines = []
    bar = "=" * 70
    lines.append(bar)
    lines.append(_c("  Android Manifest Security Audit", "BOLD", use_color))
    lines.append(bar)
    lines.append(f"  Package : {result.package}")
    lines.append(f"  Source  : {result.source}")
    lines.append(f"  Scanned : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")

    findings = sorted(
        result.findings,
        key=lambda f: (-SEVERITY_ORDER[f.severity], f.rule_id),
    )

    if not findings:
        lines.append(_c("  No findings - manifest looks clean.", "LOW", use_color))
    else:
        lines.append(_c(f"  FINDINGS ({len(findings)})", "BOLD", use_color))
        lines.append("  " + "-" * 66)
        for i, f in enumerate(findings, 1):
            tag = _c(f"[{f.severity}]", f.severity, use_color)
            lines.append(f"  {i:>2}. {tag} {f.rule_id} - {f.title}")
            lines.append(f"      family : {f.family}")
            lines.append(f"      where  : {f.component}")
            lines.append(f"      evidence: {f.evidence}")
            lines.append(f"      why    : {f.description}")
            lines.append(f"      fix    : {f.recommendation}")
            lines.append("")

    # ---- severity report ----
    counts = result.counts()
    lines.append(_c("  SEVERITY REPORT", "BOLD", use_color))
    lines.append("  " + "-" * 66)
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        label = _c(f"{sev:<9}", sev, use_color)
        lines.append(f"    {label} {counts[sev]}")
    lines.append("  " + "-" * 66)
    rating = result.risk_rating()
    rating_text = "-> CLEAN" if rating == "CLEAN" else f"-> {rating} RISK"
    lines.append(
        f"    Risk score : {result.risk_score()} / 100   "
        + _c(rating_text, rating if rating in ANSI else "BOLD", use_color)
    )
    lines.append(bar)
    return "\n".join(lines)


def result_to_dict(result: AuditResult) -> dict:
    counts = result.counts()
    return {
        "package": result.package,
        "source": result.source,
        "summary": {
            **counts,
            "total": sum(counts.values()),
            "risk_score": result.risk_score(),
            "risk_rating": result.risk_rating(),
        },
        "findings": [asdict(f) for f in result.findings],
    }


# --------------------------------------------------------------------------- #
#  CLI
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Static auditor for Android deep-link / intent hijacking risks.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--manifest", metavar="PATH",
                     help="Path to a local decoded AndroidManifest.xml")
    src.add_argument("--package", metavar="PKG",
                     help="Audit one installed package on a connected device")
    src.add_argument("--all", action="store_true",
                     help="Audit every (third-party) package on the device")

    p.add_argument("--device", metavar="SERIAL",
                   help="adb device serial (for multiple devices)")
    p.add_argument("--system", action="store_true",
                   help="With --all, also include system packages")
    p.add_argument("--json", metavar="OUT",
                   help="Write the full report as JSON to this path")
    p.add_argument("--no-extras", action="store_true",
                   help="Disable the bonus app-level hardening checks")
    p.add_argument("--no-color", action="store_true",
                   help="Disable ANSI colours in the text report")
    p.add_argument("--fail-on", default="HIGH",
                   choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "NEVER"],
                   help="Exit with code 1 if a finding at this severity or higher "
                        "exists (default: HIGH). Use NEVER to always exit 0.")
    return p


def gather_results(args) -> list:
    extras = not args.no_extras
    results = []
    if args.manifest:
        xml = read_local_manifest(args.manifest)
        results.append(audit_manifest(xml, f"manifest:{args.manifest}", extras))
    elif args.package:
        xml = pull_manifest_from_device(args.package, args.device)
        results.append(audit_manifest(xml, f"device:{args.package}", extras))
    elif args.all:
        pkgs = list_device_packages(args.device, args.system)
        if not pkgs:
            raise RuntimeError("No packages returned by adb. Is a device connected?")
        for pkg in pkgs:
            try:
                xml = pull_manifest_from_device(pkg, args.device)
                results.append(audit_manifest(xml, f"device:{pkg}", extras))
            except RuntimeError as exc:
                sys.stderr.write(f"[skip] {pkg}: {exc}\n")
    return results


def worst_severity(results: list) -> Optional[str]:
    worst = None
    for r in results:
        ms = r.max_severity()
        if ms and (worst is None or SEVERITY_ORDER[ms] > SEVERITY_ORDER[worst]):
            worst = ms
    return worst


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    use_color = (not args.no_color) and sys.stdout.isatty()

    try:
        results = gather_results(args)
    except RuntimeError as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 2

    for r in results:
        print(render_text(r, use_color))
        print()

    if len(results) > 1:
        print("=" * 70)
        print("  FLEET SUMMARY")
        print("=" * 70)
        for r in sorted(results, key=lambda x: -x.risk_score()):
            print(f"  {r.risk_rating():<8} {r.risk_score():>3}/100  "
                  f"{sum(r.counts().values()):>2} findings  {r.package}")
        print("=" * 70)

    if args.json:
        payload = {
            "tool": "smd-manifest-auditor",
            "version": "1.0",
            "generated": datetime.now(timezone.utc).isoformat(),
            "targets": [result_to_dict(r) for r in results],
        }
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        sys.stderr.write(f"[+] JSON written to {args.json}\n")

    # ---- exit code for CI ----
    if args.fail_on == "NEVER":
        return 0
    threshold = SEVERITY_ORDER[args.fail_on]
    ws = worst_severity(results)
    if ws is not None and SEVERITY_ORDER[ws] >= threshold:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
