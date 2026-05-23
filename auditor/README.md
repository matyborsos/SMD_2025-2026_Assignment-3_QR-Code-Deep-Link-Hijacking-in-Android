# Assignment 3 Manifest Auditor

Defensive static auditor for the **QR Code & Deep Link Hijacking in Android** project.

This is the defensive half of the project: this tool *detects* the insecure configuration before it ships. It obtains an app's `AndroidManifest.xml`, applies a small set of rules, and prints a **severity report** (human-readable and JSON).

---

## What it checks

| ID     | Family               | Severity        | Detects |
|--------|----------------------|-----------------|---------|
| `EX001`| Exported components  | HIGH (CRITICAL for `provider`) | An exported component with **no `android:permission`** that isn't a launcher or a verified App Link — any app can invoke it (intent injection). |
| `EX002`| Exported components  | MEDIUM          | A component with an `intent-filter` but **no explicit `android:exported`** (implicitly exported / ambiguous on Android 12+). |
| `DL001`| Deep links           | HIGH            | A **custom-scheme** deep link (e.g. `smdpoc://`) — custom schemes have no origin verification, so any app can register the same scheme (scheme collision). |
| `DL002`| Deep links           | MEDIUM          | An `http`/`https` deep link **missing `android:autoVerify`** — an unverified App Link other apps can intercept. |
| `BR001`| Sensitive deep links | CRITICAL        | A **sensitive** component (oauth / callback / login / pay / admin / …) reachable via an **unverified** `BROWSABLE` deep link — a direct hijack / account-takeover path. |
| `APP001`| App hardening | HIGH           | `android:debuggable="true"`. |
| `APP002`| App hardening | LOW            | `android:allowBackup` enabled (or defaulted). |
| `APP003`| App hardening | MEDIUM         | `android:usesCleartextTraffic="true"`. |

---

## Requirements

* **Python 3.8+** — the auditor itself uses only the standard library.
* For the **device modes** only, the Android SDK tools must be on your `PATH`:
  * `adb` (platform-tools)
  * `apkanalyzer` (cmdline-tools/latest/bin)
* For running the tests: `pip install -r requirements.txt` (installs `pytest`).

No installation step is needed for the auditor — just run `auditor.py`.

---

## Usage

The tool takes exactly one input source.

### 1. Local manifest file (no device needed)

Use this for the demo and for grading. Point it at a decoded
`AndroidManifest.xml`:

```bash
python3 auditor.py --manifest samples/vulnerable_AndroidManifest.xml
python3 auditor.py --manifest samples/hardened_AndroidManifest.xml
```

### 2. One installed app on a connected device / emulator

```bash
python3 auditor.py --package com.smd.poc
```

This runs `adb shell pm path`, pulls the base APK, and decodes its manifest with `apkanalyzer manifest print`.

### 3. Every third-party app on the device

```bash
python3 auditor.py --all                 # third-party packages
python3 auditor.py --all --system        # include system packages too
```

### Common options

| Option | Meaning |
|--------|---------|
| `--json report.json` | Also write the full report as JSON. |
| `--device SERIAL`    | Target a specific adb device (when several are connected). |
| `--no-extras`        | Disable the bonus app-level hardening checks (`APP001-003`). |
| `--no-color`         | Plain text output (colour is auto-disabled when piped). |
| `--fail-on LEVEL`    | Exit code 1 if a finding at this severity or higher exists. Default `HIGH`. Use `NEVER` to always exit 0. |

### Use in CI

The exit code makes it usable as a build gate (Phase 0 CI):

```bash
# fails the pipeline if any HIGH or CRITICAL issue is present
python3 auditor.py --manifest app/src/main/AndroidManifest.xml --fail-on HIGH
```

---

## The severity report

Every run ends with a severity report:

```
  SEVERITY REPORT
  ------------------------------------------------------------------
    CRITICAL  2
    HIGH      6
    MEDIUM    3
    LOW       1
    INFO      0
  ------------------------------------------------------------------
    Risk score : 100 / 100   -> CRITICAL RISK
```

**Severity levels** (highest impact first):

* **CRITICAL** — directly exploitable for hijack / account takeover (e.g. a sensitive component on an unverified deep link, or an exported provider).
* **HIGH** — a strong exposure that meaningfully enables the attack (custom scheme, exported component without a guard, debuggable build).
* **MEDIUM** — a weakness that helps an attacker or is ambiguous (unverified App Link, implicit export, cleartext traffic).
* **LOW** — hardening gap with limited direct impact (backup enabled).
* **INFO** — informational only.

**Risk score** is the sum of per-finding weights
(CRITICAL = 40, HIGH = 20, MEDIUM = 8, LOW = 3), capped at 100. The score maps
to an **overall rating**:

| Score   | Rating   |
|---------|----------|
| 0       | CLEAN    |
| 1–19    | LOW      |
| 20–49   | MEDIUM   |
| 50–79   | HIGH     |
| 80–100  | CRITICAL |

**JSON output** (`--json`) has the same information, structured for tooling:

```json
{
  "tool": "smd-manifest-auditor",
  "version": "1.0",
  "generated": "2026-05-23T16:57:00+00:00",
  "targets": [
    {
      "package": "com.smd.poc",
      "source": "manifest:samples/vulnerable_AndroidManifest.xml",
      "summary": {
        "CRITICAL": 2, "HIGH": 6, "MEDIUM": 3, "LOW": 1, "INFO": 0,
        "total": 12, "risk_score": 100, "risk_rating": "CRITICAL"
      },
      "findings": [
        {
          "rule_id": "BR001",
          "family": "Sensitive deep links",
          "severity": "CRITICAL",
          "title": "Sensitive component is reachable via an unverified deep link",
          "component": "activity .OAuthCallbackActivity",
          "evidence": "name matches sensitive pattern, schemes=['smdpoc']",
          "description": "...",
          "recommendation": "..."
        }
      ]
    }
  ]
}
```

---

## Demo 

The `samples/` folder contains the two fixtures used to validate the tool:

```bash
# 1) the deliberately vulnerable app  -> every planted issue is flagged
python3 auditor.py --manifest samples/vulnerable_AndroidManifest.xml
#    => CRITICAL RISK, 12 findings (exit code 1)

# 2) the same app after remediation   -> clean
python3 auditor.py --manifest samples/hardened_AndroidManifest.xml
#    => CLEAN, 0 findings (exit code 0)
```

This is the "findings appear, then clear after the fix" loop from the
architecture diagram (`remediation guidance`).

---
