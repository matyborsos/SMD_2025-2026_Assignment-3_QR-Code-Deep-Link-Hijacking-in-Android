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

Install the QR generator:

```bash
cd payload-gen
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python3 payload_gen.py     # writes out/qr_oauth.png and out/qr_internal.png
```

Load QR code in the emulator camera:
In Android Studio -> Extended Controls -> Camera -> Wall:
- Select qr_oauth.png or qr_internal.png
- Press Scan QR in the VulnerableTarget app
- While holding shift move the camera with the mouse and wasd keys to look at the QR on the wall

## Attack 1 — OAuth token theft
Steps:

1. Press Scan QR in the VulnerableTarget app

OR

```bash
adb shell am start -W -a android.intent.action.VIEW \
  -d 'smdpoc://oauth/callback?token=REAL_USER_SESSION_42'
```

2. Pick **MaliciousCompanion** in the chooser → its UI shows
`STOLEN TOKEN: REAL_USER_SESSION_42`.


> [!NOTE]  
> **How it works:**
>  
> QR encodes ```smdpoc://oauth/callback?token=…```
> 
> both apps (target and attacker) registered this URI
> 
> scan -> chooser dialog -> user picks attacker -> token in the URI is delivered to the wrong app
> 
> ```Works because custom URI schemes have no origin verification. Any app can claim them```


## Attack 2 — Intent injection (PIN bypass)
Steps:

1. Press Scan QR in the VulnerableTarget app

OR

```bash
adb shell am start -W -a android.intent.action.VIEW \
  -d 'smdpoc://internal/launch?cmd=show_secret'
```

2. Pick **MaliciousCompanion** → emulator jumps straight to
**Internal — sensitive settings**, skipping the PIN screen.

> [!NOTE]  
> **How it works:**
> 
> QR encodes ```smdpoc://internal/launch?cmd=show_secret```
> 
> scan -> only the attacker app will recognize the deep-link -> attacker app opens silently (builds explicit intent) -> calls the exported activity of target app
> 
> ```Works because target app has an exported=true activity callable from any app on the device. The QR code is just a social engineering wrapper / delivery method```


## Evidence

Tail logs while running the attacks:

```bash
adb logcat -s 'ATTACKER:*' 'TARGET:*'
```
