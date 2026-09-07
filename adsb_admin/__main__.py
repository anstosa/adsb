"""Command-line entry point for the administration server."""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from .auth import password_hash_from_environment
from .server import AdminApplication, create_server


# build command-line arguments
def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="serve the local ADS-B administration interface")
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8090)
    parser.add_argument("--origin", default="https://adsb.ballydidean.farm")
    parser.add_argument("--frame-origin", default=os.environ.get("ADSB_ADMIN_FRAME_ORIGIN"))
    parser.add_argument("--web-root", type=Path, default=Path("/opt/adsb/current/web"))
    parser.add_argument("--settings-path", type=Path, default=Path("/var/lib/adsb/config/settings.json"))
    parser.add_argument("--status-path", type=Path, default=Path("/var/lib/adsb/status/status.json"))
    parser.add_argument("--insecure-cookie", action="store_true")
    return parser


# serve until the process is stopped
def main() -> None:
    args = _parser().parse_args()
    password_hash = password_hash_from_environment()
    application = AdminApplication(
        web_root=args.web_root,
        settings_path=args.settings_path,
        status_path=args.status_path,
        password_hash=password_hash,
        origin=args.origin,
        secure_cookie=not args.insecure_cookie,
        frame_origin=args.frame_origin,
    )
    server = create_server((args.bind, args.port), application)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


# execute the command-line entry point
if __name__ == "__main__":
    main()
