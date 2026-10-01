#!/usr/bin/python3
"""Install a reviewed copy in /opt/aifinance/bin. No inherited provider credentials."""
import os
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit


def environment(text):
    allowed = {"DATABASE_URL", "SITE_URL", "ADMIN_PASSWORD", "SESSION_SECRET", "IMG_PROXY_SIGN_SECRET"}
    values = {}
    for line in text.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator or key not in allowed or key in values or not value or value != value.strip():
            raise ValueError("Invalid or duplicate preview configuration key (values not logged)")
        values[key] = value
    if values.keys() != allowed:
        raise ValueError("Missing preview configuration keys")
    db = urlsplit(values["DATABASE_URL"])
    if db.scheme not in ("postgres", "postgresql") or db.hostname != "127.0.0.1" or db.path != "/aifinance_preview":
        raise ValueError("Only the dedicated loopback preview database is allowed")
    if urlsplit(values["SITE_URL"]).scheme != "https":
        raise ValueError("Native shared preview requires an HTTPS SITE_URL")
    if len(values["ADMIN_PASSWORD"]) < 12 or any(len(values[k]) < 32 for k in ("SESSION_SECRET", "IMG_PROXY_SIGN_SECRET")):
        raise ValueError("Preview credentials do not meet minimum lengths")
    return dict(values, PATH="/usr/local/bin:/usr/bin:/bin", NODE_ENV="production", PREVIEW_MODE="true",
                COLLECT_ENABLED="false", MODEL_CALLS_ENABLED="false", FEISHU_INTERNAL_ENABLED="false",
                FEISHU_CONTENT_PUSH_ENABLED="false", INDEXNOW_SUBMIT_ENABLED="false", DATABASE_POOL_MAX="3",
                AIHOT_DATA_DIR="/opt/aifinance/shared/data", API_BASE_URL="http://127.0.0.1:3101",
                API_HOST="127.0.0.1", API_PORT="3101", WEB_HOST="127.0.0.1", WEB_PORT="3100", TRUST_PROXY="false")


def main():
    role = sys.argv[1] if len(sys.argv) == 2 else ""
    if role not in ("api", "web"):
        raise SystemExit("Only api and web roles are permitted")
    env = environment(Path("/etc/aifinance-preview.env").read_text())
    release = Path("/opt/aifinance/current").resolve(strict=True)
    sha = (release / "RELEASE_SHA").read_text().strip()
    if not re.fullmatch(r"[a-f0-9]{40}", sha) or release != Path("/opt/aifinance/releases") / sha:
        raise SystemExit("Invalid release path")
    env["AIHOT_RELEASE"] = sha
    if role == "web":
        for key in ("DATABASE_URL", "ADMIN_PASSWORD", "SESSION_SECRET", "IMG_PROXY_SIGN_SECRET"):
            del env[key]
    os.chdir(release)
    entry = "apps/api/src/main.ts" if role == "api" else "apps/web/server.ts"
    os.execve("/usr/local/bin/node", ["/usr/local/bin/node", entry], env)


if __name__ == "__main__":
    main()
