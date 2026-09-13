#!/usr/bin/env python3
from __future__ import annotations

import base64
import hashlib
import io
import os
import stat
import zipfile
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]
SOURCE = PROJECT / "src"
DIST = PROJECT / "dist"
OUTPUT = DIST / "lucx-post-configure.sh"
MARKER = b"__LUCX_POST_CONFIGURATOR_PAYLOAD__\n"


def build_payload() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in sorted((SOURCE / "lucx_post_configurator").rglob("*")):
            if not path.is_file() or "__pycache__" in path.parts or path.suffix == ".pyc":
                continue
            relative = path.relative_to(SOURCE).as_posix()
            info = zipfile.ZipInfo(relative, date_time=(2025, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (0o755 if path.name == "lucx_sub_sidecar.py" else 0o644) << 16
            archive.writestr(info, path.read_bytes())
    return buffer.getvalue()


def shell_prefix(payload_sha256: str) -> bytes:
    return f"""#!/bin/sh
# Сгенерировано tools/build_installer.py; исходники находятся в проекте x-tuna.
set -eu

umask 077
LUCX_PC_TMP=$(mktemp -d "${{TMPDIR:-/tmp}}/lucx-post-configurator.XXXXXX")
cleanup() {{ rm -rf -- "$LUCX_PC_TMP"; }}
trap cleanup EXIT HUP INT TERM

python3 - "$0" "$LUCX_PC_TMP" "{payload_sha256}" <<'PY'
import base64
import hashlib
import pathlib
import sys
import zipfile

script = pathlib.Path(sys.argv[1]).read_bytes()
destination = pathlib.Path(sys.argv[2]).resolve()
expected = sys.argv[3]
marker = b"__LUCX_POST_CONFIGURATOR_PAYLOAD__\\n"
try:
    encoded = script.split(marker, 1)[1]
except IndexError:
    raise SystemExit("installer payload marker is missing")
payload = base64.b64decode(b"".join(encoded.split()), validate=True)
if hashlib.sha256(payload).hexdigest() != expected:
    raise SystemExit("installer payload checksum mismatch")
with zipfile.ZipFile(__import__("io").BytesIO(payload)) as archive:
    for member in archive.infolist():
        target = (destination / member.filename).resolve()
        if destination != target and destination not in target.parents:
            raise SystemExit("unsafe installer payload path")
        if member.is_dir():
            target.mkdir(parents=True, exist_ok=True)
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        with archive.open(member) as source, target.open("wb") as output:
            output.write(source.read())
PY

LUCX_PC_SELF="$0" PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$LUCX_PC_TMP${{PYTHONPATH:+:$PYTHONPATH}}" python3 -m lucx_post_configurator "$@"
status=$?
exit "$status"
__LUCX_POST_CONFIGURATOR_PAYLOAD__
""".encode("utf-8")


def main() -> int:
    payload = build_payload()
    digest = hashlib.sha256(payload).hexdigest()
    encoded = base64.encodebytes(payload)
    DIST.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_bytes(shell_prefix(digest) + encoded)
    try:
        os.chmod(OUTPUT, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
    except OSError:
        pass
    checksum = hashlib.sha256(OUTPUT.read_bytes()).hexdigest()
    (DIST / "SHA256SUMS").write_text(f"{checksum}  {OUTPUT.name}\n", encoding="ascii")
    print(f"built {OUTPUT} ({OUTPUT.stat().st_size} bytes)")
    print(f"sha256 {checksum}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
