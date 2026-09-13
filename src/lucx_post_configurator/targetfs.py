from __future__ import annotations

import hashlib
import os
import stat
import tempfile
from pathlib import Path


class TargetFS:
    """Maps absolute target paths into a test root without weakening path checks."""

    def __init__(self, root: str | Path = "/") -> None:
        self.root = Path(root).resolve()

    @property
    def is_live(self) -> bool:
        return self.root == Path("/").resolve()

    def path(self, target: str | Path) -> Path:
        raw = str(target)
        if not raw.startswith("/"):
            raise ValueError(f"target path must be absolute: {raw}")
        relative = raw.lstrip("/")
        # Normalize lexical '..' components without following the final symlink.
        # Backups must be able to record and restore a symlink as a symlink (for
        # example Certbot live paths or Debian's stock Nginx default site).
        lexical = Path(os.path.abspath(self.root / relative))
        if lexical != self.root and self.root not in lexical.parents:
            raise ValueError(f"target escapes root: {raw}")
        resolved_parent = lexical.parent.resolve(strict=False)
        if resolved_parent != self.root and self.root not in resolved_parent.parents:
            raise ValueError(f"target parent escapes root through a symlink: {raw}")
        return lexical

    def exists(self, target: str | Path) -> bool:
        return self.path(target).exists()

    def read_text(self, target: str | Path, default: str = "") -> str:
        path = self.path(target)
        try:
            return path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return default

    def read_bytes(self, target: str | Path) -> bytes:
        return self.path(target).read_bytes()

    def sha256(self, target: str | Path) -> str:
        digest = hashlib.sha256()
        with self.path(target).open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def atomic_write(self, target: str | Path, data: bytes, mode: int = 0o644, *,
                     owner: tuple[int, int] | None = None) -> dict:
        if owner is not None and (not isinstance(owner, tuple) or len(owner) != 2 or
                any(type(value) is not int or not 0 <= value < 2**32 - 1 for value in owner)):
            raise ValueError("Некорректный владелец восстанавливаемого файла")
        path = self.path(target)
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        temp_path = Path(temporary)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                if owner is not None:
                    metadata = os.fstat(handle.fileno())
                    if (metadata.st_uid, metadata.st_gid) != owner:
                        if not hasattr(os, "fchown"):
                            raise OSError("Платформа не поддерживает восстановление владельца")
                        # Только наш открытый временный файл, до публикации имени.
                        os.fchown(handle.fileno(), *owner)
                os.fsync(handle.fileno())
            os.chmod(temp_path, mode)
            metadata = temp_path.lstat()
            receipt = {"existed": True, "kind": "file", "mode": stat.S_IMODE(metadata.st_mode),
                       "uid": metadata.st_uid, "gid": metadata.st_gid,
                       "inode": metadata.st_ino, "device": metadata.st_dev,
                       "sha256": hashlib.sha256(data).hexdigest()}
            os.replace(temp_path, path)
            return receipt
        finally:
            temp_path.unlink(missing_ok=True)

    def atomic_write_text(self, target: str | Path, text: str, mode: int = 0o644) -> dict:
        return self.atomic_write(target, text.encode("utf-8"), mode=mode)
