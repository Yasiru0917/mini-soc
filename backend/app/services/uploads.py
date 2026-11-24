"""Secure file upload handling (used for evidence, logs and packet captures).

Every uploaded file goes through the same checks:

1. EXTENSION ALLOWLIST - only known, harmless types are accepted.
2. SIZE LIMIT - the file is read in small chunks and the upload is aborted
   as soon as it exceeds the limit (we never load a huge file into memory).
3. CONTENT CHECK - the extension is a claim; the bytes are the truth.
   * text files must be valid UTF-8 and contain no NUL bytes
   * binary files must start with the correct "magic bytes"
     (e.g. every PNG starts with \\x89PNG)
   A file named evil.png that is really an .exe is rejected.
4. SAFE STORAGE - saved under a random UUID name in backend/data/, which is
   outside any web-served folder. The user's filename is kept only as
   metadata (sanitised), so "../../etc/passwd" style names do nothing.
5. INTEGRITY - a SHA-256 hash is computed while saving. Investigators use it
   to prove evidence has not been changed since collection.
"""

import codecs
import hashlib
import re
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from app.core.config import get_settings

CHUNK = 64 * 1024

# extension -> kind
EXTENSION_KINDS = {
    ".log": "text", ".txt": "text", ".json": "text", ".jsonl": "text", ".csv": "text",
    ".pcap": "pcap", ".pcapng": "pcap", ".cap": "pcap",
    ".png": "png", ".jpg": "jpeg", ".jpeg": "jpeg",
    ".pdf": "pdf",
}

MAGIC_BYTES = {
    # classic pcap (both byte orders, micro/nanosecond) and pcapng
    "pcap": (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d",
             b"\x0a\x0d\x0d\x0a"),
    "png": (b"\x89PNG\r\n\x1a\n",),
    "jpeg": (b"\xff\xd8\xff",),
    "pdf": (b"%PDF-",),
}

CONTENT_TYPES = {
    "text": "text/plain", "pcap": "application/vnd.tcpdump.pcap",
    "png": "image/png", "jpeg": "image/jpeg", "pdf": "application/pdf",
}


class UploadRejected(Exception):
    """Raised when a file fails validation. `status_code` maps to the HTTP response."""

    def __init__(self, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code


@dataclass
class StoredFile:
    original_name: str
    stored_name: str
    path: Path
    size: int
    sha256: str
    kind: str
    content_type: str


def sanitize_filename(name: str | None) -> str:
    """Keep only the last path component and safe characters (for display only)."""
    base = re.split(r"[\\/]", name or "")[-1]
    cleaned = re.sub(r"[^A-Za-z0-9._ -]", "_", base).strip(" .")
    return cleaned[:200] or "unnamed"


def storage_dir(subdir: str) -> Path:
    path = get_settings().data_dir / "uploads" / subdir
    path.mkdir(parents=True, exist_ok=True)
    return path


def save_upload(
    stream: BinaryIO,
    filename: str | None,
    *,
    allowed_kinds: set[str],
    max_bytes: int,
    subdir: str,
) -> StoredFile:
    original = sanitize_filename(filename)
    ext = Path(original).suffix.lower()
    kind = EXTENSION_KINDS.get(ext)
    if kind is None or kind not in allowed_kinds:
        allowed = sorted(e for e, k in EXTENSION_KINDS.items() if k in allowed_kinds)
        raise UploadRejected(f"File type '{ext or 'none'}' not allowed. Allowed: {', '.join(allowed)}", 415)

    stored_name = f"{uuid.uuid4().hex}{ext}"
    final_path = storage_dir(subdir) / stored_name
    temp_path = final_path.with_suffix(final_path.suffix + ".part")

    sha = hashlib.sha256()
    size = 0
    head = b""
    decoder = codecs.getincrementaldecoder("utf-8")("strict") if kind == "text" else None

    try:
        with temp_path.open("wb") as out:
            while chunk := stream.read(CHUNK):
                size += len(chunk)
                if size > max_bytes:
                    raise UploadRejected(f"File too large. Maximum is {max_bytes // (1024 * 1024)} MB.", 413)
                if len(head) < 16:
                    head += chunk[: 16 - len(head)]
                if decoder is not None:
                    if b"\x00" in chunk:
                        raise UploadRejected("File contains binary data; expected a text log.")
                    try:
                        decoder.decode(chunk)
                    except UnicodeDecodeError:
                        raise UploadRejected("File is not valid UTF-8 text.") from None
                sha.update(chunk)
                out.write(chunk)
            if decoder is not None:
                try:
                    decoder.decode(b"", final=True)
                except UnicodeDecodeError:
                    raise UploadRejected("File is not valid UTF-8 text.") from None

        if size == 0:
            raise UploadRejected("File is empty.")
        if kind in MAGIC_BYTES and not head.startswith(MAGIC_BYTES[kind]):
            raise UploadRejected(f"File content does not match its '{ext}' extension.")

        temp_path.replace(final_path)
    except BaseException:
        temp_path.unlink(missing_ok=True)  # never leave half-written or rejected files behind
        raise

    return StoredFile(
        original_name=original,
        stored_name=stored_name,
        path=final_path,
        size=size,
        sha256=sha.hexdigest(),
        kind=kind,
        content_type=CONTENT_TYPES[kind],
    )


def stored_path(subdir: str, stored_name: str) -> Path:
    """Resolve a stored file, refusing anything that escapes the upload folder."""
    base = storage_dir(subdir).resolve()
    path = (base / stored_name).resolve()
    if base not in path.parents:
        raise UploadRejected("Invalid file reference.", 400)
    return path
