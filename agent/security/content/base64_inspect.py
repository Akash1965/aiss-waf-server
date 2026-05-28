"""
Base64 Streaming Inspector
Decodes Base64 content and feeds it to YARA + entropy + magic byte checks.
"""
import base64
import re
from typing import Iterator


# Patterns that might be Base64 in HTTP payloads
_B64_PATTERN = re.compile(
    r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})"
)

# Minimum length to consider a string as potentially meaningful Base64
_MIN_B64_LENGTH = 48  # 36 decoded bytes


def extract_b64_candidates(data: bytes) -> list[bytes]:
    """
    Find and decode all Base64 candidates in a payload.
    Returns list of decoded byte strings.
    """
    decoded = []
    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:
        return decoded

    for match in _B64_PATTERN.finditer(text):
        candidate = match.group(0)
        if len(candidate) < _MIN_B64_LENGTH:
            continue
        try:
            raw = base64.b64decode(candidate + "==")  # pad just in case
            if len(raw) >= 16:  # minimum meaningful payload
                decoded.append(raw)
        except Exception:
            continue
    return decoded


def decode_body_if_base64(body: bytes, content_type: str) -> bytes | None:
    """
    If the whole body appears to be Base64-encoded, decode and return it.
    Returns None if the body doesn't look like Base64.
    """
    if not body:
        return None

    # Only attempt if content-type suggests encoded data or no content-type
    ct = (content_type or "").lower()
    if "multipart" in ct or "text/html" in ct:
        return None

    try:
        clean = body.strip().replace(b"\n", b"").replace(b"\r", b"")
        decoded = base64.b64decode(clean)
        # Sanity check: decoded should be at least half as long as encoded
        if len(decoded) >= len(body) * 0.5:
            return None  # Probably not Base64, just binary
        return decoded
    except Exception:
        return None


def stream_decode_chunks(data: bytes, chunk_size: int = 4096) -> Iterator[bytes]:
    """
    Yield decoded chunks from a Base64-encoded stream.
    Handles line-wrapped Base64 (e.g., email attachments).
    """
    # Remove whitespace to get clean Base64
    clean = re.sub(rb"[\s\r\n]", b"", data)

    # Decode in 3-byte multiples (every 4 Base64 chars → 3 bytes)
    encoded_chunk_size = (chunk_size // 3) * 4
    for i in range(0, len(clean), encoded_chunk_size):
        chunk = clean[i:i + encoded_chunk_size]
        if not chunk:
            break
        # Add padding if needed
        padding = (-len(chunk)) % 4
        chunk += b"=" * padding
        try:
            yield base64.b64decode(chunk)
        except Exception:
            continue
