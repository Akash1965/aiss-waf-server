"""
Magic Byte Validator
Detects actual file type from binary signature regardless of claimed Content-Type.
Used to catch file-type spoofing attacks (e.g., PHP shell uploaded as 'image.jpg').
"""

MAGIC_SIGNATURES = {
    # Executables — always suspicious in web uploads
    "EXE_WINDOWS":      (b"\x4D\x5A", "Windows PE Executable"),
    "ELF_LINUX":        (b"\x7F\x45\x4C\x46", "Linux ELF Executable"),
    "MACHO":            (b"\xCE\xFA\xED\xFE", "macOS Mach-O Binary"),

    # Scripts — suspicious if uploaded as non-script
    "PHP_SCRIPT":       (b"\x3C\x3F\x70\x68\x70", "PHP Script"),       # <?php
    "PHP_SHORT":        (b"\x3C\x3F", "PHP Short Tag"),                  # <?
    "SHELL_SHEBANG":    (b"\x23\x21", "Shell Script (#!)"),
    "PYTHON_SHEBANG":   (b"\x23\x21/usr/bin/py", "Python Script"),

    # Archives — may contain malware
    "ZIP":              (b"\x50\x4B\x03\x04", "ZIP Archive / Office Doc"),
    "GZIP":             (b"\x1F\x8B", "GZIP Compressed"),
    "TAR_BZ2":          (b"\x42\x5A\x68", "BZip2 Archive"),
    "7ZIP":             (b"\x37\x7A\xBC\xAF\x27\x1C", "7-Zip Archive"),
    "RAR":              (b"\x52\x61\x72\x21\x1A\x07", "RAR Archive"),

    # Documents (legitimate but inspect content)
    "PDF":              (b"\x25\x50\x44\x46", "PDF Document"),           # %PDF
    "OLE2":             (b"\xD0\xCF\x11\xE0", "MS Office OLE2 (doc/xls/ppt)"),

    # Java
    "JAVA_CLASS":       (b"\xCA\xFE\xBA\xBE", "Java Class File"),
    "JAR":              (b"\x50\x4B\x03\x04", "JAR File"),

    # Images (legitimate)
    "JPEG":             (b"\xFF\xD8\xFF", "JPEG Image"),
    "PNG":              (b"\x89\x50\x4E\x47\x0D\x0A\x1A\x0A", "PNG Image"),
    "GIF87":            (b"\x47\x49\x46\x38\x37\x61", "GIF87 Image"),
    "GIF89":            (b"\x47\x49\x46\x38\x39\x61", "GIF89 Image"),
    "WEBP":             (b"\x52\x49\x46\x46", "WEBP Image"),
}

# File types that are always dangerous regardless of Content-Type claim
DANGEROUS_TYPES = {
    "EXE_WINDOWS", "ELF_LINUX", "MACHO",
    "PHP_SCRIPT", "PHP_SHORT", "SHELL_SHEBANG",
    "PYTHON_SHEBANG", "JAVA_CLASS",
}

# Content-Type → expected magic type mapping
CONTENT_TYPE_MAP = {
    "image/jpeg":       {"JPEG"},
    "image/png":        {"PNG"},
    "image/gif":        {"GIF87", "GIF89"},
    "image/webp":       {"WEBP"},
    "application/pdf":  {"PDF"},
    "application/zip":  {"ZIP", "7ZIP", "RAR"},
    "text/plain":       set(),   # Anything could be plaintext
}


def detect_file_type(data: bytes) -> tuple[str | None, str | None]:
    """
    Returns (type_key, description) or (None, None) if no magic bytes matched.
    Checks the first 16 bytes of data.
    """
    header = data[:16]
    for type_key, (magic, description) in MAGIC_SIGNATURES.items():
        if header[:len(magic)] == magic:
            return type_key, description
    return None, None


def validate_content_type(data: bytes, declared_content_type: str) -> dict:
    """
    Validate that actual file type matches declared Content-Type.
    Returns verdict dict.
    """
    detected_key, detected_desc = detect_file_type(data)
    declared_ct = (declared_content_type or "").split(";")[0].strip().lower()

    result = {
        "detected_type": detected_key,
        "detected_description": detected_desc,
        "declared_content_type": declared_ct,
        "is_dangerous": False,
        "is_spoofed": False,
        "should_block": False,
        "reason": "",
    }

    if detected_key is None:
        return result

    # Check if detected type is dangerous
    if detected_key in DANGEROUS_TYPES:
        result["is_dangerous"] = True
        result["should_block"] = True
        result["reason"] = f"Dangerous file type detected: {detected_desc}"
        return result

    # Check if Content-Type is being spoofed
    if declared_ct in CONTENT_TYPE_MAP:
        expected = CONTENT_TYPE_MAP[declared_ct]
        if expected and detected_key not in expected:
            result["is_spoofed"] = True
            result["should_block"] = True
            result["reason"] = (
                f"Content-Type spoofing: claimed '{declared_ct}' "
                f"but file is actually {detected_desc}"
            )

    return result
