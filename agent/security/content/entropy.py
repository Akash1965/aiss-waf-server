"""
Shannon Entropy Calculator
High entropy (> 7.0) indicates encrypted, compressed, or packed content.
Used to detect obfuscated malware payloads.
"""
import math
from collections import Counter


def shannon_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy of binary data.
    Returns value between 0.0 (uniform) and 8.0 (maximum randomness).
    """
    if not data:
        return 0.0

    counts = Counter(data)
    total = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def is_suspicious_entropy(data: bytes, threshold: float = 7.2) -> tuple[bool, float]:
    """
    Returns (is_suspicious, score).
    Threshold 7.2 catches most packed/encrypted payloads while avoiding
    false positives on legitimate compressed assets.
    """
    score = shannon_entropy(data)
    return score >= threshold, score


def entropy_verdict(data: bytes) -> dict:
    """Full entropy analysis result."""
    score = shannon_entropy(data)
    suspicious = score >= 7.2
    level = "CLEAN"
    if score >= 7.8:
        level = "HIGH_ENTROPY_LIKELY_ENCRYPTED"
    elif score >= 7.2:
        level = "HIGH_ENTROPY_SUSPICIOUS"
    elif score >= 6.0:
        level = "MEDIUM_ENTROPY"
    return {
        "score": round(score, 4),
        "suspicious": suspicious,
        "level": level,
    }
