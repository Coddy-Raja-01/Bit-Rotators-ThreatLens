import re
import hashlib

def tokenize_simhash(text: str) -> list[str]:
    """Tokenize text into lowercase feature tokens."""
    tokens = re.findall(r"\w+", text.lower())
    # Generate bi-grams and words
    features = []
    for i in range(len(tokens)):
        features.append(tokens[i])
        if i < len(tokens) - 1:
            features.append(f"{tokens[i]}_{tokens[i+1]}")
    return features

def compute_simhash(text: str, hash_bits: int = 64) -> str:
    """
    Computes 64-bit Simhash for text content to detect near-duplicate templates.
    Returns 16-character hexadecimal string.
    """
    if not text or len(text.strip()) == 0:
        return "0000000000000000"

    tokens = tokenize_simhash(text)
    if not tokens:
        return "0000000000000000"

    v = [0] * hash_bits
    for token in tokens:
        # Compute 64-bit hash using MD5
        h = int(hashlib.md5(token.encode("utf-8")).hexdigest()[:16], 16)
        for i in range(hash_bits):
            bit = (h >> i) & 1
            if bit:
                v[i] += 1
            else:
                v[i] -= 1

    fingerprint = 0
    for i in range(hash_bits):
        if v[i] > 0:
            fingerprint |= (1 << i)

    return f"{fingerprint:016x}"

def simhash_hamming_distance(hash1: str, hash2: str) -> int:
    """Computes bitwise Hamming distance between two hex Simhashes (0-64)."""
    try:
        val1 = int(hash1, 16)
        val2 = int(hash2, 16)
        xor_val = val1 ^ val2
        return bin(xor_val).count("1")
    except Exception:
        return 64

