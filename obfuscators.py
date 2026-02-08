# obfuscators.py
"""
Cloak - String Obfuscation Module
Implements reversible obfuscation techniques for payloads.
"""

import random

def insert_random_chars(payload: str, charset="XYZ") -> str:
    """Insert random characters after each char in payload."""
    return "".join(ch + random.choice(charset) for ch in payload)

def split_and_concat(payload: str, chunk_size=2) -> str:
    """Split payload into chunks and join with '+'."""
    chunks = [payload[i:i+chunk_size] for i in range(0, len(payload), chunk_size)]
    return "+".join(chunks)

def escape_sequence_obfuscation(payload: str) -> str:
    """Convert each char into \\xNN escape sequence."""
    return "".join("\\x{:02x}".format(ord(c)) for c in payload)

def reversible_transform(payload: str) -> str:
    """Simple reversible transformation: reverse string."""
    return payload[::-1]
