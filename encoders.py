# encoders.py
"""
Cloak - Payload Encoder Module
Provides multiple encoding/decoding techniques.
"""

import base64
import binascii

# --- Base64 ---
def encode_base64(data: bytes) -> str:
    """Encode bytes to Base64 string."""
    return base64.b64encode(data).decode('utf-8')

def decode_base64(encoded: str) -> bytes:
    """Decode Base64 string back to bytes."""
    return base64.b64decode(encoded.encode('utf-8'))

# --- XOR ---
def encode_xor(data: bytes, key: int) -> str:
    """XOR encode bytes with a single-byte key, output hex string."""
    return binascii.hexlify(bytes(b ^ key for b in data)).decode('utf-8')

def decode_xor(encoded: str, key: int) -> bytes:
    """XOR decode hex string back to bytes using the same key."""
    raw = binascii.unhexlify(encoded.encode('utf-8'))
    return bytes(b ^ key for b in raw)

# --- ROT13 ---
def encode_rot13(data: str) -> str:
    """Apply ROT13 substitution cipher to text."""
    trans = str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"
    )
    return data.translate(trans)

def decode_rot13(encoded: str) -> str:
    """ROT13 is symmetric, so decode is same as encode."""
    return encode_rot13(encoded)

# --- Hex ---
def encode_hex(data: bytes) -> str:
    """Encode bytes to hex string."""
    return binascii.hexlify(data).decode('utf-8')

def decode_hex(encoded: str) -> bytes:
    """Decode hex string back to bytes."""
    return binascii.unhexlify(encoded.encode('utf-8'))

# --- Base32 ---
def encode_base32(data: bytes) -> str:
    """Encode bytes to Base32 string."""
    return base64.b32encode(data).decode('utf-8')

def decode_base32(encoded: str) -> bytes:
    """Decode Base32 string back to bytes."""
    return base64.b32decode(encoded.encode('utf-8'))

# --- Base85 ---
def encode_base85(data: bytes) -> str:
    """Encode bytes to Base85 string."""
    return base64.b85encode(data).decode('utf-8')

def decode_base85(encoded: str) -> bytes:
    """Decode Base85 string back to bytes."""
    return base64.b85decode(encoded.encode('utf-8'))
