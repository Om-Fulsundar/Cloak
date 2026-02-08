# decoders.py
"""
Cloak - Decoding Module
Provides decoding functions for reversible encoders and obfuscators.
Notes:
- Encoding schemes are fully reversible.
- Some obfuscation methods are only partially reversible.
"""

import base64
import binascii

# --- Decoders for Encoders ---
def decode_base64(data: str) -> str:
    return base64.b64decode(data).decode('utf-8')

def decode_xor(data: str, key: int) -> str:
    raw = binascii.unhexlify(data)
    return "".join(chr(b ^ key) for b in raw)

def decode_rot13(data: str) -> str:
    trans = str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"
    )
    return data.translate(trans)

def decode_hex(data: str) -> str:
    return binascii.unhexlify(data).decode('utf-8')

def decode_base32(data: str) -> str:
    return base64.b32decode(data).decode('utf-8')

def decode_base85(data: str) -> str:
    return base64.b85decode(data).decode('utf-8')


# --- Decoders for Obfuscators ---
def decode_reverse(payload: str) -> str:
    return payload[::-1]

def decode_escape(payload: str) -> str:
    # Expect payload like "\x34\x33\x34..."
    import re
    # Find all hex pairs after \x
    hex_pairs = re.findall(r'\\x([0-9a-fA-F]{2})', payload)
    bytes_out = bytearray(int(h, 16) for h in hex_pairs)
    return bytes_out.decode('utf-8', errors='ignore')

def decode_split(payload: str, delimiter="+") -> str:
    # Join chunks back together
    return payload.replace(delimiter, "")

def decode_insert(payload: str, charset="XYZ") -> str:
    """
    WARNING: Not truly reversible.
    Random characters were inserted without metadata.
    We cannot reliably strip them out unless we know exactly which chars were added.
    """
    raise NotImplementedError("Obfuscation method 'insert' is not reversible without metadata.")
