# main.py
# script by Om Fulsundar (https://github.com/Om-Fulsundar)

import argparse
from encoders import (
    encode_base64, encode_xor, encode_rot13,
    encode_hex, encode_base32, encode_base85
)
from obfuscators import (
    insert_random_chars, split_and_concat,
    escape_sequence_obfuscation, reversible_transform
)
from detector import detect, effectiveness
from report import save_output, generate_report
from decoders import (
    decode_base64, decode_xor, decode_rot13,
    decode_hex, decode_base32, decode_base85,
    decode_reverse, decode_escape, decode_split, decode_insert
)


def main():
    parser = argparse.ArgumentParser(description="Cloak: Payload Encoder/Obfuscation/Detection/Decoding Framework")
    parser.add_argument("--payload", "-p", required=True, help="Raw payload string (for encode/decode)")
    parser.add_argument("--encoder", "-e",
                        choices=["base64","xor","rot13","hex","base32","base85"],
                        help="Encoding method")
    parser.add_argument("--key", "-k", type=int, help="Key for XOR encoding/decoding")
    parser.add_argument("--obfuscator", "-o",
                        choices=["insert","split","escape","reverse"],
                        help="Optional obfuscation method")
    parser.add_argument("--decode", "-d", action="store_true", help="Decode instead of encode/obfuscate")
    args = parser.parse_args()

    if args.decode:
        # --- Decoding path ---
        result = args.payload

        # First de-obfuscate
        if args.obfuscator == "reverse":
            result = decode_reverse(result)
        elif args.obfuscator == "escape":
            result = decode_escape(result)
        elif args.obfuscator == "split":
            result = decode_split(result)
        elif args.obfuscator == "insert":
            try:
                result = decode_insert(result)
            except NotImplementedError as e:
                print(f"[WARNING] {e}")

        # Then decode
        if args.encoder == "base64":
            result = decode_base64(result)
        elif args.encoder == "xor":
            if args.key is None:
                raise ValueError("XOR decoding requires --key")
            result = decode_xor(result, args.key)
        elif args.encoder == "rot13":
            result = decode_rot13(result)
        elif args.encoder == "hex":
            result = decode_hex(result)
        elif args.encoder == "base32":
            result = decode_base32(result)
        elif args.encoder == "base85":
            result = decode_base85(result)

        print("=== Cloak Decoding ===")
        print(f"[DECODER] {args.encoder.upper() if args.encoder else 'NONE'}")
        print(f"[DE-OBFUSCATOR] {args.obfuscator or 'NONE'}")
        print(f"[OUTPUT] {result}")

    else:
        # --- Encoding + Obfuscation path ---
        data = args.payload.encode()
        result = args.payload

        if args.encoder == "base64":
            result = encode_base64(data)
        elif args.encoder == "xor":
            if args.key is None:
                raise ValueError("XOR encoding requires --key")
            result = encode_xor(data, args.key)
        elif args.encoder == "rot13":
            result = encode_rot13(args.payload)
        elif args.encoder == "hex":
            result = encode_hex(data)
        elif args.encoder == "base32":
            result = encode_base32(data)
        elif args.encoder == "base85":
            result = encode_base85(data)

        if args.obfuscator == "insert":
            result = insert_random_chars(result)
        elif args.obfuscator == "split":
            result = split_and_concat(result)
        elif args.obfuscator == "escape":
            result = escape_sequence_obfuscation(result)
        elif args.obfuscator == "reverse":
            result = reversible_transform(result)

        # Detection + Effectiveness
        detected_original = detect(args.payload)
        detected_transformed = detect(result)
        verdict = effectiveness(args.payload, result)

        # Report
        report = generate_report(args.payload, result, detected_original, detected_transformed)
        filename = save_output(report)

        print("=== Cloak Execution ===")
        print(f"[ENCODER] {args.encoder.upper() if args.encoder else 'NONE'}")
        print(f"[OBFUSCATOR] {args.obfuscator or 'NONE'}")
        print(f"[OUTPUT] {result[:80]}")
        print(f"[DETECTION] Original: {'DETECTED' if detected_original else 'BYPASSED'}")
        print(f"[DETECTION] Transformed: {'DETECTED' if detected_transformed else 'BYPASSED'}")
        print(f"[EFFECTIVENESS] {verdict}")
        print(f"\n--- Report saved to results/{filename} ---")


if __name__ == "__main__":
    main()
