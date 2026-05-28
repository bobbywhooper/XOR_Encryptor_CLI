import sys
import argparse
import base64
import hashlib
import getpass

# 1. Parser setup
parser = argparse.ArgumentParser(description="My Security Tool")
parser.add_argument("--encrypt", action="store_true", help="Encrypt mode")
parser.add_argument("--decrypt", action="store_true", help="Decrypt mode")
parser.add_argument("--file", required=True, help="File to process")
parser.add_argument("--output", default="output.bin", help="File to save the result (default: output.bin)")

# 2. Parse args
args = parser.parse_args()
key = getpass.getpass("Enter key: ")

# 3. Validate args
if not key.strip():
    print("Error: Key cannot be empty.")
    sys.exit(1)

if not args.encrypt and not args.decrypt:
    print("Error: specify --encrypt or --decrypt.")
    sys.exit(1)

# 4. Functions
def derive_key(key: str, length: int) -> bytes:
    raw = key.encode()
    stretched = b""
    counter = 0
    while len(stretched) < length:
        stretched += hashlib.sha256(raw + counter.to_bytes(4, 'big')).digest()
        counter += 1
    return stretched[:length]

def xor_encrypt(file, key):
    try:
        with open(file, 'rb') as f:
            data = bytearray(f.read())
    except FileNotFoundError:
        print(f"Error: The file '{file}' was not found.")
        return None
    except PermissionError:
        print(f"Error: You do not have permission to read '{file}'.")
        return None

    if not data:
        print("Error: file is empty.")
        return None

    key_bytes = derive_key(key, len(data))
    encrypted = bytes([data[i] ^ key_bytes[i] for i in range(len(data))])
    return base64.b64encode(encrypted)

def xor_decrypt(file, key):
    try:
        with open(file, "rb") as f:
            b64_data = f.read()
    except FileNotFoundError:
        print(f"Error: The file '{file}' was not found.")
        return None
    except PermissionError:
        print(f"Error: You do not have permission to read '{file}'.")
        return None

    if not b64_data:
        print("Error: file is empty.")
        return None

    try:
        encrypted_data = base64.b64decode(b64_data)
    except base64.binascii.Error:
        print("Error: not valid Base64.")
        return None

    data = bytearray(encrypted_data)
    key_bytes = derive_key(key, len(data))
    return bytes([data[i] ^ key_bytes[i] for i in range(len(data))])

# 5. Execute
if args.encrypt:
    print(f"Encrypting {args.file}...")
    result = xor_encrypt(args.file, key)
    if result is None:
        sys.exit(1)
    with open(args.output, "wb") as f:
        f.write(result)
    print(f"Saved to {args.output}")

elif args.decrypt:
    print(f"Decrypting {args.file}...")
    result = xor_decrypt(args.file, key)
    if result is None:
        sys.exit(1)
    with open(args.output, "wb") as f:
        f.write(result)
    print(f"Saved to {args.output}")