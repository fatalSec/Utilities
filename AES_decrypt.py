import argparse
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Util import Counter

def parse_args():
    parser = argparse.ArgumentParser(description="AES Decryption Utility")
    parser.add_argument("--key", required=True, help="AES key (32 characters for AES-256)")
    parser.add_argument("--iv", required=True, help="Initialization vector (16 characters)")
    parser.add_argument("--mode", required=True, choices=["CBC", "CFB", "OFB", "CTR"], help="AES mode")
    parser.add_argument("--data", required=True, help="Base64-encoded encrypted data")
    return parser.parse_args()

def get_cipher(key, iv, mode):
    mode_map = {
        "CBC": AES.MODE_CBC,
        "CFB": AES.MODE_CFB,
        "OFB": AES.MODE_OFB,
        "CTR": AES.MODE_CTR
    }

    if mode == "CTR":
        ctr = Counter.new(128, initial_value=int.from_bytes(iv.encode(), byteorder='big'))
        return AES.new(key.encode(), mode_map[mode], counter=ctr)
    else:
        return AES.new(key.encode(), mode_map[mode], iv.encode())

def main():
    args = parse_args()

    try:
        encrypted_data = base64.b64decode(args.data)
    except Exception as e:
        print(f"Failed to decode base64 data: {e}")
        return

    try:
        cipher = get_cipher(args.key, args.iv, args.mode)
        decrypted = cipher.decrypt(encrypted_data)

        # For CBC only: remove padding
        if args.mode == "CBC":
            decrypted = unpad(decrypted, AES.block_size)

        print("Decrypted Data:", decrypted.decode('utf-8'))
    except Exception as e:
        print(f"Decryption failed: {e}")

if __name__ == "__main__":
    main()
