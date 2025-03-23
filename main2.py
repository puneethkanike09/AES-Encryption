from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from PIL import Image
from stegano import lsb
import base64
import sys
import os
import binascii  # Added for hex conversion

def decrypt_message(encrypted_message, key):
    """Decrypt an AES-encrypted message."""
    try:
        if len(key) not in (16, 24, 32):
            raise ValueError(f"Invalid key length: {len(key)} bytes (must be 16, 24, or 32)")
        
        iv = base64.b64decode(encrypted_message[:24])
        ciphertext = base64.b64decode(encrypted_message[24:])
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_plaintext = cipher.decrypt(ciphertext)
        plaintext = unpad(padded_plaintext, AES.block_size)
        return plaintext.decode('utf-8')
    except ValueError as e:
        raise ValueError(f"Decryption error: {str(e)}")
    except Exception as e:
        raise ValueError(f"Invalid key or corrupted data: {str(e)}")

def extract_from_image(image_path):
    """Extract hidden message from an image."""
    try:
        message = lsb.reveal(image_path)
        if not message:
            raise ValueError("No hidden message found")
        return message
    except Exception as e:
        raise ValueError(f"Extraction error: {str(e)}")

def main():
    """Main function to handle extraction and decryption process."""
    INPUT_IMAGE = 'output_image.png'

    try:
        if not os.path.exists(INPUT_IMAGE):
            raise FileNotFoundError(f"Image '{INPUT_IMAGE}' not found")

        key_input = input("Enter the secret key (hex): ").strip()
        if not key_input:
            raise ValueError("Key cannot be empty")

        # Convert hex key back to bytes
        try:
            key = binascii.unhexlify(key_input)
        except binascii.Error:
            raise ValueError("Invalid key format (must be hexadecimal)")

        encrypted_message = extract_from_image(INPUT_IMAGE)
        plaintext = decrypt_message(encrypted_message, key)
        print(f"\nDecrypted message: {plaintext}")

    except ValueError as e:
        print(f"Error: {str(e)}")
    except FileNotFoundError as e:
        print(f"Error: {str(e)}")
    except KeyboardInterrupt:
        print("\nProcess interrupted by user (Ctrl+C)")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()