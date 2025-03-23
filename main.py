from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
from PIL import Image
from stegano import lsb
import base64
import sys
import os
import binascii  # Added for hex conversion

def encrypt_message(message, key):
    """Encrypt a message using AES in CBC mode with random IV."""
    try:
        cipher = AES.new(key, AES.MODE_CBC)
        padded_message = pad(message.encode('utf-8'), AES.block_size)
        ciphertext = cipher.encrypt(padded_message)
        iv_b64 = base64.b64encode(cipher.iv).decode('utf-8')
        ct_b64 = base64.b64encode(ciphertext).decode('utf-8')
        return iv_b64 + ct_b64
    except Exception as e:
        raise ValueError(f"Encryption error: {str(e)}")

def hide_in_image(input_path, message, output_path):
    """Hide encrypted message in an image using LSB steganography."""
    try:
        secret_image = lsb.hide(input_path, message)
        secret_image.save(output_path)
        print(f"Encrypted image saved to: {output_path}")
    except Exception as e:
        raise ValueError(f"Steganography error: {str(e)}")

def main():
    """Main function to handle encryption and steganography process."""
    INPUT_IMAGE = 'input_image.png'
    OUTPUT_IMAGE = 'output_image.png'
    KEY_SIZE = 16  # 16 bytes = 128-bit AES

    try:
        if not os.path.exists(INPUT_IMAGE):
            raise FileNotFoundError(f"Input image '{INPUT_IMAGE}' not found")

        message = input("Enter message to hide: ").strip()
        if not message:
            raise ValueError("Message cannot be empty")

        key = get_random_bytes(KEY_SIZE)
        encrypted_message = encrypt_message(message, key)
        hide_in_image(INPUT_IMAGE, encrypted_message, OUTPUT_IMAGE)

        # Convert key to hexadecimal instead of Base64
        key_hex = binascii.hexlify(key).decode('utf-8')
        print(f"\nSave this key for decryption (hex): {key_hex}")

    except ValueError as e:
        print(f"Error: {str(e)}")
    except FileNotFoundError as e:
        print(f"Error: {str(e)}")
    except PermissionError:
        print(f"Error: Permission denied when saving '{OUTPUT_IMAGE}'")
    except KeyboardInterrupt:
        print("\nProcess interrupted by user (Ctrl+C)")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()