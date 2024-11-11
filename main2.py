from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from PIL import Image
from stegano import lsb
import base64

def aes_decrypt(encrypted_message, key):
    try:
        iv = base64.b64decode(encrypted_message[:24])
        ct = base64.b64decode(encrypted_message[24:])
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt.decode('utf-8')
    except (ValueError, KeyError):
        return None

def extract_message(image_path):
    secret = lsb.reveal(image_path)
    return secret

def main():
    image_path = 'output_image.png'  # Path to your steganographed image
    secret_key = input("Enter the secret key: ")
    secret_key = base64.b64decode(secret_key)
    
    encrypted_message = extract_message(image_path)
    plain_text = aes_decrypt(encrypted_message, secret_key)
    
    if plain_text:
        print(f"Decrypted message: {plain_text}")
    else:
        print("Invalid key or corrupted message!")

if __name__ == "__main__":
    main()
