from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
from PIL import Image
from stegano import lsb
import base64

def aes_encrypt(plain_text, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plain_text.encode(), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return iv + ct

def embed_message(image_path, message, output_image_path):
    secret = lsb.hide(image_path, message)
    secret.save(output_image_path)
    print(f"Image saved to {output_image_path}")

def main():
    image_path = 'image.png'  # Path to your input image
    output_image_path = 'output_image.png'
    plain_text = 'anything.'
    key = get_random_bytes(16)  # AES key must be either 16, 24, or 32 bytes long
    
    encrypted_message = aes_encrypt(plain_text, key)
    embed_message(image_path, encrypted_message, output_image_path)
    print(f"Secret key: {base64.b64encode(key).decode('utf-8')}")

if __name__ == "__main__":
    main()
