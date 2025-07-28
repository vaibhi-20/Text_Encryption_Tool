import base64
import rsa
from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# AES FUNCTIONS
def aes_encrypt(plaintext):
    key = get_random_bytes(16)  # AES-128
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return base64.b64encode(cipher.iv + ct_bytes).decode(), base64.b64encode(key).decode()

def aes_decrypt(ciphertext_b64, key_b64):
    ciphertext = base64.b64decode(ciphertext_b64)
    key = base64.b64decode(key_b64)
    iv = ciphertext[:AES.block_size]
    ct = ciphertext[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode()

# DES FUNCTIONS
def des_encrypt(plaintext):
    key = get_random_bytes(8)  # DES key must be 8 bytes
    cipher = DES.new(key, DES.MODE_ECB)
    ct = cipher.encrypt(pad(plaintext.encode(), DES.block_size))
    return base64.b64encode(ct).decode(), base64.b64encode(key).decode()

def des_decrypt(ciphertext_b64, key_b64):
    ciphertext = base64.b64decode(ciphertext_b64)
    key = base64.b64decode(key_b64)
    cipher = DES.new(key, DES.MODE_ECB)
    pt = unpad(cipher.decrypt(ciphertext), DES.block_size)
    return pt.decode()

# RSA FUNCTIONS
def rsa_generate_keys():
    public_key, private_key = rsa.newkeys(2048)
    return public_key, private_key

def rsa_encrypt(plaintext, public_key):
    return base64.b64encode(rsa.encrypt(plaintext.encode(), public_key)).decode()

def rsa_decrypt(ciphertext_b64, private_key):
    ciphertext = base64.b64decode(ciphertext_b64)
    return rsa.decrypt(ciphertext, private_key).decode()

# MAIN PROGRAM
def main():
    print("\n--- Multi-Algorithm Text Encryption Tool ---")
    print("Choose algorithm:")
    print("1. AES")
    print("2. DES")
    print("3. RSA")
    choice = input("Enter your choice (1/2/3): ")

    if choice == '1':
        text = input("Enter plaintext: ")
        encrypted, key = aes_encrypt(text)
        print("\nEncrypted (AES):", encrypted)
        print("AES Key:", key)
        decrypted = aes_decrypt(encrypted, key)
        print("Decrypted Text:", decrypted)

    elif choice == '2':
        text = input("Enter plaintext: ")
        encrypted, key = des_encrypt(text)
        print("\nEncrypted (DES):", encrypted)
        print("DES Key:", key)
        decrypted = des_decrypt(encrypted, key)
        print("Decrypted Text:", decrypted)

    elif choice == '3':
        text = input("Enter plaintext: ")
        public_key, private_key = rsa_generate_keys()
        encrypted = rsa_encrypt(text, public_key)
        print("\nEncrypted (RSA):", encrypted)
        decrypted = rsa_decrypt(encrypted, private_key)
        print("Decrypted Text:", decrypted)
    else:
        print("Invalid choice. Exiting.")

if __name__ == "__main__":
    main()
