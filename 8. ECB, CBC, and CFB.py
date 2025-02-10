from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import binascii
def encrypt_ecb(plaintext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return ciphertext
def encrypt_cbc(plaintext, key):
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return iv + ciphertext
def encrypt_cfb(plaintext, key):
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CFB, iv)
    ciphertext = cipher.encrypt(plaintext.encode())
    return iv + ciphertext
if __name__ == "__main__":
    key = get_random_bytes(16)  # AES requires a 16-byte key
    plaintext = "Sensitive Data for Encryption"  # Example plaintext
    ecb_ciphertext = encrypt_ecb(plaintext, key)
    cbc_ciphertext = encrypt_cbc(plaintext, key)
    cfb_ciphertext = encrypt_cfb(plaintext, key)
    print("Encryption Key (hex):", binascii.hexlify(key).decode())
    print("ECB Ciphertext (hex):", binascii.hexlify(ecb_ciphertext).decode())
    print("CBC Ciphertext (hex):", binascii.hexlify(cbc_ciphertext).decode())
    print("CFB Ciphertext (hex):", binascii.hexlify(cfb_ciphertext).decode())
