from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# AES requires a 16, 24, or 32 byte key (128, 192, or 256 bits)
def aes_encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return cipher.iv + ct_bytes  # Append IV to ciphertext for decryption

def aes_decrypt(ciphertext, key):
    iv = ciphertext[:AES.block_size]
    ct = ciphertext[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(ct), AES.block_size)
    return decrypted.decode()

# Example usage:
key = get_random_bytes(16)  # AES 128-bit key
message = "HELLO"
ciphertext = aes_encrypt(message, key)
decrypted_message = aes_decrypt(ciphertext, key)
print("AES - Encrypted:", ciphertext)
print("AES - Decrypted:", decrypted_message)
