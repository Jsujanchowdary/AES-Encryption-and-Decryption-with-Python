# AES Encryption and Decryption with Python

This repository demonstrates the implementation of AES encryption and decryption using the `PyCryptodome` library in Python. AES (Advanced Encryption Standard) is a symmetric key encryption algorithm widely used to secure data.

## Prerequisites

To run this project, you'll need to have Python installed, along with the following dependencies:

- `pycryptodome` library

You can install it via pip:

```bash
pip install pycryptodome
```

## AES Encryption Overview

AES is a symmetric encryption algorithm, meaning the same key is used for both encryption and decryption. AES supports key lengths of 128, 192, and 256 bits. In this implementation, AES is used in CBC (Cipher Block Chaining) mode, which requires an initialization vector (IV) to provide additional security.

### AES Key Sizes
- **128-bit key**: 16 bytes
- **192-bit key**: 24 bytes
- **256-bit key**: 32 bytes

In this example, a 128-bit (16-byte) AES key is used.

## Code Walkthrough

### AES Encryption

The `aes_encrypt` function encrypts the plaintext using AES in CBC mode:

```python
def aes_encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return cipher.iv + ct_bytes  # Append IV to ciphertext for decryption
```

- **Key**: A 128-bit (16-byte) key is used for AES encryption.
- **Initialization Vector (IV)**: The IV is randomly generated and prepended to the ciphertext. This helps ensure that identical plaintexts encrypt to different ciphertexts.
- **Padding**: Since AES works on fixed block sizes (16 bytes), the plaintext is padded to the appropriate block size using `Crypto.Util.Padding.pad`.

### AES Decryption

The `aes_decrypt` function decrypts the ciphertext using the corresponding AES key:

```python
def aes_decrypt(ciphertext, key):
    iv = ciphertext[:AES.block_size]
    ct = ciphertext[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(ct), AES.block_size)
    return decrypted.decode()
```

- **IV extraction**: The IV is extracted from the first 16 bytes of the ciphertext.
- **Decryption**: The ciphertext is decrypted using the same AES key and the extracted IV.
- **Unpadding**: The padding is removed after decryption using `Crypto.Util.Padding.unpad`.

### Example Usage

Here’s an example demonstrating how to encrypt and decrypt a message using AES:

```python
key = get_random_bytes(16)  # AES 128-bit key
message = "HELLO"
ciphertext = aes_encrypt(message, key)
decrypted_message = aes_decrypt(ciphertext, key)

print("AES - Encrypted:", ciphertext)
print("AES - Decrypted:", decrypted_message)
```

In this example:
- A random 128-bit AES key is generated.
- The message `"HELLO"` is encrypted.
- The encrypted message is decrypted back to the original message.

## Example Output

When you run the script, the output will look something like this:

```text
AES - Encrypted: b'...'  # The encrypted ciphertext (binary data, including IV)
AES - Decrypted: HELLO
```

- The ciphertext is displayed as binary data, including the IV.
- The decrypted message will be `"HELLO"`, which matches the original plaintext.

## How to Run the Code

1. Clone the repository:

```bash
git clone https://github.com/Jsujanchowdary/AES-Encryption-and-Decryption-with-Python.git
```

2. Navigate to the project directory:

```bash
cd AES-Encryption-and-Decryption-with-Python
```

3. Run the script:

```bash
python aes.py
```

## Conclusion

This project demonstrates how to use AES encryption and decryption with the PyCryptodome library in Python. AES is widely used for securing sensitive data, and this implementation in CBC mode with padding ensures data confidentiality and integrity.

---

### Example Directory Structure

```plaintext
aes-encryption-python/
│
├── aes.py       # Python script for AES encryption and decryption
├── README.md            # Project documentation
└── requirements.txt     # Python dependencies
```

---

### Notes

- AES encryption is highly secure and widely used in modern cryptography.
- CBC mode is a secure mode of operation, but it requires careful handling of the IV. In this example, the IV is stored with the ciphertext to simplify the decryption process.
- The AES key must be kept secret, as anyone with access to the key can decrypt the data.

Feel free to modify the code and experiment with different key sizes, modes, or data. If you need help or have questions, feel free to open an issue!

---
