# 🔐 Multi-Algorithm Text Encryption Tool (Python)

This Python tool allows you to encrypt and decrypt text using three different encryption algorithms: **AES**, **DES**, and **RSA**. It demonstrates the use of symmetric and asymmetric encryption techniques with an easy-to-use command-line interface.

## 🛠️ Features

- **AES Encryption**: Uses AES with CBC mode and random keys for encryption.
- **DES Encryption**: Uses DES with ECB mode and random keys.
- **RSA Encryption**: Uses RSA with a 2048-bit key pair for encryption and decryption.
- Encrypt and decrypt any text using these three algorithms.

## 🚀 Installation

### Prerequisites:
Ensure you have Python 3.x installed. You also need to install the following dependencies:

- `pycryptodome` for DES and AES encryption.
- `rsa` for RSA encryption.
- `colorama` for colored console output.

You can install the required libraries using pip:

```bash
pip install pycryptodome rsa colorama
