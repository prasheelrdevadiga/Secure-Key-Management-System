# 🔐 Secure Key Management System

## 📌 Overview
The **Secure Key Management System** is a cryptographic toolset designed to handle **key generation, authentication, encryption, and key revocation** for secure communication. It supports **AES key generation, RSA key pairs, digital signatures, X.509 certificates, and key revocation management**.

## 🚀 Features
- **AES Key Generation** – Generates 256-bit AES keys for encryption.
- **RSA Key Pair Generation** – Generates RSA public-private key pairs (4096-bit).
- **Digital Signatures** – Sign and verify messages to ensure integrity and authenticity.
- **X.509 Certificate Management** – Create and manage self-signed certificates.
- **Key Revocation List (KRL)** – Manage revoked keys and prevent unauthorized use.
- **Command-Line Interface** – Easy-to-use interactive system for key management.

---

## 🛠 Installation
### **1️⃣ Install Dependencies**
This project uses Python's `cryptography` library. Install it using:
```sh
pip install cryptography
```


```

---

## 📜 Usage
Run the program using:
```sh
python main.py
```
This opens an interactive menu where you can perform different cryptographic operations.

---



---

## 📌 Modules Explanation
### **1️⃣ AES Key Generation (`aes_keygen.py`)**
🔹 Generates a **256-bit AES key** for encryption.
```python
import os

def generate_aes_key():
    key = os.urandom(32)  # 256-bit key
    with open("aes_key.bin", "wb") as f:
        f.write(key)
    print("🔑 AES Key Generated and Saved to 'aes_key.bin'")
```

### **2️⃣ RSA Key Pair Generation (`rsagen.py`)**
🔹 Generates **4096-bit RSA keys** for secure encryption and authentication.
```python
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    public_key = private_key.public_key()
    with open("private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open("public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    print("🔑 RSA Key Pair Generated!")
```

### **3️⃣ Digital Signatures (`authentication.py`)**
🔹 Signs and verifies messages using **RSA signatures**.
```python
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes

def sign_message(message):
    with open("private_key.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), None)
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def verify_signature(message, signature):
    with open("public_key.pem", "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("✅ Signature Verified!")
    except:
        print("❌ Invalid Signature!")
```

### **4️⃣ X.509 Certificate Management (`certificate_manager.py`)**
🔹 Creates a **self-signed X.509 certificate**.
```python
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes

def generate_x509_certificate():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, "Secure Org"),
        x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "secure.org"),
    ])
    cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
    print("✅ X.509 Certificate Generated!")
```

### **5️⃣ Key Revocation List (`krl_manager.py`)**
🔹 Manages revoked keys to prevent their usage.
```python
revoked_keys = []

def revoke_key(key_name):
    if key_name not in revoked_keys:
        revoked_keys.append(key_name)
        print(f"⚠️ Key '{key_name}' Revoked!")

def check_key_status(key_name):
    return key_name in revoked_keys

def remove_key_revocation(key_name):
    if key_name in revoked_keys:
        revoked_keys.remove(key_name)
        print(f"✅ Key '{key_name}' Un-revoked!")
```

### **6️⃣ Main CLI Application (`main.py`)**
🔹 Provides a command-line interface for user interaction.
```python
import aes_keygen, rsagen, certificate_manager, krl_manager, authentication

def main():
    while True:
        print("\n🔐 Secure Key Management System 🔐")
        print("1. Generate AES Key")
        print("2. Generate RSA Key Pair")
        print("3. Generate X.509 Certificate")
        print("4. Revoke Key")
        print("5. Check Key Revocation Status")
        print("6. Remove Key Revocation")
        print("7. Check Authentication (Sign & Verify)")
        print("8. Exit")
        choice = input("Enter your choice: ")
        if choice == "1":
            aes_keygen.generate_aes_key()
        elif choice == "8":
            break
        else:
            print("❌ Invalid Choice!")

if __name__ == "__main__":
    main()
```

---

## 📌 Conclusion
This **Secure Key Management System** ensures **data protection** with strong encryption, authentication, and key management. 🚀

🔹 **Secure** 🔹 **Reliable** 🔹 **Easy to Use**

