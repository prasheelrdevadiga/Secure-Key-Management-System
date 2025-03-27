from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.exceptions import InvalidSignature

# Function to load the RSA private key from a file
def get_private_key():
    with open("private_key.pem", "rb") as key_file:
        return load_pem_private_key(key_file.read(), password=None)

# Function to generate a digital signature for a message
def generate_signature(message):
    private_key = get_private_key()
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

# Function to validate the digital signature
def validate_signature(message, signature):
    try:
        public_key = get_private_key().public_key()
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("✅ Signature is valid!")
    except InvalidSignature:
        print("❌ Signature verification failed!")
