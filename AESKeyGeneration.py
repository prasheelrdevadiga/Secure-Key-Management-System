import os

def create_aes_key():
    key = os.urandom(32)  # Generates a 256-bit AES key
    with open("aes_key.bin", "wb") as file:
        file.write(key)
    print("✅ AES Key successfully created and stored in 'aes_key.bin'.")
