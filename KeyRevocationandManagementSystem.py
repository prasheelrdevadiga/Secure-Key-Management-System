# List to store revoked keys
revoked_keys = []

# Function to revoke a key
def revoke_key(key_name):
    if key_name not in revoked_keys:
        revoked_keys.append(key_name)
        print(f"⚠️ Key '{key_name}' has been revoked!")
    else:
        print(f"⚠️ Key '{key_name}' is already revoked!")

# Function to check if a key is revoked
def is_key_revoked(key_name):
    return key_name in revoked_keys

# Function to reinstate a revoked key
def restore_key(key_name):
    if key_name in revoked_keys:
        revoked_keys.remove(key_name)
        print(f"✅ Key '{key_name}' has been reinstated!")
    else:
        print(f"❌ Key '{key_name}' was not found in the revoked list!")
