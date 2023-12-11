import os

def generate_aes_key(length=32):
    return os.urandom(length)

if __name__ == "__main__":
    key = generate_aes_key()
    print("AES Key (hex):", key.hex())