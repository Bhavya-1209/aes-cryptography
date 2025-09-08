from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import os

# ---------- AES Helper Functions ----------
def pad(text):
    block_size = 16
    padding_len = block_size - len(text) % block_size
    return text + chr(padding_len) * padding_len

def unpad(text):
    return text[:-ord(text[-1])]

def aes_encrypt(message):
    key = get_random_bytes(16)  # AES-128
    iv = get_random_bytes(16)   # Initialization vector
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(message).encode())
    
    # Save key to file
    with open("aes_key.key", "wb") as f:
        f.write(key)
    
    # Return IV + ciphertext encoded in base64
    return base64.b64encode(iv + ciphertext).decode()

def aes_decrypt(enc_message):
    if not os.path.exists("aes_key.key"):
        print("AES key file not found! Encrypt first.")
        return
    key = open("aes_key.key", "rb").read()
    raw = base64.b64decode(enc_message)
    iv, ciphertext = raw[:16], raw[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(ciphertext).decode()
    return unpad(decrypted)

# ---------- Main Program ----------
if __name__ == "__main__":
    print("=== AES Encryption Tool ===")
    choice = input("Encrypt (E) or Decrypt (D)? ").upper()

    if choice == "E":
        msg = input("Enter message to encrypt: ")
        encrypted = aes_encrypt(msg)
        print("Encrypted message:", encrypted)
        print("AES key saved automatically in aes_key.key file.")

    elif choice == "D":
        enc_msg = input("Enter AES encrypted message: ")
        decrypted = aes_decrypt(enc_msg)
        if decrypted:
            print("Decrypted message:", decrypted)
    else:
        print("Invalid choice!")
