from cryptography.fernet import Fernet

def generate_key():
    return Fernet.generate_key()

def encrypt_message(message, key):
    f = Fernet(key)
    return f.encrypt(message.encode())

def decrypt_message(encrypted_message, key):
    f = Fernet(key)
    return f.decrypt(encrypted_message).decode()

if __name__ == "__main__":
    key = generate_key()
    message = "Abracadabra"
    encrypted_message = encrypt_message(message, key)
    decrypted_message = decrypt_message(encrypted_message, key)

    print(f"Original Message: {message}")
    print(f"Encrypted Message: {encrypted_message}")
    print(f"Decrypted Message: {decrypted_message}")
