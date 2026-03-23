from Crypto.Cipher import AES
import hashlib

def derive_key(password):
    return hashlib.sha256(password.encode()).digest()

def encrypt_file(file_data, password):
    key = derive_key(password)
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(file_data)
    return cipher.nonce + tag + ciphertext

def decrypt_file(encrypted_data, password):
    key = derive_key(password)
    nonce = encrypted_data[:16]
    tag = encrypted_data[16:32]
    ciphertext = encrypted_data[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)