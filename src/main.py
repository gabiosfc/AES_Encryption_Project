from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import constant_time
import os
import base64

def generate_key(password):
    salt = b'salt_'  # Use a proper random salt in real applications
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt(message, password):
    key = generate_key(password)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    padder = padding.PKCS7(128).padder()
    padded_message = padder.update(message.encode()) + padder.finalize()
    
    encrypted_message = encryptor.update(padded_message) + encryptor.finalize()
    return base64.b64encode(iv + encrypted_message).decode()

def decrypt(encrypted_message, password):
    encrypted_message = base64.b64decode(encrypted_message)
    iv = encrypted_message[:16]
    key = generate_key(password)
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    decrypted_message = decryptor.update(encrypted_message[16:]) + decryptor.finalize()
    
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_message = unpadder.update(decrypted_message) + unpadder.finalize()
    
    return unpadded_message.decode()

# Exemplo de uso
mensagem = "Esta é uma mensagem secreta."
chave = "minha_chave_secreta"

mensagem_cifrada = encrypt(mensagem, chave)
print(f"Mensagem Cifrada: {mensagem_cifrada}")

mensagem_decifrada = decrypt(mensagem_cifrada, chave)
print(f"Mensagem Decifrada: {mensagem_decifrada}")
