# mlkem_modulo.py
# Requiere: pip install pqcrypto (o uso de la implementación estándar Kyber/ML-KEM)
# Para una simulación portátil sin compilar C, usamos la estructura estándar KEM:

import os
from pqcrypto.kem.mlkem768 import generate_keypair, encrypt, decrypt

def generar_par_claves_mlkem():
    """
    Genera un par de claves (Pública y Privada) usando ML-KEM-768.
    Retorna (public_key_hex, secret_key_hex)
    """
    public_key, secret_key = generate_keypair()
    return public_key.hex(), secret_key.hex()

def encapsular_secreto_mlkem(public_key_hex: str):
    """
    Alice (o la app) toma la clave pública de ML-KEM y encapsula una clave secreta.
    Retorna (ciphertext_hex, shared_secret_hex)
    """
    public_key = bytes.fromhex(public_key_hex)
    ciphertext, shared_secret = encrypt(public_key)
    return ciphertext.hex(), shared_secret.hex()

def desencapsular_secreto_mlkem(ciphertext_hex: str, secret_key_hex: str) -> str:
    """
    Bob (el servidor) usa su clave privada para obtener el mismo secreto compartido.
    """
    ciphertext = bytes.fromhex(ciphertext_hex)
    secret_key = bytes.fromhex(secret_key_hex)
    shared_secret = decrypt(ciphertext, secret_key)
    return shared_secret.hex()

def cifrar_password_xor(password: str, shared_secret_hex: str) -> str:
    """
    Cifra la contraseña usando el secreto compartido derivado de ML-KEM mediante XOR.
    """
    pass_bytes = password.encode('utf-8')
    pass_int = int.from_bytes(pass_bytes, byteorder='big')
    
    # Tomamos el secreto compartido de ML-KEM
    secret_bytes = bytes.fromhex(shared_secret_hex)
    secret_int = int.from_bytes(secret_bytes, byteorder='big')
    
    cifrado_int = pass_int ^ secret_int
    return hex(cifrado_int)