import os
import hashlib

def simular_mlkem768_kem():
    """
    Simulación conceptual del protocolo ML-KEM-768 (CRYSTALS-Kyber).
    Genera un par de claves (Pública y Privada), un texto cifrado de encapsulamiento
    y un secreto compartido (shared secret) de 256 bits.
    """
    # 1. Generación de claves (KeyPair Generation)
    # En ML-KEM real, la clave pública se basa en vectores sobre anillos de polinomios (Lattices)
    semilla_privada = os.urandom(32)
    clave_privada = hashlib.sha3_512(semilla_privada).hexdigest()
    
    # La clave pública deriva de la privada
    clave_publica = hashlib.sha3_256(clave_privada.encode()).hexdigest()
    
    # 2. Encapsulamiento (Encapsulation)
    # Genera el secreto compartido y el ciphertext que se transmite
    entropia_encapsulamiento = os.urandom(32)
    ciphertext = hashlib.sha3_256(clave_publica.encode() + entropia_encapsulamiento).hexdigest()
    
    # Secreto compartido derivado
    secreto_compartido = hashlib.sha3_256(ciphertext.encode() + clave_privada.encode()).hexdigest()
    
    return clave_publica, ciphertext, secreto_compartido

def cifrar_password_xor(password: str, secreto_hex: str) -> str:
    """
    Cifra la contraseña realizando una operación XOR simétrica 
    entre los bytes de la contraseña y el secreto compartido derivado de ML-KEM.
    """
    pass_bytes = password.encode('utf-8')
    pass_int = int.from_bytes(pass_bytes, byteorder='big')
    
    secreto_bytes = bytes.fromhex(secreto_hex)
    secreto_int = int.from_bytes(secreto_bytes, byteorder='big')
    
    cifrado_int = pass_int ^ secreto_int
    return hex(cifrado_int)


if __name__ == "__main__":
    # Prueba individual del script ML-KEM
    pub_key, ciphertext, shared_secret = simular_mlkem768_kem()
    print("--- PRUEBA ML-KEM ---")
    print("Clave Pública:", pub_key[:30], "...")
    print("Ciphertext KEM:", ciphertext[:30], "...")
    print("Secreto Compartido:", shared_secret)
    
    password_prueba = "12345678"
    password_cifrada = cifrar_password_xor(password_prueba, shared_secret)
    print("\nContraseña Original:", password_prueba)
    print("Contraseña Cifrada (Hex):", password_cifrada)