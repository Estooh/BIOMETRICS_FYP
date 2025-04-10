from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Generate ECDH private keys for both Sensor (Alice) and Auth Engine (Bob)
sensor_private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
engine_private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())

# Generate corresponding public keys
sensor_public_key = sensor_private_key.public_key()
engine_public_key = engine_private_key.public_key()

# Exchange and compute shared secrets
sensor_shared_key = sensor_private_key.exchange(ec.ECDH(), engine_public_key)
engine_shared_key = engine_private_key.exchange(ec.ECDH(), sensor_public_key)

# Derive AES session key using HKDF
def derive_key(shared_key):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # 256-bit AES key
        salt=None,
        info=b'biometric-secure-transport',
        backend=default_backend()
    ).derive(shared_key)

sensor_aes_key = derive_key(sensor_shared_key)
engine_aes_key = derive_key(engine_shared_key)

# Check if both keys are equal (they must be!)
print("Sensor AES Key: ", sensor_aes_key.hex())
print("Engine AES Key: ", engine_aes_key.hex())
print("Keys Match? ", sensor_aes_key == engine_aes_key)

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

def encrypt_data(key, plaintext):
    # Generate a 12-byte nonce for AES-GCM
    nonce = os.urandom(12)
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(nonce),
        backend=default_backend()
    ).encryptor()
    
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    return (ciphertext, nonce, encryptor.tag)

def decrypt_data(key, ciphertext, nonce, tag):
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(nonce, tag),
        backend=default_backend()
    ).decryptor()
    
    decrypted = decryptor.update(ciphertext) + decryptor.finalize()
    return decrypted.decode()

# Simulate biometric data
biometric_sample = "fingerprint_template_12345"

# Encrypt using Sensor's AES Key
ciphertext, nonce, tag = encrypt_data(sensor_aes_key, biometric_sample)
print("\nEncrypted Biometric Data (hex):", ciphertext.hex())

# Decrypt using Engine's AES Key
decrypted_data = decrypt_data(engine_aes_key, ciphertext, nonce, tag)
print("Decrypted Biometric Data:", decrypted_data)

# Final check
print("Match Original? ", decrypted_data == biometric_sample)
