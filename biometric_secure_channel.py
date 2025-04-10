from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os


class KeyExchange:
    def __init__(self):
        self.private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
        self.public_key = self.private_key.public_key()

    def generate_shared_key(self, peer_public_key_bytes):
        peer_public_key = serialization.load_pem_public_key(peer_public_key_bytes, backend=default_backend())
        shared_key = self.private_key.exchange(ec.ECDH(), peer_public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'biometric-secure-channel',
            backend=default_backend()
        ).derive(shared_key)
        return derived_key

    def get_serialized_public_key(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )


class Encryptor:
    def __init__(self, key):
        self.key = key

    def encrypt(self, plaintext):
        nonce = os.urandom(12)
        encryptor = Cipher(
            algorithms.AES(self.key),
            modes.GCM(nonce),
            backend=default_backend()
        ).encryptor()
        ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
        return ciphertext, nonce, encryptor.tag

    def decrypt(self, ciphertext, nonce, tag):
        decryptor = Cipher(
            algorithms.AES(self.key),
            modes.GCM(nonce, tag),
            backend=default_backend()
        ).decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()


class BiometricSecureChannel:
    def __init__(self):
        self.sensor = KeyExchange()
        self.engine = KeyExchange()

    def establish_secure_channel(self):
        sensor_pub = self.sensor.get_serialized_public_key()
        engine_pub = self.engine.get_serialized_public_key()

        sensor_key = self.sensor.generate_shared_key(engine_pub)
        engine_key = self.engine.generate_shared_key(sensor_pub)

        print("Sensor AES Key: ", sensor_key.hex())
        print("Engine AES Key: ", engine_key.hex())
        print("Keys Match? ", sensor_key == engine_key)

        return sensor_key, engine_key

    def secure_transmission(self, biometric_data):
        sensor_key, engine_key = self.establish_secure_channel()

        encryptor = Encryptor(sensor_key)
        ciphertext, nonce, tag = encryptor.encrypt(biometric_data)
        print("\nEncrypted Biometric Data (hex):", ciphertext.hex())

        decryptor = Encryptor(engine_key)
        decrypted_data = decryptor.decrypt(ciphertext, nonce, tag).decode()
        print("Decrypted Biometric Data:", decrypted_data)
        print("Match Original? ", decrypted_data == biometric_data)


# 🚀 Launch
if __name__ == "__main__":
    bsc = BiometricSecureChannel()
    bsc.secure_transmission("fingerprint_template_12345")
