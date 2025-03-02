import os
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes



class ECCEncryption:
    def __init__(self):
        self.private_key, self.public_key = self.generate_ecc_keys()

    def generate_ecc_keys(self):
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()
        return private_key, public_key

    def serialize_private_key(self):
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

    def serialize_public_key(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def encrypt_message(self, message):
        shared_key = self.private_key.exchange(ec.ECDH(), self.public_key)  
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        secret_key = kdf.derive(shared_key)

        nonce = os.urandom(12)
        cipher = Cipher(algorithms.AES(secret_key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_message = encryptor.update(message) + encryptor.finalize()
        return base64.b64encode(salt + nonce + encrypted_message + encryptor.tag)

    def decrypt_message(self, encrypted_message):
        shared_key = self.private_key.exchange(ec.ECDH(), self.public_key)  
        encrypted_message = base64.b64decode(encrypted_message)
        salt = encrypted_message[:16]
        nonce = encrypted_message[16:28]
        ciphertext = encrypted_message[28:-16]
        tag = encrypted_message[-16:]

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        secret_key = kdf.derive(shared_key)
        cipher = Cipher(algorithms.AES(secret_key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()

        try:
            decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()
            return decrypted_message.decode('utf-8')
        except Exception as e:
            print("Decryption failed:", e)
            return None

    def get_serialized_private_key(self):
        return self.serialize_private_key().decode()

    def get_serialized_public_key(self):
        return self.serialize_public_key().decode()

def main():
    encryption = ECCEncryption()
    print("Private Key:", encryption.get_serialized_private_key())
    print("Public Key:", encryption.get_serialized_public_key())

    message = input("Enter the message you want to encrypt: ")
    encrypted_message = encryption.encrypt_message(message.encode())
    print("Encrypted Message:", encrypted_message.decode())
    decrypted_message = encryption.decrypt_message(encrypted_message)

    if decrypted_message:
        print("Decrypted Message:", decrypted_message)
    else:
        print("Decrypted Message is not valid UTF-8.")


if __name__ == "__main__":
    main()
