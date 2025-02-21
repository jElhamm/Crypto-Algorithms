import random
import sympy


class RSA:
    def __init__(self, key_size=1024):
        self.key_size = key_size
        self.public_key, self.private_key = self.generate_keys()

    def generate_prime(self, bits):
        return sympy.randprime(2**(bits-1), 2**bits)

    def mod_inverse(self, e, phi):

        g, x, _ = self.extended_gcd(e, phi)
        if g != 1:
            raise ValueError("Eroor !")
        return x % phi

    def extended_gcd(self, a, b):
        if a == 0:
            return b, 0, 1
        g, x1, y1 = self.extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return g, x, y

    def generate_keys(self):
        p = self.generate_prime(self.key_size // 2)
        q = self.generate_prime(self.key_size // 2)
        n = p * q
        phi = (p - 1) * (q - 1)

        e = 65537
        d = self.mod_inverse(e, phi)

        public_key = (e, n)
        private_key = (d, n)

        return public_key, private_key

    def encrypt(self, plaintext: str):
        e, n = self.public_key
        plaintext_int = int.from_bytes(plaintext.encode(), "big")
        ciphertext = pow(plaintext_int, e, n)
        return ciphertext

    def decrypt(self, ciphertext: int):
        d, n = self.private_key
        plaintext_int = pow(ciphertext, d, n)
        plaintext_bytes = plaintext_int.to_bytes((plaintext_int.bit_length() + 7) // 8, "big")
        return plaintext_bytes.decode()


# -------------------- Test --------------------
rsa = RSA(key_size=512)
plaintext = "Hello, RSA Algorithm!"
ciphertext = rsa.encrypt(plaintext)
decrypted_text = rsa.decrypt(ciphertext)
ciphertext, decrypted_text
