class RC4:
    def __init__(self, key: bytes):
        self.S = list(range(256))
        self.key_schedule(key)

    def key_schedule(self, key: bytes):
        j = 0
        key_length = len(key)

        for i in range(256):
            j = (j + self.S[i] + key[i % key_length]) % 256
            self.S[i], self.S[j] = self.S[j], self.S[i]

    def generate_keystream(self, length: int):
        i = j = 0
        keystream = bytearray()

        for _ in range(length):
            i = (i + 1) % 256
            j = (j + self.S[i]) % 256
            self.S[i], self.S[j] = self.S[j], self.S[i]
            keystream.append(self.S[(self.S[i] + self.S[j]) % 256])

        return keystream

    def encrypt(self, plaintext: bytes) -> bytes:
        keystream = self.generate_keystream(len(plaintext))
        return bytes([p ^ k for p, k in zip(plaintext, keystream)])

    def decrypt(self, ciphertext: bytes) -> bytes:
        return self.encrypt(ciphertext)


# --------------------------- Test ---------------------------
key = b"supersecretkey"
plaintext = b"Hello, RC4 Stream Cipher!"
rc4 = RC4(key)
ciphertext = rc4.encrypt(plaintext)
decrypted_text = rc4.decrypt(ciphertext)
ciphertext, decrypted_text
