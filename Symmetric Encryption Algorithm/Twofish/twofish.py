import struct


class Twofish:
    def __init__(self, key: bytes):
        self.key = key
        self.Nk = len(key) // 4
        self.round_keys = self.key_expansion(key)

    def key_expansion(self, key: bytes):
        S = [0] * 4
        subkeys = [0] * 40

        for i in range(self.Nk):
            S[i] = struct.unpack(">I", key[i * 4:(i + 1) * 4])[0]

        for i in range(20):
            A = self.h(2 * i, S)
            B = self.h(2 * i + 1, S)
            B = ((B << 8) | (B >> 24)) & 0xFFFFFFFF

            subkeys[2 * i] = (A + B) & 0xFFFFFFFF
            subkeys[2 * i + 1] = (A + 2 * B) & 0xFFFFFFFF

        return subkeys

    def h(self, X, S):
        return (S[X % self.Nk] ^ ((X * 0x01010101) & 0xFFFFFFFF))

    def encrypt_block(self, block: bytes):
        R = list(struct.unpack(">4I", block))

        for i in range(4):
            R[i] ^= self.round_keys[i]

        for r in range(16):
            T0 = self.h(R[0], self.round_keys)
            T1 = self.h(R[1], self.round_keys)
            T1 = ((T1 << 8) | (T1 >> 24)) & 0xFFFFFFFF

            R[2] ^= (T0 + T1 + self.round_keys[2 * r + 8]) & 0xFFFFFFFF
            R[3] ^= (T0 + 2 * T1 + self.round_keys[2 * r + 9]) & 0xFFFFFFFF
            R = [R[1], R[2], R[3], R[0]]

        for i in range(4):
            R[i] ^= self.round_keys[i + 4]

        return struct.pack(">4I", *R)

    def decrypt_block(self, block: bytes):
        R = list(struct.unpack(">4I", block))

        for i in range(4):
            R[i] ^= self.round_keys[i + 4]

        for r in range(15, -1, -1):
            R = [R[3], R[0], R[1], R[2]]
            T0 = self.h(R[0], self.round_keys)
            T1 = self.h(R[1], self.round_keys)
            T1 = ((T1 << 8) | (T1 >> 24)) & 0xFFFFFFFF

            R[2] ^= (T0 + T1 + self.round_keys[2 * r + 8]) & 0xFFFFFFFF
            R[3] ^= (T0 + 2 * T1 + self.round_keys[2 * r + 9]) & 0xFFFFFFFF

        for i in range(4):
            R[i] ^= self.round_keys[i]

        return struct.pack(">4I", *R)

    def encrypt(self, plaintext: bytes) -> bytes:
        padded = self.pad(plaintext)
        ciphertext = b""

        for i in range(0, len(padded), 16):
            ciphertext += self.encrypt_block(padded[i:i+16])

        return ciphertext

    def decrypt(self, ciphertext: bytes) -> bytes:
        plaintext = b""

        for i in range(0, len(ciphertext), 16):
            plaintext += self.decrypt_block(ciphertext[i:i+16])

        return self.unpad(plaintext)

    @staticmethod
    def pad(data: bytes) -> bytes:
        pad_len = 16 - (len(data) % 16)
        return data + bytes([pad_len] * pad_len)

    @staticmethod
    def unpad(data: bytes) -> bytes:
        pad_len = data[-1]
        return data[:-pad_len]



# ------------------------ Test ------------------------
key = b"thisis256bitkey!!!"
plaintext = b"Hello, Twofish!!!"
twofish = Twofish(key)
ciphertext = twofish.encrypt(plaintext)
decrypted_text = twofish.decrypt(ciphertext)
ciphertext, decrypted_text
