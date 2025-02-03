import struct


class Blowfish:
    def __init__(self, key: bytes):
        self.P = self.initial_P[:]
        self.S = [s[:] for s in self.initial_S]

        self.key_schedule(key)

    initial_P = [
        0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344,
        0xA4093822, 0x299F31D0, 0x082EFA98, 0xEC4E6C89,
        0x452821E6, 0x38D01377, 0xBE5466CF, 0x34E90C6C,
        0xC0AC29B7, 0xC97C50DD, 0x3F84D5B5, 0xB5470917,
        0x9216D5D9, 0x8979FB1B
    ]

    initial_S = [[
        0xD1310BA6, 0x98DFB5AC, 0x2FFD72DB, 0xD01ADFB7,
        0xB8E1AFED, 0x6A267E96, 0xBA7C9045, 0xF12C7F99,
        0x24A19947, 0xB3916CF7, 0x0801F2E2, 0x858EFC16,
        0x636920D8, 0x71574E69, 0xA458FEA3, 0xF4933D7E
    ]] * 4

    def key_schedule(self, key: bytes):
        key_len = len(key)
        key = (key * (72 // key_len + 1))[:72]

        for i in range(18):
            self.P[i] ^= struct.unpack(">I", key[i * 4:(i + 1) * 4])[0]

        data = (0, 0)
        for i in range(0, 18, 2):
            data = self.encrypt_block(*data)
            self.P[i], self.P[i + 1] = data

        for i in range(4):
            for j in range(0, 16, 2):
                data = self.encrypt_block(*data)
                self.S[i][j], self.S[i][j + 1] = data

    def encrypt_block(self, left: int, right: int):
        for i in range(16):
            left = (left ^ self.P[i]) & 0xFFFFFFFF
            right = (right ^ self.f(left)) & 0xFFFFFFFF
            left, right = right, left

        left, right = right, left
        right = (right ^ self.P[16]) & 0xFFFFFFFF
        left = (left ^ self.P[17]) & 0xFFFFFFFF

        return left, right

    def decrypt_block(self, left: int, right: int):
        for i in range(17, 1, -1):
            left = (left ^ self.P[i]) & 0xFFFFFFFF
            right = (right ^ self.f(left)) & 0xFFFFFFFF
            left, right = right, left

        left, right = right, left
        right = (right ^ self.P[1]) & 0xFFFFFFFF
        left = (left ^ self.P[0]) & 0xFFFFFFFF

        return left, right

    def f(self, x: int) -> int:
        a = (x >> 24) & 0xFF
        b = (x >> 16) & 0xFF
        c = (x >> 8) & 0xFF
        d = x & 0xFF

        return ((self.S[0][a % 16] + self.S[1][b % 16]) ^ self.S[2][c % 16]) + self.S[3][d % 16] & 0xFFFFFFFF

    def encrypt(self, plaintext: bytes) -> bytes:
        padded = self.pad(plaintext)
        ciphertext = b""

        for i in range(0, len(padded), 8):
            left, right = struct.unpack(">II", padded[i:i+8])
            left, right = self.encrypt_block(left, right)
            ciphertext += struct.pack(">II", left, right)

        return ciphertext

    def decrypt(self, ciphertext: bytes) -> bytes:
        plaintext = b""

        for i in range(0, len(ciphertext), 8):
            left, right = struct.unpack(">II", ciphertext[i:i+8])
            left, right = self.decrypt_block(left, right)
            plaintext += struct.pack(">II", left, right)

        return self.unpad(plaintext)

    @staticmethod
    def pad(data: bytes) -> bytes:
        pad_len = 8 - (len(data) % 8)
        return data + bytes([pad_len] * pad_len)

    @staticmethod
    def unpad(data: bytes) -> bytes:
        pad_len = data[-1]
        return data[:-pad_len]


# ------------------------------ Test ------------------------------
key = b"supersecretkey"
plaintext = b"Hello, Blowfish!"
blowfish = Blowfish(key)
ciphertext = blowfish.encrypt(plaintext)
decrypted_text = blowfish.decrypt(ciphertext)
ciphertext, decrypted_text
