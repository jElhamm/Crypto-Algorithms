import struct


class ChaCha20:
    def __init__(self, key: bytes, nonce: bytes, counter: int = 0):
        assert len(key) == 32,
        assert len(nonce) == 12,

        self.key = key
        self.nonce = nonce
        self.counter = counter

    def quarter_round(self, state, a, b, c, d):
        state[a] = (state[a] + state[b]) & 0xFFFFFFFF
        state[d] ^= state[a]
        state[d] = (state[d] << 16) | (state[d] >> 16)

        state[c] = (state[c] + state[d]) & 0xFFFFFFFF
        state[b] ^= state[c]
        state[b] = (state[b] << 12) | (state[b] >> 20)

        state[a] = (state[a] + state[b]) & 0xFFFFFFFF
        state[d] ^= state[a]
        state[d] = (state[d] << 8) | (state[d] >> 24)

        state[c] = (state[c] + state[d]) & 0xFFFFFFFF
        state[b] ^= state[c]
        state[b] = (state[b] << 7) | (state[b] >> 25)

    def chacha_block(self, counter):
        constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
        key_words = list(struct.unpack("<8I", self.key))
        counter_nonce = [counter] + list(struct.unpack("<3I", self.nonce))

        state = constants + key_words + counter_nonce

        working_state = state[:]
        for _ in range(10):
            self.quarter_round(working_state, 0, 4, 8, 12)
            self.quarter_round(working_state, 1, 5, 9, 13)
            self.quarter_round(working_state, 2, 6, 10, 14)
            self.quarter_round(working_state, 3, 7, 11, 15)

            self.quarter_round(working_state, 0, 5, 10, 15)
            self.quarter_round(working_state, 1, 6, 11, 12)
            self.quarter_round(working_state, 2, 7, 8, 13)
            self.quarter_round(working_state, 3, 4, 9, 14)

        output = [(state[i] + working_state[i]) & 0xFFFFFFFF for i in range(16)]

        return struct.pack("<16I", *output)  

    def keystream(self, length: int):
        output = bytearray()
        counter = self.counter
        while len(output) < length:
            output += self.chacha_block(counter)
            counter += 1

        return output[:length]

    def encrypt(self, plaintext: bytes) -> bytes:
        keystream = self.keystream(len(plaintext))
        return bytes([p ^ k for p, k in zip(plaintext, keystream)])

    def decrypt(self, ciphertext: bytes) -> bytes:
        return self.encrypt(ciphertext)


# ---------------------------- Test ------------------------------
key = b"thisis32byteslongsupersecretkey!"
nonce = b"123456789012"
plaintext = b"Hello, ChaCha20 Stream Cipher!"
chacha = ChaCha20(key, nonce)
ciphertext = chacha.encrypt(plaintext)
decrypted_text = chacha.decrypt(ciphertext)
ciphertext, decrypted_text
