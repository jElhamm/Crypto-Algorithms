class DES:
    # Initial and Final Permutations
    IP = [58, 50, 42, 34, 26, 18, 10, 2,
          60, 52, 44, 36, 28, 20, 12, 4,
          62, 54, 46, 38, 30, 22, 14, 6,
          64, 56, 48, 40, 32, 24, 16, 8,
          57, 49, 41, 33, 25, 17, 9, 1,
          59, 51, 43, 35, 27, 19, 11, 3,
          61, 53, 45, 37, 29, 21, 13, 5,
          63, 55, 47, 39, 31, 23, 15, 7]

    FP = [40, 8, 48, 16, 56, 24, 64, 32,
          39, 7, 47, 15, 55, 23, 63, 31,
          38, 6, 46, 14, 54, 22, 62, 30,
          37, 5, 45, 13, 53, 21, 61, 29,
          36, 4, 44, 12, 52, 20, 60, 28,
          35, 3, 43, 11, 51, 19, 59, 27,
          34, 2, 42, 10, 50, 18, 58, 26,
          33, 1, 41, 9, 49, 17, 57, 25]

    def __init__(self, key):
        self.key = key
        self.subkeys = self.generate_subkeys()

    def permute(self, block, table):
        return ''.join(block[i - 1] for i in table)

    def encrypt_block(self, block):
        block = self.permute(block, self.IP)
        left, right = block[:32], block[32:]

        for subkey in self.subkeys:
            left, right = right, bin(int(left, 2) ^ int(right, 2))[2:].zfill(32)

        return self.permute(right + left, self.FP)

    def decrypt_block(self, block):
        block = self.permute(block, self.IP)
        left, right = block[:32], block[32:]

        for subkey in reversed(self.subkeys):
            left, right = right, bin(int(left, 2) ^ int(right, 2))[2:].zfill(32)

        return self.permute(right + left, self.FP)

    def generate_subkeys(self):
        # Placeholder for actual key scheduling logic
        return [self.key] * 16


class TripleDES:
    def __init__(self, key1, key2, key3=None):
        self.des1 = DES(key1)
        self.des2 = DES(key2)
        self.des3 = DES(key3 if key3 else key1)

    def encrypt_block(self, block):
        # Encrypt → Decrypt → Encrypt
        block = self.des1.encrypt_block(block)
        block = self.des2.decrypt_block(block)
        block = self.des3.encrypt_block(block)
        return block

    def decrypt_block(self, block):
        # Decrypt → Encrypt → Decrypt
        block = self.des3.decrypt_block(block)
        block = self.des2.encrypt_block(block)
        block = self.des1.decrypt_block(block)
        return block


def text_to_bin(text):
    return ''.join(format(ord(c), '08b') for c in text).ljust(64, '0')[:64]


def bin_to_text(binary):
    return ''.join(chr(int(binary[i:i + 8], 2)) for i in range(0, len(binary), 8))


if __name__ == "__main__":
    key1 = input("Enter the first 64-bit key (binary): ")
    key2 = input("Enter the second 64-bit key (binary): ")
    key3 = input("Enter the third 64-bit key (binary) or press Enter to reuse Key1: ")

    plaintext = input("Enter the text to encrypt: ")
    plaintext_bin = text_to_bin(plaintext)                                             # Convert text to binary

    des3 = TripleDES(key1, key2, key3 if key3 else key1)                               # Initialize 3DES
    ciphertext = des3.encrypt_block(plaintext_bin)
    decrypted_bin = des3.decrypt_block(ciphertext)
    decrypted_text = bin_to_text(decrypted_bin)

    print(f"\nCiphertext: {ciphertext}")
    print(f"Decrypted text: {decrypted_text}")
