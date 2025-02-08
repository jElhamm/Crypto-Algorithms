import itertools


class DES:
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

    E = [32, 1, 2, 3, 4, 5, 4, 5,
         6, 7, 8, 9, 8, 9, 10, 11,
         12, 13, 12, 13, 14, 15, 16, 17,
         16, 17, 18, 19, 20, 21, 20, 21,
         22, 23, 24, 25, 24, 25, 26, 27,
         28, 29, 28, 29, 30, 31, 32, 1]

    P = [16, 7, 20, 21, 29, 12, 28, 17,
         1, 15, 23, 26, 5, 18, 31, 10,
         2, 8, 24, 14, 32, 27, 3, 9,
         19, 13, 30, 6, 22, 11, 4, 25]

    PC1 = [57, 49, 41, 33, 25, 17, 9,
           1, 58, 50, 42, 34, 26, 18,
           10, 2, 59, 51, 43, 35, 27,
           19, 11, 3, 60, 52, 44, 36,
           63, 55, 47, 39, 31, 23, 15,
           7, 62, 54, 46, 38, 30, 22,
           14, 6, 61, 53, 45, 37, 29,
           21, 13, 5, 28, 20, 12, 4]

    PC2 = [14, 17, 11, 24, 1, 5, 3, 28,
           15, 6, 21, 10, 23, 19, 12, 4,
           26, 8, 16, 7, 27, 20, 13, 2,
           41, 52, 31, 37, 47, 55, 30, 40,
           51, 45, 33, 48, 44, 49, 39, 56,
           34, 53, 46, 42, 50, 36, 29, 32]

    SHIFT_SCHEDULE = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

    def __init__(self, key):
        self.key = self.permute(key, self.PC1, 56)
        self.subkeys = self.generate_subkeys()

    def permute(self, bits, table, n):
        return ''.join(bits[i - 1] for i in table)

    def left_shift(self, key, n):
        return key[n:] + key[:n]

    def generate_subkeys(self):
        left, right = self.key[:28], self.key[28:]
        subkeys = []
        for shift in self.SHIFT_SCHEDULE:
            left, right = self.left_shift(left, shift), self.left_shift(right, shift)
            subkeys.append(self.permute(left + right, self.PC2, 48))
        return subkeys

    def feistel_function(self, right, subkey):
        expanded = self.permute(right, self.E, 48)
        xored = bin(int(expanded, 2) ^ int(subkey, 2))[2:].zfill(48)
        return self.permute(xored, self.P, 32)

    def encrypt_block(self, block):
        block = self.permute(block, self.IP, 64)
        left, right = block[:32], block[32:]

        for subkey in self.subkeys:
            left, right = right, bin(int(left, 2) ^ int(self.feistel_function(right, subkey), 2))[2:].zfill(32)

        return self.permute(right + left, self.FP, 64)

    def decrypt_block(self, block):
        block = self.permute(block, self.IP, 64)
        left, right = block[:32], block[32:]

        for subkey in reversed(self.subkeys):
            left, right = right, bin(int(left, 2) ^ int(self.feistel_function(right, subkey), 2))[2:].zfill(32)

        return self.permute(right + left, self.FP, 64)



def text_to_bin(text):
    return ''.join(format(ord(c), '08b') for c in text)


def bin_to_text(binary):
    return ''.join(chr(int(binary[i:i + 8], 2)) for i in range(0, len(binary), 8))


if __name__ == "__main__":
    key = input("Enter a 64-bit key (binary): ")
    plaintext = input("Enter the text to encrypt: ")
    plaintext_bin = text_to_bin(plaintext).ljust(64, '0')[:64]

    des = DES(key)
    ciphertext = des.encrypt_block(plaintext_bin)
    decrypted_bin = des.decrypt_block(ciphertext)
    decrypted_text = bin_to_text(decrypted_bin)

    print(f"\nCiphertext: {ciphertext}")
    print(f"Decrypted text: {decrypted_text}")
