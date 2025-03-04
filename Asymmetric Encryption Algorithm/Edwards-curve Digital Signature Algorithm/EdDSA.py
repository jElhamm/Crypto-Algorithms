import hashlib
import os

# ------------------------ Curve parameters for Ed25519 ------------------------
p = 2**255 - 19
l = 2**252 + 277423177773723535358519377812588220463
d = -121665 * pow(121666, p - 2, p) % p
A = 486662
B = 1
N = 2**252 + 277423177773723535358519377812588220462

# -------------------------- Base point of the curve ---------------------------
Bx = 15112221349535400772501151473424177802255311534232426302117909313469357029
By = 46316807470492602080381825768711624267472575846176223469714232424115712737


class EdwardsCurve:
    def __init__(self):
        self.p = p
        self.Bx = Bx
        self.By = By
        self.N = N

    def modinv(self, a):
        """ Modular inverse """
        return pow(a, self.p - 2, self.p)

    def modmul(self, a, b):
        """ Modular multiplication """
        return (a * b) % self.p

    def point_add(self, P, Q):
        """ Point addition on the Edwards curve """
        Px, Py = P
        Qx, Qy = Q
        num = self.modmul(Py - Qy, Px - Qx)
        denom = self.modmul(Py + Qy, Px + Qx)
        return (num * self.modinv(denom)) % self.p, (num * self.modinv(denom)) % self.p

    def scalar_mult(self, k, P):
        """ Scalar multiplication k * P on the Edwards curve """
        R = None
        for i in range(255):
            if (k >> i) & 1:
                if R is None:
                    R = P
                else:
                    R = self.point_add(R, P)
            P = self.point_add(P, P)
        return R


class EdDSA:
    def __init__(self):
        self.curve = EdwardsCurve()

    def hash(self, msg):
        """ Hash function (SHA-512) for EdDSA """
        return hashlib.sha512(msg.encode('utf-8')).digest()

    def sign(self, message, private_key):
        """ EdDSA Signing """
        h1 = self.hash(message)
        h1 = h1[:32]                                                            # First 32 bytes of the SHA-512 hash
        r = int.from_bytes(h1, 'little') % self.curve.N
        R = self.curve.scalar_mult(r, (self.curve.Bx, self.curve.By))           # R = r * B (Base point)
        Rx, Ry = R
        h2 = self.hash(message)
        h2 = h2[:32]                                                            # Again take the first 32 bytes
        h2_int = int.from_bytes(h2, 'little')
        s = (r + h2_int * private_key) % self.curve.N
        return (Rx, Ry), s

    def verify(self, message, signature, public_key):
        """ EdDSA Verification """
        (Rx, Ry), s = signature
        h1 = self.hash(message)
        h1 = h1[:32]
        h1_int = int.from_bytes(h1, 'little')
        R = self.curve.scalar_mult(s, (self.curve.Bx, self.curve.By))
        Q = self.curve.scalar_mult(h1_int, public_key)
        R_check = self.curve.point_add(R, Q)
        return R_check == (Rx, Ry)

class KeyGenerator:
    @staticmethod
    def generate_private_key():
        """ Generate a random 32-byte private key """
        return int.from_bytes(os.urandom(32), 'little') % N

    @staticmethod
    def private_to_public(private_key):
        """ Public key from private key """
        curve = EdwardsCurve()
        R = curve.scalar_mult(private_key, (curve.Bx, curve.By))
        return R

def main():
    message = input("\n\n---> Enter the message: ")
    private_key = KeyGenerator.generate_private_key()
    public_key = KeyGenerator.private_to_public(private_key)

    print(f"\nPrivate Key: {private_key}")
    print(f"\nPublic Key: {public_key}")
    eddsa = EdDSA()

    signature = eddsa.sign(message, private_key)
    print(f"\nSignature: {signature}")

    if eddsa.verify(message, signature, public_key):
        print("\n---> Signature is valid.\n")
    else:
        print("\n---> Signature is invalid.\n")


if __name__ == "__main__":
    main()

