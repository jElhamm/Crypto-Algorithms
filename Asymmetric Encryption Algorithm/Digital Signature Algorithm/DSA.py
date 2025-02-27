import hashlib
import random

class DigitalSignature:
    def __init__(self, p, q, g):
        self.p = p
        self.q = q
        self.g = g
    
    def generate_key(self):
        x = random.randint(1, self.q-1)
        y = pow(self.g, x, self.p)
        return x, y

    def sign_message(self, message, x):
        h = int(hashlib.sha1(message.encode('utf-8')).hexdigest(), 16)
        k = random.randint(1, self.q-1)

        r = pow(self.g, k, self.p) % self.q
        s = (pow(k, -1, self.q) * (h + x * r)) % self.q
        
        return r, s
    
    def verify_signature(self, message, r, s, y):
        h = int(hashlib.sha1(message.encode('utf-8')).hexdigest(), 16)
        w = pow(s, -1, self.q)
        u1 = (h * w) % self.q
        u2 = (r * w) % self.q
        v = (pow(self.g, u1, self.p) * pow(y, u2, self.p)) % self.p % self.q
        return v == r


def get_user_input():
    p = int(input("Enter prime p (large prime number): "))
    q = int(input("Enter prime q (subgroup order): "))
    g = int(input("Enter base g (generator): "))
    message = input("Enter the message you want to sign: ")
    
    return p, q, g, message


def main():
    p, q, g, message = get_user_input()
    signature_system = DigitalSignature(p, q, g)

    x, y = signature_system.generate_key()
    print(f"Private key (x): {x}")
    print(f"Public key (y): {y}")

    r, s = signature_system.sign_message(message, x)
    print(f"Signature: (r, s) = ({r}, {s})")
    
    is_valid = signature_system.verify_signature(message, r, s, y)
    if is_valid:
        print("The signature is valid.")
    else:
        print("The signature is invalid.")


if __name__ == "__main__":
    main()
