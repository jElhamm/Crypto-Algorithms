import random
import sympy


class DiffieHellmanFixed:
    def __init__(self, p: int, g: int):
        self.p = p
        self.g = g
        self.private_key = random.randint(2, p - 2)
        self.public_key = pow(g, self.private_key, p)

    def compute_shared_secret(self, received_public_key):
        shared_secret = pow(received_public_key, self.private_key, self.p)
        return shared_secret


p = sympy.randprime(2**511, 2**512)
g = random.randint(2, p - 1) 

alice = DiffieHellmanFixed(p, g)
bob = DiffieHellmanFixed(p, g)

alice_shared_secret = alice.compute_shared_secret(bob.public_key)
bob_shared_secret = bob.compute_shared_secret(alice.public_key)

alice_shared_secret, bob_shared_secret, alice_shared_secret == bob_shared_secret
