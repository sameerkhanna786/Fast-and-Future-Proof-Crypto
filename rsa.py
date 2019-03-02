import prime
import random
from math import gcd

def egcd(a, b):
    if a == 0:
        return b, 0, 1
    else:
        g, y, x = egcd(b % a, a)
        return g, x - (b // a) * y, y

def multiplicative_inverse(e, phi):
    g, x, y = egcd(e, phi)
    if g == 1:
        return x % phi

def generate_keys(num_bits):
    valid_keypair = False
    while not valid_keypair:
        p = prime.generate_a_prime_number(num_bits)
        q = prime.generate_a_prime_number(num_bits)
        tot = (p-1)*(q-1)
        if p==q:
            continue
        key1, key2 = generate_keypair(p, q)
        e, n = key1
        d, n = key2
        valid_keypair = not(None in key1 or None in key2) and n > pow(2, num_bits)
    return key1, key2

def generate_keypair(p, q):
    if not (prime.isPrime(p) and prime.isPrime(q)):
        raise ValueError('Both numbers must be prime.')
    elif p == q:
        raise ValueError('p and q cannot be equal')
    #n = pq
    n = p * q

    #Phi is the totient of n
    phi = (p-1) * (q-1)

    #Choose an integer e such that e and phi(n) are coprime
    e = int(random.randint(1, phi))

    #Use Euclid's Algorithm to verify that e and phi(n) are comprime
    g = gcd(e, phi)
    while g != 1:
        e = int(random.randint(1, phi))
        g = gcd(e, phi)

    #Use Extended Euclid's Algorithm to generate the private key
    d = multiplicative_inverse(e, phi)
    #Return public and private keypair
    #Public key is (e, n) and private key is (d, n)
    return ((e, n), (d, n))

def encrypt(pk, plaintext):
    e, n = pk
    return pow(plaintext, e, n)

def decrypt(pk, ciphertext):
    d, n = pk
    return pow(ciphertext, d, n)

"""
# TESTING SCHEME
result = True
counter = 0
while result:
    plaintext = random.getrandbits(128)
    public, private = generate_keys(128)
    e, n = public
    encrypted_msg = encrypt(private, plaintext)
    plaintxt = decrypt(public, encrypted_msg)
    result = plaintext == plaintxt
    if not result:
        print(plaintext, plaintxt)
    counter += 1
    if counter % 100 == 0:
        print(counter)
    if counter > 1000000:
        break
"""
