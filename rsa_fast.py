import prime
import random
from math import gcd

"""
Implmentation of the extended gcd algorithm.

Input: Numbers a and b
Output: g, x, and y of the egcd algorithm
"""
def egcd(a, b):
    """return (g, x, y) such that a*x + b*y = g = gcd(a, b)"""
    x0, x1, y0, y1 = 0, 1, 1, 0
    while a != 0:
        q, b, a = b // a, a, b % a
        y0, y1 = y1, y0 - q * y1
        x0, x1 = x1, x0 - q * x1
    return b, x0, y0

"""
Multiplicative inverse of two numbers e and phi.
Outputs number b such that b*e%phi is equal to 1.

Input: Numbers e and phi
Output: Multiplicative inverse
"""
def multiplicative_inverse(e, phi):
    g, x, y = egcd(e, phi)
    if g == 1:
        return x % phi

"""
Outputs valid keypair for RSA.
1. Send random primes p and q to RSA key generation.
2. Check if RSA keygeneration led to a valid key pair.
3. Go back to #1 if not so.
4. Return valid keypair.


Input: Bitlength of keys
Output: Public (key1) and Private (key2) keys
"""
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

"""
Outputs valid keypair for RSA given prime numbers p and q.
1. Calculates the totient (called phi in the code) of p and q: tot(p, q) = (p-1)*(q-1)
2. Calculates n which is p*q
3. Finds a random number e between 1 and phi.
4. Check if e is coprime with phi. Repeat #3 until it is.
5. Find d, the multiplicative inverse of e mod phi. (NOTE that this may be None if not possible.)
6. Set public key to be (e, n)
7. Set private key to (d, n)

Input: Bitlength of keys
Output: Public (key1) and Private (key2) keys
"""
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

    #Use Euclid's Algorithm to verify that e and phi(n) are coprime
    g = gcd(e, phi)
    while g != 1:
        e = int(random.randint(1, phi))
        g = gcd(e, phi)

    #Use Extended Euclid's Algorithm to generate the private key
    d = multiplicative_inverse(e, phi)
    #Return public and private keypair
    #Public key is (e, n) and private key is (d, n)
    return ((e, n), (d, n))

"""
Encrypts message into ciphertext.
Ciphertext = Message^e % n

Input: Public key (pk) and the message (plaintext)
Output: Ciphertext
"""
def encrypt(pk, plaintext):
    e, n = pk
    return pow(plaintext, e, n)

"""
Decrypts ciphertext into message.
Message = Ciphertext^d % n = Message^(ed) % n = Message % n

Input: Private key (pk) and the ciphertext
Output: Plaintext/Message
"""
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
    result = plaintext == plaintxt and encrypted_msg < n
    if not result:
        print(plaintext, plaintxt)
    counter += 1
    if counter % 100 == 0:
        print(counter)
    if counter > 1000000:
        break
"""

#SPEED TESTING SCHEME
import time

key_size = 128
while key_size < 5000:
    start_time = time.time()
    plain_size = 128
    plaintext = random.getrandbits(plain_size)
    public, private = generate_keys(key_size)
    e, n = public
    encrypted_msg = encrypt(private, plaintext)
    plaintxt = decrypt(public, encrypted_msg)
    result = plaintext == plaintxt
    if not result:
        print(plaintext, plaintxt)
    else:
        print("Time it took to create keys, encrypt, and then decrypt " + str(plain_size) + " bits using " + str(key_size) + " bit keys: ", time.time() - start_time)
    key_size *= 2
print("Rest of the test removed for demo due to how long it takes to run.")

