from operator import xor
import random
import prime

def encrypt(plaintext, key):
    return xor(plaintext, key)

def decrypt(ciphertext, key):
    return xor(ciphertext, key)
