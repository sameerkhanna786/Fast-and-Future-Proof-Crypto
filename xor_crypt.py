from operator import xor
import random
import prime
"""
This is a basic xor based cryptotography.
XOR, short for exclusive or, follows the following rules:
1 XOR 1 = 0
0 XOR 0 = 0
1 XOR 0 = 1
0 XOR 1 = 1

The computation is done bitwise (bit by bit) in order to get the output.
It works in the following way:
NUM XOR NUM = 0, as a bit by bit comparison would always be either 1 to 1 or 0 to 0.

Thus, MSG XOR KEY XOR KEY = MSG XOR 0 = MSG.

This means that encryption and decrpytion would use the same function (f(x) = x XOR key), making it great for symetric encryption.
"""

def encrypt(plaintext, key):
    return xor(plaintext, key)

def decrypt(ciphertext, key):
    return xor(ciphertext, key)
