import prime
import random
from random import randint

def encryption(plaintext, n):
    #plaintext = padding(plaintext)
    return plaintext ** 2 % n


# padding 16 bits to the front of a number
def padding(plaintext):
    binary_str = bin(plaintext) 
    binary_str = binary_str.replace("0b","")
    output = '1111111111111111' + binary_str
    print(output)
    return int(output, 2)       # convert back to integer


# encryption function
def decryption(a, p, q):
    n = p * q
    r, s = 0, 0
    # find sqrt
    # for p
    if p % 4 == 3:
        r = prime.sqrt_p_3_mod_4(a, p)
    elif p % 8 == 5:
        r = prime.sqrt_p_5_mod_8(a, p)
    # for q
    if q % 4 == 3:
        s = prime.sqrt_p_3_mod_4(a, q)
    elif q % 8 == 5:
        s = prime.sqrt_p_5_mod_8(a, q)

    gcd, c, d = prime.egcd(p, q)
    x = (r * d * q + s * c * p) % n
    y = (r * d * q - s * c * p) % n
    lst = [x, n - x, y, n - y]

    return lst

    """
    plaintext = choose(lst)
    string = bin(plaintext)
    string = string[15:]
    plaintext = int(string, 2)
    """
    return plaintext


# decide which answer to choose
def choose(lst):
    for i in lst:
        binary = bin(i)
        binary = binary.replace("0b","")
        print(binary)
        if binary[:15] == '1111111111111111':
            return i
    return

result = True
while True:
    str_p = hex(prime.generate_a_prime_number(128))
    str_q = hex(prime.generate_a_prime_number(128))
    plain = 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeef'
    p = int(str_p, 16)
    q = int(str_q, 16)
    plaintext = int(plain, 16)
    n = p*q
    a = encryption(plaintext, n)
    lst = decryption(a, p, q)
    result = plaintext in decryption(a, p, q)
    print(result)
              

