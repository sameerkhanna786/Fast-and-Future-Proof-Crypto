import prime
import rsa
import random
import numpy as np
from decimal import Decimal


"""
Converts the integer into its hex form.
If the number is smaller than the intended bitlength, pad the value with zeroes in the front.

Input: the integer (num) and the desired length (bitlength)
Output: the padded hex form (out)
"""
def int_to_hex(num, bitlength):
    str = hex(num)[2:]
    while len(str)*4 < bitlength:
        str = '0' + str
    return str

"""
Takes in a list and makes all objects the same length without changing their values by padding.

Input: list of objects (lst)
Output: the padded objects concatenated together and formed into a string (out)
"""
def balance_len(lst):
    str_len = max([len(x) for x in lst])
    lst_out = []
    for i in lst:
        while len(i) < str_len:
            i = '0' + i
        lst_out.append(i)
    out = ""
    for i in lst_out:
        out = out + i
    return out

"""
Takes in the node organization, the number of series nodes and the number of parallel nodes, and returns the combined key.
The key is created by generating 128 bit prime numbers. The total number of such keys is given by series_num*para_num.

Input: Node organization (series_num, para_num) and the base key's bitlength (bitlength)
Output: The combination key (key)
"""
def create_key(series_num, para_num, bitlength = 128):
    ser_str = str(hex(series_num))[2:]
    while len(ser_str) < 4:
        ser_str = "0" + ser_str
    par_str = str(hex(para_num))[2:]
    while len(par_str) < 4:
        par_str = "0" + par_str
    public_key = ser_str + par_str
    private_key = ser_str + par_str
    for i in range(para_num):
        pub_lst = []
        priv_lst = []
        n_lst = []
        for i in range(series_num):
            pub, priv = rsa.generate_keys(bitlength)
            size = bitlength*2
            e, n = pub
            d, n = priv
            e_str = int_to_hex(e, size)
            d_str = int_to_hex(d, size)
            n_str = int_to_hex(n, size)
            pub_lst.append(e_str + n_str)
            priv_lst.append(d_str + n_str)
            n_lst.append(n)
        pub_lst = np.array(pub_lst)
        priv_lst = np.array(priv_lst)
        n_lst = np.array(n_lst)
        for i in pub_lst[n_lst.argsort()]:
            public_key = public_key + i
        for i in priv_lst[n_lst.argsort()[::-1]]:
            private_key = private_key + i    
    return public_key, private_key

"""
Takes in the combined key and extracts and returns the metadata regarding node organization.

Input: The combination key (key)
Output: Node organization (series_num, para_num)
"""
def node_nums(key):
    series_num = int(key[:4], 16)
    para_num = int(key[4:8], 16)
    return series_num, para_num

"""
Takes in a message and splits it into exactly num parts

Input: Message (msg), and the number of splits (num)
Output: List of strings containing the split segments (lst_out)
"""
def str_split(msg, num):
    lst = []
    chunk = int(len(msg)/num)
    counter = 1
    while counter < num:
        tmp = msg[:chunk]
        msg = msg[chunk:]
        lst.append(tmp)
        counter += 1
    lst.append(msg)
    str_len = max(len(x) for x in lst)
    lst_out = []
    for i in lst:
        while len(i) < str_len:
            i = '0' + i
        lst_out.append(i)
    return lst_out

"""
Takes care of the series nodes in message encryption.

Input: Message (msg), key (key), and the number of series nodes (series_num)
Output: The encrypted portion in hex form
"""
def series_encrypt(msg, key, series_num):
    key_lst = str_split(key, series_num)
    out = int(msg, 16)
    out_lst = []
    for key in key_lst:
        out_lst.append(out)
        e_str, n_str = str_split(key, 2)
        e = int(e_str, 16)
        n = int(n_str, 16)
        out = rsa.encrypt((e, n), out)
    out_lst.append(out)
    return int_to_hex(out, 128)

"""
Takes care of the series nodes in message decryption.

Input: Ciphertext (ciph), key (key), and the number of series nodes (series_num)
Output: The encrypted portion in hex form
"""
def series_decrypt(ciph, key, series_num):
    key_lst = str_split(key, series_num)
    out = int(ciph, 16)
    out_lst = []
    for key in key_lst:
        out_lst.append(out)
        e_str, n_str = str_split(key, 2)
        e = int(e_str, 16)
        n = int(n_str, 16)
        out = rsa.encrypt((e, n), out)
    out_lst.append(out)
    return int_to_hex(out, 128)

"""
Takes care of the parallel nodes in message encryption.

Input: Message (msg), and the combination key (key)
Output: The padded ciphertext
"""
def encrypt(msg, key):
    series_num, para_num = node_nums(key)
    key_rest = key[8:]
    msg_lst = str_split(msg, para_num)
    key_lst = str_split(key_rest, para_num)
    para_map = zip(msg_lst, key_lst)
    ciph_lst = []
    for a in para_map:
        ciph_lst.append(series_encrypt(a[0], a[1], series_num))
    return balance_len(ciph_lst)

"""
Takes care of the parallel nodes in message decryption.

Input: Ciphertext (ciph), and the combination key (key)
Output: The padded message
"""
def decrypt(ciph, key):
    series_num, para_num = node_nums(key)
    key_rest = key[8:]
    ciph_lst = str_split(ciph, para_num)
    key_lst = str_split(key_rest, para_num)
    para_map = zip(ciph_lst, key_lst)
    out = ""
    for a in para_map:
        out = out + series_encrypt(a[0], a[1], series_num)
    return out

"""
#CORRECTNESS TESTING SCHEME
key_size = 128
msg_size = 128
num_iter = 1000000
result = True
counter = 0
while result and counter < num_iter:
    series = random.getrandbits(3)
    para = random.getrandbits(3)
    if series == 0:
        series = 1
    if para == 0:
        para = 1
    pub, priv = create_key(series, para, key_size)
    msg = hex(random.getrandbits(msg_size))[2:].replace('0', '1')
    e = encrypt(msg, pub)
    o_msg = decrypt(e, priv).replace('0', '')
    result = msg == o_msg and msg != e
    if not result:
        print(msg, o_msg)
    counter += 1
if result:
    print("TEST SUCCESSFUL!")
else:
    print("TEST FAILED")
"""

"""
#SPEED TESTING SCHEME
import time

key_size = 256
while key_size <= 16384:
    num_units = key_size/128
    series = int(num_units/2)
    para = int(num_units/series)
    if series == 0:
        series = 1
    if para == 0:
        para = 1
    start_time = time.time()
    plain_size = 128
    pub, priv = create_key(series, para, 128)
    msg = hex(random.getrandbits(128))[2:].replace('0', '1')
    e = encrypt(msg, pub)
    o_msg = decrypt(e, priv).replace('0', '')
    result = msg == o_msg and msg != e
    print("Time it took to create keys, encrypt, and then decrypt " + str(plain_size) + " bits using " + str(key_size) + " bit keys: ", time.time() - start_time)
    key_size *= 2
"""


    

