import prime
import xor_crypt
import random

def int_to_hex(num, bitlength):
    str = hex(num)[2:]
    while len(str)*4 < bitlength:
        str = '0' + str
    return str

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

def create_key(series_num, para_num):
    num_nodes = series_num*para_num
    ser_str = str(hex(series_num))[2:]
    while len(ser_str) < 4:
        ser_str = "0" + ser_str
    par_str = str(hex(para_num))[2:]
    while len(par_str) < 4:
        par_str = "0" + par_str
    key = ser_str + par_str
    for i in range(num_nodes):
        key = key + str(hex(prime.generate_a_prime_number(128)))[2:]
    return key

def node_nums(key):
    series_num = int(key[:4], 16)
    para_num = int(key[4:8], 16)
    return series_num, para_num

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

def series_encrypt(msg, key, series_num):
    key_lst = str_split(key, series_num)
    out = int(msg, 16)
    for key in key_lst:
        k = int(key, 16)
        out = xor_crypt.encrypt(out, k)
    return int_to_hex(out, 128)

def series_decrypt(ciph, key, series_num):
    key_lst = str_split(key, series_num)
    out = int(ciph, 16)
    for key in key_lst:
        k = int(key, 16)
        out = xor_crypt.decrypt(out, k)
    return int_to_hex(out, 128)

def encrypt(msg, key):
    series_num, para_num = node_nums(key)
    #msg = '1'*(len(msg)%para_num) + msg
    key_rest = key[8:]
    msg_lst = str_split(msg, para_num)
    key_lst = str_split(key_rest, para_num)
    para_map = zip(msg_lst, key_lst)
    ciph_lst = []
    for a in para_map:
        ciph_lst.append(series_encrypt(a[0], a[1], series_num))
    return balance_len(ciph_lst)

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

result = True
counter = 0
while result:
    series = random.getrandbits(5) 
    para = random.getrandbits(5)
    if series == 0:
        series = 1
    if para == 0:
        para = 1
    k = create_key(series, para)
    msg = hex(random.getrandbits(1024))[2:].replace('0', '1')
    e = encrypt(msg, k)
    o_msg = decrypt(e, k).replace('0', '')
    result = msg == o_msg and msg != e
    if not result:
        print(msg, o_msg)
    if counter % 1000 == 0:
        print(counter)
    counter += 1





    
