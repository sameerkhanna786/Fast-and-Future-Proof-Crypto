import prime
import Rabin

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
        key = key + str(hex(prime.generate_a_prime_number(256)))[2:]
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
    return lst

def series_encrypt(msg, key, series_num):
    msg_lst = str_split(msg, series_num)
    key_lst = str_split(key, series_num)
    para_map = zip(msg_lst, key_lst)
    out = ""
    for a in para_map:
        msg_tmp = a[0]
        print(msg_tmp)
        key_tmp = a[1]
        lst = str_split(key_tmp, 2)
        p = int(lst[0], 16)
        q = int(lst[1], 16)
        print(lst[0], lst[1])
        n = p*q
        out_tmp = Rabin.encryption(int(msg_tmp, 16), n)
        print(out_tmp)
        print(Rabin.decryption(out_tmp, p, q))
        out = out + str(Rabin.encryption(int(msg_tmp, 16), n))
    print(out)
    return out

def series_decrypt(ciph, key, series_num):
    ciph_lst = str_split(ciph, series_num)
    key_lst = str_split(key, series_num)
    para_map = zip(ciph_lst, key_lst)
    out = ""
    for a in para_map:
        ciph_tmp = a[0]
        key_tmp = a[1]
        lst = str_split(key_tmp, 2)
        p = int(lst[0], 16)
        q = int(lst[1], 16)
        print(p, q)
        out = out + str(hex(Rabin.decryption(int(ciph_tmp, 16), p, q))[2:])
    return out

def encrypt(msg, key):
    series_num, para_num = node_nums(key)
    key_rest = key[8:]
    msg_lst = str_split(msg, para_num)
    key_lst = str_split(key_rest, para_num)
    para_map = zip(msg_lst, key_lst)
    out = ""
    for a in para_map:
        out = out + series_encrypt(a[0], a[1], series_num)
    return out

def decrypt(ciph, key):
    series_num, para_num = node_nums(key)
    key_rest = key[8:]
    ciph_lst = str_split(ciph, para_num)
    key_lst = str_split(key_rest, para_num)
    para_map = zip(ciph_lst, key_lst)
    out = ""
    for a in para_map:
        if len(a[0]) > 0:
            out = out + series_encrypt(a[0], a[1], series_num)
    return out

def add_space(string):
    string = string[::-1]
    string = ' '.join(string[i:i + 8] for i in range(0, len(string), 8))
    return string[::-1]
     
k = create_key(1, 1)
msg = 'deadfacedeafbeef'
print(int(msg, 16))
print("ENC")
ciph = encrypt(msg, k)
print("CIPH")
print(ciph)
print("DEC")
msg_temp = decrypt(ciph, k)
print("MSG")
print(msg_temp)

