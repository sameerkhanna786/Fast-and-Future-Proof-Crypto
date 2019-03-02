import prime
import rsa
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

def create_key(series_num, para_num, bitlength):
    num_nodes = series_num*para_num
    ser_str = str(hex(series_num))[2:]
    while len(ser_str) < 4:
        ser_str = "0" + ser_str
    par_str = str(hex(para_num))[2:]
    while len(par_str) < 4:
        par_str = "0" + par_str
    public_key = ser_str + par_str
    private_key = ser_str + par_str
    for i in range(num_nodes):
        pub, priv = rsa.generate_keys(bitlength)
        size = bitlength*2
        e, n = pub
        d, n = priv
        e_str = int_to_hex(e, size)
        d_str = int_to_hex(d, size)
        n_str = int_to_hex(n, size)
        public_key = public_key + e_str + n_str
        private_key = private_key + d_str + n_str
    return public_key, private_key

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
        e_str, n_str = str_split(key, 2)
        e = int(e_str, 16)
        n = int(n_str, 16)
        if n < out:
            print("ERROR: mod too low")
        out = rsa.encrypt((e, n), out)
    return int_to_hex(out, 128)

def series_decrypt(ciph, key, series_num):
    key_lst = str_split(key, series_num)
    out = int(ciph, 16)
    for key in key_lst:
        e_str, n_str = str_split(key, 2)
        e = int(e_str, 16)
        n = int(n_str, 16)
        print(n)
        out = rsa.encrypt((e, n), out)
    return int_to_hex(out, 128)

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
    series = 1 
    para = 1
    if series == 0:
        series = 1
    if para == 0:
        para = 1
    pub, priv = create_key(series, para, 128)
    msg = hex(random.getrandbits(128))[2:].replace('0', '1')
    e = encrypt(msg, pub)
    o_msg = decrypt(e, priv).replace('0', '')
    result = msg == o_msg and msg != e
    if not result:
        print(msg, o_msg)
    if counter % 100 == 0:
        print(counter)
    counter += 1





    

