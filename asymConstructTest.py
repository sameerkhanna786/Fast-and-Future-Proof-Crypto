import unittest
import asymConstruct
import random

class AsymConstructTest(unittest.TestCase):
    
    #tests the correctness of the algorithm if there are no parallel nodes present.
    def test_no_para_node(self):
        para = 1
        series = 2
        pub, priv = asymConstruct.create_key(series, para, 128)
        msg = hex(random.getrandbits(128))[2:].replace('0', '1')
        e = asymConstruct.encrypt(msg, pub)
        o_msg = asymConstruct.decrypt(e, priv).replace('0', '')
        self.assertEqual(msg, o_msg)
        self.assertNotEqual(msg, e)

    #tests the correctness of the algorithm if there are no series nodes present.
    def test_no_series_node(self):
        para = 2
        series = 1
        pub, priv = asymConstruct.create_key(series, para, 128)
        msg = hex(random.getrandbits(128))[2:].replace('0', '1')
        e = asymConstruct.encrypt(msg, pub)
        o_msg = asymConstruct.decrypt(e, priv).replace('0', '')
        self.assertEqual(msg, o_msg)
        self.assertNotEqual(msg, e)

    #tests the correctness of the algorithm if there are more parallel nodes than the length of the message.
    #message length = 128/16 = 8
    def test_larger_para_node(self):
        para = 10
        series = 2
        pub, priv = asymConstruct.create_key(series, para, 128)
        msg = hex(random.getrandbits(128))[2:].replace('0', '1')
        e = asymConstruct.encrypt(msg, pub)
        o_msg = asymConstruct.decrypt(e, priv).replace('0', '')
        self.assertEqual(msg, o_msg)
        self.assertNotEqual(msg, e)

    #tests the correctness of the algorithm if there are more series nodes than the length of the message.
    #message length = 128/16 = 8
    def test_larger_series_node(self):
        para = 10
        series = 2
        pub, priv = asymConstruct.create_key(series, para, 128)
        msg = hex(random.getrandbits(128))[2:].replace('0', '1')
        e = asymConstruct.encrypt(msg, pub)
        o_msg = asymConstruct.decrypt(e, priv).replace('0', '')
        self.assertEqual(msg, o_msg)
        self.assertNotEqual(msg, e)

    #tests the correctness of the algorithm if the message is extremely small.
    def test_small_message(self):
        para = 2
        series = 2
        pub, priv = asymConstruct.create_key(series, para, 128)
        msg = hex(1)[2:]
        e = asymConstruct.encrypt(msg, pub)
        o_msg = asymConstruct.decrypt(e, priv).replace('0', '')
        self.assertEqual(msg, o_msg)
        self.assertNotEqual(msg, e)

    #tests the correctness of the algorithm if the key is small.
    #note: the key sizes must be larger or equal to the message_size/para_nodes
    def test_small_key(self):
        para = 2
        series = 2
        pub, priv = asymConstruct.create_key(series, para, 6)
        msg = hex(random.getrandbits(3))[2:].replace('0', '1')
        e = asymConstruct.encrypt(msg, pub)
        o_msg = asymConstruct.decrypt(e, priv).replace('0', '')
        self.assertEqual(msg, o_msg)
        self.assertNotEqual(msg, e)

    #tests the correctness of the algorithm with random series nodes, parallel nodes, key size, and message size + values
    #tests 10 times
    def test_rand_100_runs(self):
        counter = 0
        while counter < 10:
            counter += 1
            para = random.getrandbits(4)
            if para < 1:
                para = 1
            series = random.getrandbits(4)
            if series < 1:
                series = 1
            key_size = random.getrandbits(8)
            if key_size < 2:
                key_size = 2
            pub, priv = asymConstruct.create_key(series, para, key_size)
            msg_size = random.getrandbits(8)
            while msg_size > key_size or msg_size < 1:
                msg_size = random.getrandbits(8)
            msg = hex(random.getrandbits(msg_size))[2:].replace('0', '1')
            e = asymConstruct.encrypt(msg, pub)
            o_msg = asymConstruct.decrypt(e, priv).replace('0', '')
            self.assertEqual(msg, o_msg)
            self.assertNotEqual(msg, e)
    

if __name__ == '__main__':
    unittest.main()
