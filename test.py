import tornado.web
from Crypto.Cipher import AES
from _md5 import md5
# from Crypto import Random


class Encryption(object):
    def __init__(self, data=None, key=None):
        self.data = data
        self.key = md5(key).digest()
        self.iv = 16 * '\x00'
        self.mode = AES.MODE_CFB

    def encrypt(self, data=None):
        if not data:
            data = self.data

        ciphered = AES.new(self.key, self.mode, self.iv).encrypt(data)
        return ciphered

    def decrypt(self, data=None):
        if not data:
            data = self.data

        de_ciphered = AES.new(self.key, self.mode, self.iv).decrypt(data)
        return de_ciphered

# enc_obj = Encryption(key=b'key')
# l = [{'html': '<div class="message" id="m6da221e6-1c77-4439-a5e5-f9436875d53a">b&#39;\\x0eT@\\xca&#39;</div>\n',
#       'body': "message",
#       'id': '6da221e6-1c77-4439-a5e5-f9436875d53a'}]
#
# for message in l:
#     message['body'] = str(enc_obj.encrypt(data=message['body']))
# print('message in MessageUpdatesHandler after enc:', l)
#
# for message in l:
#     message['body'] = enc_obj.decrypt(data=message['body'][2:-1].encode())
#
# print(l)




d = {'body': 'message', 'key': b'key'}
enc_obj = Encryption(key=b'key')
print(d)
d['body'] = str(enc_obj.encrypt(data=d['body']))
b'\\x0eT@\\xca,3\\xf0' == enc_obj.encrypt(data=d['body'])
# b'\x0eT@\xca,3\xf0'
print(d)
data = d['body'][2:-1].encode()
# data = b'\x0eT@\\xca,3\\xf0'
d['body'] = enc_obj.decrypt(data=data)
print(d)


# # e = Encryption()
# e2 = Encryption(data='enc data', key=b'234')
# print(e2.encrypt())
# # e3 = Encryption().decrypt(data=e2)
# # print(e3.decode('utf-8'))
# #
# # md5('222'.encode('utf-8')).digest()