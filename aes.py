"""
coding:utf-8
@Software:PyCharm
@Time:2023/1/27 14:32
@Author:椰子汁
"""
import base64
from binascii import b2a_hex, a2b_hex

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


class AesUtil:

    @staticmethod
    def aes_encrypt_text(decrypt_text: str, key: str, iv="", model="CBC", method="base64") -> str:
        """
        AES加密
        :param decrypt_text: 明文
        :param key: 密钥
        :param model: 加密模式： CBC, ECB
        :param iv: 密钥偏移量，只有CBC模式有
        :param method: 用base64加密还是16进制字符串
        :return: 密文
        """
        if model == 'CBC':
            aes = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv.encode('utf-8'))
        else:
            aes = AES.new(key.encode('utf-8'), AES.MODE_ECB)
        encrypt_text = aes.encrypt(pad(decrypt_text.encode('utf-8'), AES.block_size, style='pkcs7'))
        if method == "base64":
            return base64.b64encode(encrypt_text).decode()
        else:
            return b2a_hex(encrypt_text).decode()

    @staticmethod
    def aes_decrypt_text(encrypt_text: str, key: str, iv="", model="CBC", method="base64") -> str:
        """
        AES解密
        :param encrypt_text: 密文
        :param key: 密钥
        :param model: 解密模式： CBC, ECB
        :param iv: 密钥偏移量，只有CBC模式有
        :param method: 用base64解密还是16进制字符串
        :return:解密后的数据
        """
        if model == 'CBC':
            aes = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv.encode('utf-8'))
        else:
            aes = AES.new(key.encode('utf-8'), AES.MODE_ECB)
        if method == "base64":
            decrypt_text = aes.decrypt(base64.b64decode(encrypt_text)).decode('utf8')
        else:
            decrypt_text = aes.decrypt(a2b_hex(encrypt_text)).decode('utf8')
        return decrypt_text

# text='{"x":113.66666666666667,"y":5}'
# key='MNVd7LHfdQZdRPM9'
# res=AesUtil().aes_encrypt_text(text,key,model='ECB')
# print(res)
