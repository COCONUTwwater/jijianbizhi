"""
coding:utf-8
@Software:PyCharm
@Time:2023/1/27 14:13
@Author:椰子汁
"""
import base64
import io
import json
from binascii import b2a_hex, a2b_hex

import ddddocr
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from PIL import Image


def get_token_secretkey():
    '''
    保存图片并获取token，secretKey
    :return: token,secretKey
    '''
    url = "https://api.zzzmh.cn/captcha/get"

    payload = "{\"captchaType\":\"blockPuzzle\",\"clientUid\":null,\"ts\":1674799664542}"
    headers = {
        'authority': 'api.zzzmh.cn',
        'accept': 'application/json, text/plain, */*',
        'accept-language': 'zh-CN,zh;q=0.9,zh-TW;q=0.8',
        'cache-control': 'no-cache',
        'content-type': 'application/json; charset=UTF-8',
        'origin': 'https://bz.zzzmh.cn',
        'pragma': 'no-cache',
        'referer': 'https://bz.zzzmh.cn/',
        'sec-ch-ua': '"Not_A Brand";v="99", "Google Chrome";v="109", "Chromium";v="109"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-site',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36',
        'x-requested-with': 'XMLHttpRequest'
    }

    response = requests.request("POST", url, headers=headers, data=payload)

    # 获取滑块请求中的信息
    res = json.loads(response.text)
    small_img = res['repData']['jigsawImageBase64']
    big_img = res['repData']['originalImageBase64']
    secretKey = res['repData']['secretKey']
    token = res['repData']['token']

    # 保存图片
    # 转二进制
    big_img = base64.b64decode(big_img)
    small_img = base64.b64decode(small_img)

    # 二进制字符串写入图片文件
    bigimg = Image.open(io.BytesIO(small_img))
    bigimg.save("small.png")
    smallimg = Image.open(io.BytesIO(big_img))
    smallimg.save("big.png")

    return token, secretKey


# 获取滑块距离
def get_cx():
    det = ddddocr.DdddOcr(det=False, ocr=False, show_ad=False)

    with open(r'big.png', 'rb') as f:
        target_bytes = f.read()

    with open(r'small.png', 'rb') as f:
        background_bytes = f.read()

    res = det.slide_match(target_bytes, background_bytes, simple_target=True)
    return res['target'][0]


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


def pass_captcha(pointJson, token):
    url = "https://api.zzzmh.cn/captcha/check"

    payload = "{\"captchaType\":\"blockPuzzle\",\"pointJson\":\"" + pointJson + "\",\"token\":\"" + token + "\"}"
    headers = {
        'authority': 'api.zzzmh.cn',
        'accept': 'application/json, text/plain, */*',
        'accept-language': 'zh-CN,zh;q=0.9,zh-TW;q=0.8',
        'cache-control': 'no-cache',
        'content-type': 'application/json; charset=UTF-8',
        'origin': 'https://bz.zzzmh.cn',
        'pragma': 'no-cache',
        'referer': 'https://bz.zzzmh.cn/',
        'sec-ch-ua': '"Not_A Brand";v="99", "Google Chrome";v="109", "Chromium";v="109"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-site',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36',
        'x-requested-with': 'XMLHttpRequest'
    }

    response = requests.request("POST", url, headers=headers, data=payload)

    print(response.text)


def run():
    token, secretKey = get_token_secretkey()
    x = get_cx()
    print(x)
    text = '{"x":' + str(x) + ',"y":5}'
    pointJson = AesUtil().aes_encrypt_text(text, secretKey, model='ECB')
    pass_captcha(pointJson, token)


if __name__ == '__main__':
    run()
