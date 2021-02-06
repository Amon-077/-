#关于crypto类库的使用方式参见：https://www.dlitz.net/software/pycrypto/api/2.6/Crypto.Cipher.AES-module.html
from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex

def add_to_16(text):
    if len(text.encode('utf-8'))%16:
        add=16-len(text.encode('utf-8'))%16
    else:
        add=0
    text=text+('\0'*add)
    return text.encode('utf-8')

def encrypt(text,key):
    key=key.encode('utf-8')
    mode=AES.MODE_CBC
    iv=b'qqqqqqqqqqqqqqqq'
    text=add_to_16(text)
    cryptos=AES.new(key,mode,iv)
    cipher_text=cryptos.encrypt(text)
    return b2a_hex(cipher_text)

def decrypt(text,key):
    key=key.encode('utf-8')
    iv=b'qqqqqqqqqqqqqqqq'
    mode=AES.MODE_CBC
    cryptos=AES.new(key,mode,iv)
    plain_text=cryptos.decrypt(a2b_hex(text))
    return bytes.decode(plain_text).rstrip('\0')

if __name__ == '__main__':
    str1="This a test message"
    e=encrypt(str1,'0123456789101112')
    d=decrypt(e,'0123456789101112')
    print("原文: ",str1)
    print("加密: ",e)
    print("解密: ",d)
