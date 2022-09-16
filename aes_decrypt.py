import binascii
from os import access
from Crypto.Cipher import AES
class AESCipher:
    BLOCK_SIZE = 16

    class PKCS7Encoder():
        class InvalidBlockSizeError(Exception):
            """Raised for invalid block sizes"""
            pass

        def __init__(self, block_size=16):
            if block_size < 2 or block_size > 255:
                raise AESCipher.PKCS7Encoder.InvalidBlockSizeError('The block size must be '
                                                                   'between 2 and 255, inclusive')
            self.block_size = block_size

        def encode(self, text):
            text_length = len(text)
            amount_to_pad = self.block_size - (text_length % self.block_size)
            if amount_to_pad == 0:
                amount_to_pad = self.block_size
            pad = chr(amount_to_pad)
            return text + pad * amount_to_pad

        def decode(self, text):
            pad = text[-1]
            return text[:-pad]

    def __init__(self, key):
        self.key = key
        self.encoder = AESCipher.PKCS7Encoder(AESCipher.BLOCK_SIZE)

    def encrypt(self, raw):
        data = self.encoder.encode(raw).encode("utf-8")
        cipher = AES.new(self.key.encode("utf-8"), AES.MODE_ECB)
        return cipher.encrypt(data)

    def decrypt(self, enc):
        cipher = AES.new(self.key.encode("utf-8"), AES.MODE_ECB)
        return self.encoder.decode(cipher.decrypt(enc))
access_secret = "fa1e85fa2b91480dbcc01092427c5670"
ticket_key = "948034CB6C33E3FA5D58C78EF7227636E006A399325F9FE6634D5C6536AEDD75"
print("access_secret : "+access_secret)
print("ticket_key : "+ticket_key)
aes = AESCipher(access_secret)

ticket_key_decrypted = aes.decrypt(binascii.unhexlify(ticket_key))
print("binascii.unhexlify(ticket_key) :")
print(binascii.unhexlify(ticket_key))
print("ticket_key_decrypted : ")
print(ticket_key_decrypted)
ticket_key_decrypted = ticket_key_decrypted.decode('utf-8')
print("ticket_key_decrypted decode: "+ticket_key_decrypted)
