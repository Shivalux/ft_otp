import sys, os
import hmac
import hashlib
import qrcode
import base64
from Crypto.Cipher import AES
from datetime import datetime

IV = b'\x89#\xf2\xb2\x98\xf6\x18\xf4\xb7Bax,8\x8c6'
KEY = b'\xc4\xe1\xa0_P\x01\x9c\xfc\xf5\xe2\xa2[\xb0\x96\xf9,\xdbv\t=\x88P\xb5\x15>S\xda\x19\x14\xa1[\x1d'
USAGE ='''\
usage
'''
def main() -> int:
    try:
        if len(sys.argv) == 3 and sys.argv[1] == "-g":
            with open(sys.argv[2], 'r') as file:
                hexadecimal_key = file.read()
            if not is_hexadecimal(hexadecimal_key):
                return error("Key must be 64 hexadecimal characters.", 1)
            with open(sys.argv[2], 'rb') as file:
                key = file.read()
            encrypted = key_encrypt(key)
            if not encrypted: return 1
            with open("ft_otp.key", 'wb') as file:
                file.write(encrypted)
            qrcode_generate(hexadecimal_key)
            print("Key was successfully saved in ft_otp.key.")
        elif len(sys.argv) == 3 and sys.argv[1] == "-k":
            with open(sys.argv[2], 'rb') as file:
                key = file.read()
            decrypted_key = key_decrypt(key)
            otp = hotp_algorithm(decrypted_key)
            print(otp)
        else:
            print(USAGE)
            return 1
    except FileNotFoundError:
        return error("File is not found.")
    except Exception as e:
        return error(e)
    return 0

def qrcode_generate(key):
    binary_key = bytes.fromhex(key)
    base32_key = base64.b32encode(binary_key).decode('utf-8').replace('=', '')
    otp_uri = f"otpauth://totp/FT_OTP?secret={base32_key}&issuer=m"
    img = qrcode.make(otp_uri)
    img.show()
    img.save("otp_qr.png")


def hotp_algorithm(key):
    time = int(datetime.now().timestamp() // 30)
    time = format(time, 'b')
    hmac_result = hmac.new(key, time.encode(), hashlib.sha1)
    hmac_result = hmac_result.digest()
    offset = hmac_result[-1] & 0x0F
    code = hmac_result[offset:offset+4]
    binary_code = int.from_bytes(code, 'big') & 0x7FFFFFFF
    otp = binary_code % (10 ** 6)
    return otp

def key_decrypt(key):
    try:
        cripher = AES.new(KEY, AES.MODE_CBC, IV)
        decrypted_key = cripher.decrypt(key)
        padding_length = decrypted_key[-1]
        if padding_length > 16 or padding_length < 1:
            raise ValueError("Invalid padding encountered.")
        decrypted_key = decrypted_key[:-padding_length]
        return decrypted_key
    except ValueError as e:
        return error(e)
    except Exception as e:
        return error(f"{e}:: occured during decryption.")

def key_encrypt(key):
    try :
        cripher = AES.new(KEY, AES.MODE_CBC, IV)
        padding_length = 16 - (len(key) % 16)
        padding = bytes([padding_length] * padding_length)
        key += padding
        return cripher.encrypt(key)
    except Exception as e:
        return error(f"{e}:: occurred during encryption.")

def is_hexadecimal(hexadecimal: str) -> bool:
    for i in hexadecimal.upper():
        if not i in "0123456789ABCDEF":
            return False
    return len(hexadecimal) >= 64

def error(message: str, code=None):
    print(f"[ERROR]: {message}")
    return code

if __name__ == "__main__":
    main()