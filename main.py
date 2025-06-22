import sys, os
import hmac
import hashlib
import qrcode
import base64
import struct
from Crypto.Cipher import AES
from datetime import datetime

# os.urandom(16)
IV = b''
# os.urandom(32)
KEY = b''
USAGE ='''\
-------------------------------------------------------------------------------------------------
USAGE: ./ft_otp [-g] [-k] FILENAME
-------------------------------------------------------------------------------------------------
Option:
 • -g         : Accepts a hexadecimal key (at least 64 characters long) and stores the 
                encrypted key in a file named "ft_otp.key".
 • -k         : Generates a temporary password based on the provided key given as argument.
 
Additional Notes:
 • The hexadecimal key used with the "-g" option must be at least 64 characters in length.
 • Ensure that the key is valid and properly formatted in hexadecimal before usage.
 -------------------------------------------------------------------------------------------------
'''

def main() -> int:
    try:
        if len(sys.argv) == 3 and sys.argv[1] == "-g":
            with open(sys.argv[2], 'r') as file:
                hexadecimal_key = file.read()
            if not is_hexadecimal(hexadecimal_key):
                return error("Key must conation at least 64 hexadecimal characters.", 1)
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
    otp_uri = f"otpauth://totp/cybersecurity-piscine?secret={base32_key}&issuer=ft_otp"
    img = qrcode.make(otp_uri)
    img.show()
    img.save("otp_qr.png")
    return None


def hotp_algorithm(key):
    binary_key = bytes.fromhex(key.decode('utf-8'))
    print(binary_key)
    print(key)
    time = datetime.now().timestamp()
    time_bytes = struct.pack(">Q", int(time // 30))
    hmac_result = hmac.new(binary_key, time_bytes, hashlib.sha1).digest()
    offset = hmac_result[-1] & 0x0F
    code = hmac_result[offset:offset+4]
    binary_code = struct.unpack(">I", code)[0] & 0x7FFFFFFF
    otp = binary_code % (10 ** 6)
    return str(otp).zfill(6)

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