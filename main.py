import sys
import hmac
import hashlib
import math
import qrcode
import base64
import struct
import threading
import tkinter as tk
from tkinter import ttk
from ttkbootstrap import Style
from Crypto.Cipher import AES
from datetime import datetime

# os.urandom(16)
IV = b''
# os.urandom(32)
KEY = b''
USAGE ='''\
-------------------------------------------------------------------------------------------------
USAGE: ./ft_otp [-g] [-k] [-i] FILENAME
-------------------------------------------------------------------------------------------------
Option:
 • -g FILENAME  : Accepts a hexadecimal key (at least 64 characters long) and stores the 
                  encrypted key in a file named "ft_otp.key".
 • -k FILENAME  : Generate a temporary one-time password (OTP) using the key provided in FILENAME.
 • -i FILENAME  : Launch the graphical interface to display the OTP using the key in FILENAME.
 
Additional Notes:
 • The hexadecimal key used with the "-g" option must be at least 64 characters in length.
 • Ensure that the key is valid and properly formatted in hexadecimal before .
 -------------------------------------------------------------------------------------------------
'''

def main() -> int:
    try:
        if len(sys.argv) == 3 and sys.argv[1] == "-g":
            with open(sys.argv[2], 'rb') as file:
                bkey = file.read()
            hexadecimal_key = bkey.decode('utf-8')
            if not is_hexadecimal(hexadecimal_key):
                return error("Hexadecimal key must contain at least 64 characters.", 1)
            encrypted = key_encrypt(bkey)
            if not encrypted: return 1
            with open("ft_otp.key", 'wb') as file:
                file.write(encrypted)
            qrcode_generate(hexadecimal_key)
            print("Key was successfully saved in ft_otp.key.")
        elif len(sys.argv) == 3 and sys.argv[1] in ["-k", "-i", "--interface"]:
            with open(sys.argv[2], 'rb') as file:
                bkey = file.read()
            decrypted_key = key_decrypt(bkey)
            if sys.argv[1] == "-k":
                otp = hotp_algorithm(decrypted_key)
                print(otp)
            else:
                graphic_interface(decrypted_key)
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

def graphic_interface(key):
    def countdown():
        value = math.floor(datetime.now().timestamp() % 30)
        if value == 0:
            message.config(text=hotp_algorithm(key))
            progress.config(style="info.Striped.Horizontal.TProgressbar")
        elif value == 20:
            progress.config(style="warning.Striped.Horizontal.TProgressbar")
        elif value == 27:
            progress.config(style="danger.Striped.Horizontal.TProgressbar")
        progress.config(value=value)
        root.after(1000, countdown)

    root = tk.Tk()
    root.title("42 cybersecurity: ft_otp")
    root.config(padx="40", pady="20")
    Style(theme="darkly")
    root.resizable(False, False)
    message = ttk.Label(root, text=hotp_algorithm(key), font=('Helvetica', 62), foreground="#FFB200")
    progress = ttk.Progressbar(root, style="info.Striped.Horizontal.TProgressbar",
                               maximum=30, value=math.floor(datetime.now().timestamp() % 30), length=230)
    message.grid(column=1, row=2)
    progress.grid(column=1, row=4)
    countdown()
    root.mainloop()
    return

def error(message: str, code=None):
    print(f"[ERROR]: {message}")
    return code

if __name__ == "__main__":
    main()