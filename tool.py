import pyotp
import base64


with open("key.txt", "r") as file:
    key = file.read().strip()

key_bytes = bytes.fromhex(key)
base32_key = base64.b32encode(key_bytes).decode('utf-8')
totp = pyotp.TOTP(base32_key)
print(totp.now())
