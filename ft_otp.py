import time
import base64
import sys
import hashlib
import hmac
import pyotp
import qrcode
import tkinter as tk

from cryptography.fernet import Fernet
from PIL import Image, ImageTk


def get_timestamp():
    """
    Get the timestamp divided by a fixed interval.
    """
    return int(time.time() // 30)


def is_invalid(arg):
    valid_options = "gkq"
    for char in arg:
        if char not in valid_options:
            print(f"Error: Invalid option '-{char}' found.")
            sys.exit(1)


def is_valid_hex_key(content):
    """
    Check if the key is a valid hexadecimal string.
    """
    if len(content) < 64:
        print("Error: The key must be at least 64 characters long.")
        return False
    try:
        int(content, 16)
        return True
    except ValueError:
        print("Error: The key must be a valid hexadecimal string.")
        return False


def parse_key_file(arg):
    if arg.endswith(".hex"):
        try:
            with open(arg, "rb") as file:
                content = file.read()
            if is_valid_hex_key(content):
                return content
            else:
                sys.exit(1)
        except OSError:
            print("Error: Could not opent the file")
            sys.exit(1)
    else:
        print("Error: Please provide a valid .hex file.")
        sys.exit(1)


def generate_fernet_and_save():
    """
    Generate a Fernet key and save it in a file.
    """
    key = Fernet.generate_key()
    with open("keygen.key", "wb") as file:
        file.write(key)
    return key


def generate_key():
    index = 1
    if len(sys.argv) == 1 or len(sys.argv) > 3:
        print("Usage: ft_otp.py [-g] [-k keyfile]")
        sys.exit(1)
    while index < len(sys.argv):
        arg = sys.argv[index]
        if arg.startswith('-'):
            if any(char in arg for char in "gkq"):
                is_invalid(arg[1:])
                if arg == "-g":
                    if index + 1 < len(sys.argv):
                        key_file = parse_key_file(sys.argv[index + 1])
                        try:
                            # Generate a Fernet key and save it
                            key_fernet = generate_fernet_and_save()
                            f = Fernet(key_fernet)
                            encrypted_data = f.encrypt(key_file)
                            return encrypted_data
                        except ValueError:
                            print("Error: Could not convert the key to bytes.")
                            sys.exit(1)
                        return key_bytes
                    else:
                        print("Error: No file provided after -g.")
                        sys.exit(1)
            else:
                print(f"Error: No valid option '{arg}'")
                sys.exit(1)
        index += 1
    return None


def save_key(key_bytes):
    with open("ft_otp.key", "wb") as file:
        file.write(key_bytes)
        print("Key was successfully saved in ft_otp.key.")


def get_n_bytes():
    """
    Conver Unix time to time step(30 seconds)
    """
    ts = get_timestamp()
    ts_hex = hex(ts)[2:].zfill(16)
    try:
        N_bytes = bytes.fromhex(ts_hex)
    except ValueError:
        print("Error: Could not convert the timestamp to bytes.")
        sys.exit(1)
    return N_bytes


def compute_hmac(key_bytes, N_bytes):
    """
    Compute HMAC-SHA-1
    """
    hmac_result = hmac.new(key_bytes, N_bytes, hashlib.sha1).digest()

    # Dynamic truncation to get 6-digit OTP
    offset = hmac_result[-1] & 0x0F
    truncated_hash = hmac_result[offset:offset + 4]
    code = int.from_bytes(truncated_hash, 'big') & 0x7FFFFFFF
    otp = code % 10**6
    print(f"OTP: {otp:06d}")
    totp = pyotp.TOTP(base64.b32encode(key_bytes).decode())
    print(f"pyotp: {totp.now()}")


def get_key():
    """
    Get the key from the file.
    """
    try:
        with open("keygen.key", "rb") as file:
            content = file.read().strip()
        if content:
            return content
        else:
            print("Error: keygen.key is empty or not valid.")
            sys.exit(1)
    except FileNotFoundError:
        print("Error: keygen.key file not found")
        sys.exit(1)


def parse_otp_file():
    index = 1
    if len(sys.argv) == 1 or len(sys.argv) > 3:
        print("Usage: ft_otp.py [-g] [-k keyfile]")
        sys.exit(1)
    while index < len(sys.argv):
        arg = sys.argv[index]
        if arg.startswith('-'):
            if any(char in arg for char in "gkq"):
                if arg == "-k":
                    if index + 1 < len(sys.argv):
                        if sys.argv[index + 1] == "ft_otp.key":
                            try:
                                with open(sys.argv[index + 1], "rb") as file:
                                    content = file.read().strip()
                                if content:
                                    n_bytes = get_n_bytes()
                                    key_file = get_key()
                                    f = Fernet(key_file)
                                    decrypted_data = f.decrypt(content)
                                    compute_hmac(decrypted_data, n_bytes)
                                    sys.exit(0)
                                else:
                                    print("Error: ft_otp.key is empty or not valid.")
                                    sys.exit(1)
                            except FileNotFoundError:
                                print("Error: ft_otp file not found")
                                sys.exit(1)
                        else:
                            print("Error: Invalid key file.")
                            sys.exit(1)
                    else:
                        print("Error: No file provided after -k.")
                        sys.exit(1)
            else:
                print(f"Error: No valid option '{arg}'")
                sys.exit(1)
        index += 1


def show_qr_code():
    """
    Show the QR code in the terminal.
    """
    window = tk.Tk()
    window.title("OTP QR Code")

    # Open the saved QR code
    img = Image.open("qr_code.png")
    photo = ImageTk.PhotoImage(img)

    # Add the image to a label widget and pack it
    label = tk.Label(window, image=photo)
    label.image = photo
    label.pack()

    window.mainloop()


def qr_code():
    """
    Generate a QR code for the OTP key.
    """
    index = 1
    if len(sys.argv) == 1 or len(sys.argv) > 3:
        print("Usage: ft_otp.py [-g] [-k keyfile]")
        sys.exit(1)
    while index < len(sys.argv):
        arg = sys.argv[index]
        if arg.startswith('-'):
            if any(char in arg for char in "gkq"):
                if arg == "-q":
                    # Generate a random key
                    key = pyotp.random_base32()
                    totp = pyotp.TOTP(key)
                    print(f"Your secret key is: {totp.secret}")
                    # Generate a provisioning URI for the QR code
                    uri = totp.provisioning_uri(name="test", issuer_name="test")
                    # Generate the QR code
                    qr = qrcode.make(uri)
                    qr.save("qr_code.png")
                    print("QR code was successfully saved in qr_code.png.")
                    N_bytes = get_n_bytes()
                    compute_hmac(key.encode(), N_bytes)
                    show_qr_code()
                    sys.exit(0)
            else:
                print(f"Error: No valid option '{arg}'")
                sys.exit(1)
        index += 1

    sys.exit(0)


if __name__ == '__main__':
    qr_code()
    parse_otp_file()
    # Decode the key from the file
    key_bytes = generate_key()
    if key_bytes is not None:
        save_key(key_bytes)
    else:
        print("Error: No key provided.")
        sys.exit(1)
