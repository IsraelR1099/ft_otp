import time
import base64
import sys
import hashlib
import hmac
from cryptography.fernet import Fernet


def get_timestamp():
    """
    Get the timestamp divided by a fixed interval.
    """
    return int(time.time() // 30)


def is_invalid(arg):
    valid_options = "gk"
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
    if arg.endswith(".txt"):
        try:
            with open(arg, "r") as file:
                content = file.read()
            if is_valid_hex_key(content):
                return content
            else:
                sys.exit(1)
        except OSError:
            print("Error: Could not opent the file")
            sys.exit(1)
    else:
        print("Error: Please provide a valid .txt file.")
        sys.exit(1)



def generate_key():
    index = 1
    if len(sys.argv) == 1 or len(sys.argv) > 3:
        print("Usage: ft_otp.py [-g] [-k keyfile]")
        sys.exit(1)
    while index < len(sys.argv):
        arg = sys.argv[index]
        if arg.startswith('-'):
            if any(char in arg for char in "gk"):
                is_invalid(arg[1:])
                if arg == "-g":
                    if index + 1 < len(sys.argv):
                        key = parse_key_file(sys.argv[index + 1])
                        try:
                            # Conthe hexadecimal key to bytes
                            key_bytes = bytes.fromhex(key)
                            key_fernet = Fernet.generate_key()
                            print(f"key fernet '{key_fernet}'")
                            cipher = Fernet(key_fernet)
                            encrypted_key = cipher.encrypt(key_bytes)
                            return encrypted_key
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
    decode_key = key_bytes.decode('utf-8')
    print(f"decoded key: '{decode_key}'")
    with open("ft_otp.key", "w") as file:
        file.write(decode_key)
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

    #Dynamic truncation to get 6-digit OTP
    offset = hmac_result[-1] & 0x0F
    truncated_hash = hmac_result[offset:offset + 4]
    code = int.from_bytes(truncated_hash, 'big') & 0x7FFFFFFF
    otp = code % 10**6
    print(f"OTP: {otp:06d}")


def parse_otp_file():
    index = 1
    if len(sys.argv) == 1 or len(sys.argv) > 3:
        print("Usage: ft_otp.py [-g] [-k keyfile]")
        sys.exit(1)
    while index < len(sys.argv):
        arg = sys.argv[index]
        if arg.startswith('-'):
            if any(char in arg for char in "gk"):
                if arg == "-k":
                    if index + 1 < len(sys.argv):
                        if sys.argv[index + 1] == "ft_otp.key":
                            try:
                                with open(sys.argv[index + 1], "r") as file:
                                    content = file.read().strip()
                                if content:
                                    print(f"content es: '{content}'")
                                    fernet_key = input("Enter the Fernet key:").encode()
                                    f = Fernet(fernet_key)
                                    key_bytes = fernet.decrypt(content)
                                    n_bytes = get_n_bytes()
                                    compute_hmac(key_bytes, n_bytes)
                                    sys.exit(0)
                                else:
                                    print(f"Error: ft_otp.key is empty or not valid.")
                                    sys.exit(1)
                            except FileNotFoundError:
                                print(f"Error: ft_otp file not found")
                                sys.exit(1)
                        else:
                            print("Error: Invalid key file.")
                            sys.exit(1)
            else:
                print(f"Error: No valid option '{arg}'")
                sys.exit(1)
        index += 1


if __name__ == '__main__':
    parse_otp_file()
    # Decode the key from the file
    key_bytes = generate_key()
    print(f"key encrypted: '{key_bytes}'")
    if key_bytes is not None:
        save_key(key_bytes)
    else:
        print("Error: No key provided.")
        sys.exit(1)
