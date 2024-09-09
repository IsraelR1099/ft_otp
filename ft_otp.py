import time
import sys
import hashlib
import hmac


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
        print("valid file")
        try:
            with open(arg, "r") as file:
                content = file.read()
            if is_valid_hex_key(content):
                return content
        except OSError:
            print("Error: Could not opent the file")
            sys.exit(1)
    else:
        print("Error: Please provide a valid .txt file.")
        sys.exit(1)


"""
if arg == "-k":
                    if index + 1 < len(sys.argv):
                        print_token(sys.argv[index])
                    else:
                        print("Error: No .key file provided after -k.")
                        sys.exit(1)
"""


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
                            return key_bytes
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


if __name__ == '__main__':
    # Conver Unix time to time step(30 seconds)
    ts = get_timestamp()
    ts_hex = hex(ts)[2:].zfill(16)
    N_bytes = bytes.fromhex(ts_hex)
    print(ts)
    print(ts_hex)
    print(N_bytes)
    # Decode the key from the file
    key_bytes = generate_key()
    print(f"key: {key_bytes}")
    # Compute HMAC-SHA-1
    hmac = hmac.new(key_bytes, N_bytes, hashlib.sha1).digest()
    print(f"hmac: {hmac}")
