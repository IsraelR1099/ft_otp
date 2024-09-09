import time
import sys


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


def parse_key_file(arg):
    if arg.endswith(".txt"):
        print("valid file")
        try:
            file = open(arg, "r")
            print(file.read)
            file.close()
        except OSError:
            print("Error: Could not opent the file")
            sys.exit(1)
    else:
        print("Error: Please provide a valid .txt file.")
        sys.exit(1)


def generate_key():
    index = 1
    if len(sys.argv) == 1 or len(sys.argv) > 3:
        print("Error: Not valid usage.")
        sys.exit(1)
    while index < len(sys.argv):
        arg = sys.argv[index]
        if arg.startswith('-'):
            if any(char in arg for char in "gk"):
                is_invalid(arg[1:])
                if arg == "-g":
                    if index + 1 < len(sys.argv):
                        parse_key_file(sys.argv[index + 1])
                    else:
                        print("Error: No file provided after -g.")
                        sys.exit(1)
                if arg == "-k":
                    if index + 1 < len(sys.argv):
                        print_token(sys.argv[index])
                    else:
                        print("Error: No .key file provided after -k.")
                        sys.exit(1)
            else:
                print(f"Error: No valid option '{arg}'")
                sys.exit(1)
        index += 1


if __name__ == '__main__':
    ts = get_timestamp()
    ts_hex = hex(ts)[2:].zfill(16)
    N_bytes = bytes.fromhex(ts_hex)
    generate_key()
    print(ts)
    print(ts_hex)
    print(N_bytes)
