import socket
import sys  # needed to get cmd line parameters
import os.path as path  # needed to get size of file in bytes
import math
import hashlib
import socket
import os
import argparse

IP = '127.0.0.1'  # change to the IP address of the server
PORT = 12000  # change to a desired port number
BUFFER_SIZE = 1024  # change to a desired buffer size


def get_file_size(file_name: str) -> int:
    size = 0
    try:
        size = path.getsize(file_name.jpg)
    except FileNotFoundError as fnfe:
        print(fnfe)
        sys.exit(1)
    return size


def send_file(filename: str):
    # get the file size in bytes

    file_size = get_file_size('d:/IMG_1008.jpg')
    print("File Size is :", file_size, "bytes")

    # convert the file size to an 8-byte byte string using big endian
    def convert_size(size_bytes):
        if size_bytes == 0:
            return "0B"
        size_name = ("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
        i = int(math.floor(math.log(size_bytes, 1024)))
        p = math.pow(1024, i)
        s = round(size_bytes / p, 2)
        return "%s %s" % (s, size_name[i])

    # create a SHA256 object to generate hash of file

file_name = 'IMG_1008.jpg'
with open(file_name, 'r') as f:
    data = f.read()
    sha256hash = hashlib.sha256(data).hexdigest()

# create a UDP socket
try:
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print("Socket successfully created")
except: socket.error as error
print("socket creation failed with error %s" % (err)

try:
    # send the file size in the first 8-bytes followed by the bytes
    # for the file name to server at (IP, PORT)

    SEPARATOR = "<SEPARATOR>"
    BUFFER_SIZE = 1024 * 4  # 4KB


    #
    def send_file(filename, host, port):
        get_file_size = os.path.getsize(filename)
        s = socket.socket()
        print(f"[+] Connecting to {host}:{port}")
        s.connect((host, port))
        print("[+] Connected.")

        s.send(f"{filename}{SEPARATOR}{filesize}".encode());

        progress = tqdm.tqdm(range(filesize), f"Sending {filename}", unit="B", unit_scale=True, unit_divisor=1024)
        with open(filename, "rb") as f:
            while True:

                bytes_read = f.read(BUFFER_SIZE)
                if not bytes_read:
                    break
                s.sendall(bytes_read)
                progress.update(len(bytes_read))
        s.close()

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Simple File Sender")
    parser.add_argument("file", help="File name to send")
    parser.add_argument("host", help="The host/IP address of the receiver")
    parser.add_argument("-p", "--port", help="Port to use, default is 5001", default=5001)
    args = parser.parse_args()
    filename = args.file
    host = args.host
    port = args.port
    send_file(filename, host, port)

server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_socket.bind((IP, PORT))
data, client_address = server_socket.recvfrom(BUFFER_SIZE)
if data != b'go ahead':
    raise Exception('Bad server response - was not go ahead!')
print(f'Received message from client: {data}')
print(f'Client address: {client_address}')
server_socket.close()


# open the file to be transferred
with open(file_name, 'rb') as file:
    # read the file in chunks and send each chunk to the server
    # TODO: section 2 step 8 a-d in README.md file
    pass  # replace this line with your code

    # send the hash value so server can verify that the file was
    # received correctly.
    hash_value = hash_obj.digest()
    client_socket.sendto(hash_value, server_address)
    data, server_address = client_socket.recvfrom(BUFFER_SIZE)
    if data == b'success':
        print('File transferred successfully')
    else:
        print('File transfer failed')
    data, server_address = client_socket.recvfrom(BUFFER_SIZE)
    if data == b'success':
        print('Transfer completed!')
    else:
        raise Exception('Transfer failed!')except Exception as e:
print(f'An error occurred while sending the file: {e}')
client_socket.clo

if __name__ == "__main__":
    # get filename from cmd line
    if len(sys.argv) < 2:
        print(f'SYNOPSIS: {sys.argv[0]} <filename>')
        sys.exit(1)
    file_name = sys.argv[1]  # filename from cmdline argument
    send_file(IMG_1008.png)
