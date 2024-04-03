import socket
import os
import hashlib  # needed to verify file hash


IP = '127.0.0.1'  # change to the IP address of the server
PORT = 12000  # change to a desired port number
BUFFER_SIZE = 1024  # change to a desired buffer size


def get_file_info(data: bytes) -> (str, int):
    return data[8:].decode(), int.from_bytes(data[:8],byteorder='big')


def upload_file(server_socket: socket, file_name: str, file_size: int):
    # create a SHA256 object to verify file hash
    hash_obj = hashlib.sha256()
    # create a new file to store the received data
    with open(file_name+'.temp', 'wb') as file:
        # TODO: section 1 step 7a - 7e in README.md file
        pass  # replace this line with your code for section 1 step 7a - 7e

    # get hash from client to verify
    client_hash, client_address = server_socket.recvfrom(BUFFER_SIZE)
    if server_hash == client_hash:
        print('File transfer successful. Hashes match.')
    else:
        print('File transfer failed. Hashes do not match.')

    # TODO: section 1 step 9 in README.md file


def start_server():
    # create a UDP socket and bind it to the specified IP and port
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind((IP, PORT))
    print(f'Server ready and listening on {IP}:{PORT}')

    try:
        while True:
            data, client_address = server_socket.recvfrom(BUFFER_SIZE)
            # expecting an 8-byte byte string for file size followed by file name
            # unpack the first 8 bytes of data as a big-endian long long integer to get file size
            file_size = int.from_bytes(data[:8], byteorder='big')
            file_name = data[8:].decode()
            file_size_bytes = get_file_size(file_name)
            # TODO: section 1 step 4 in README.md file
            upload_file(server_socket, file_name, file_size)
    except KeyboardInterrupt as ki:
        pass
    except Exception as e:
        print(f'An error occurred while receiving the file:str {e}')
    finally:
        server_socket.close()


if __name__ == '__main__':
    start_server()


if __name__ == '__main__':
    start_server()
