#python3 client.py --server_ip 127.0.0.1 --id 123 --f C:\Users\16973\Desktop\preview.doc
#python3 client.py --server_ip 10.0.2.3 --id 1 --f /home/can201/test_5M
#dd if=/dev/zero of=test_25M bs=1M count=25
from socket import *
import json
import hashlib
import struct
import logging
import time
import argparse
import os
from tqdm import tqdm
# Operation type constants
OP_SAVE, OP_DELETE, OP_GET, OP_UPLOAD, OP_DOWNLOAD, OP_BYE, OP_LOGIN, OP_ERROR = 'SAVE', 'DELETE', 'GET', 'UPLOAD', 'DOWNLOAD', 'BYE', 'LOGIN', "ERROR"
# Data type constants
TYPE_FILE, TYPE_DATA, TYPE_AUTH, DIR_EARTH = 'FILE', 'DATA', 'AUTH', 'EARTH'
# Field name constants
FIELD_OPERATION, FIELD_DIRECTION, FIELD_TYPE, FIELD_USERNAME, FIELD_PASSWORD, FIELD_TOKEN = 'operation', 'direction', 'type', 'username', 'password', 'token'
FIELD_KEY, FIELD_SIZE, FIELD_TOTAL_BLOCK, FIELD_MD5, FIELD_BLOCK_SIZE = 'key', 'size', 'total_block', 'md5', 'block_size'
FIELD_STATUS, FIELD_STATUS_MSG, FIELD_BLOCK_INDEX = 'status', 'status_msg', 'block_index'
# Communication direction constants
DIR_REQUEST, DIR_RESPONSE = 'REQUEST', 'RESPONSE'

# Global variables
token = None  # Authentication token
logger = logging.getLogger('CLIENT')  # Logger

# Configure client logging system
def set_logger():
    logger_ = logging.getLogger('CLIENT')
    logger_.setLevel(logging.INFO)

    formatter = logging.Formatter(
        '%(asctime)s - CLIENT[%(levelname)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S')

    # Console log handler
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(formatter)

    logger_.propagate = False
    logger_.addHandler(ch)
    return logger_

# Construct network packet
def make_packet(json_data, bin_data=None):
    j = json.dumps(dict(json_data), ensure_ascii=False)
    j_len = len(j)
    if bin_data is None:
        return struct.pack('!II', j_len, 0) + j.encode()
    else:
        return struct.pack('!II', j_len, len(bin_data)) + j.encode() + bin_data

# Receive complete TCP packet from connection
def get_tcp_packet(conn):
    bin_data = b''
    # Receive 8-byte packet header
    while len(bin_data) < 8:
        data_rec = conn.recv(8)
        if data_rec == b'':
            time.sleep(0.01)
        if data_rec == b'':
            return None, None
        bin_data += data_rec
    data = bin_data[:8]
    bin_data = bin_data[8:]
    j_len, b_len = struct.unpack('!II', data)

    # Receive JSON data part
    while len(bin_data) < j_len:
        data_rec = conn.recv(j_len - len(bin_data))
        if data_rec == b'':
            time.sleep(0.01)
        if data_rec == b'':
            return None, None
        bin_data += data_rec
    j_bin = bin_data[:j_len]

    try:
        json_data = json.loads(j_bin.decode())
    except Exception as ex:
        logger.error(f"JSON parsing error: {ex}")
        return None, None

    bin_data = bin_data[j_len:]
    # Receive binary data part
    while len(bin_data) < b_len:
        data_rec = conn.recv(b_len - len(bin_data))
        if data_rec == b'':
            time.sleep(0.01)
        if data_rec == b'':
            return None, None
        bin_data += data_rec
    return json_data, bin_data

### STEP Protocol Client Class ###
class STEPClient:
    def __init__(self, server_ip, server_port):
        self.server_ip = server_ip
        self.server_port = server_port
        self.socket = None
        self.token = None
        self.username = None

    def _ensure_connected(self):
        if self.socket is None:
            raise RuntimeError('Socket is not connected')

    # Establish connection to server
    def connect(self):
        try:
            self.socket = socket(AF_INET, SOCK_STREAM)
            self.socket.connect((self.server_ip, int(self.server_port)))
            logger.info(f"Successfully connected to server {self.server_ip}:{self.server_port}")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to server: {e}")
            return False

    # Close client connection
    def close(self):
        if self.socket:
            self.socket.close()
            self.socket = None
            logger.info("Connection closed")

    # User login authentication, get access token
    def login(self, username, password):
        try:
            # Calculate password MD5 according to server requirements
            password_md5 = hashlib.md5(password.encode()).hexdigest().lower()

            # Build login request data
            login_data = {
                FIELD_OPERATION: OP_LOGIN,
                FIELD_DIRECTION: DIR_REQUEST,
                FIELD_TYPE: TYPE_AUTH,
                FIELD_USERNAME: username,
                FIELD_PASSWORD: password_md5
            }

            # Send login request packet
            packet = make_packet(login_data)
            self.socket.send(packet)

            # Wait for server response
            json_response, bin_data = get_tcp_packet(self.socket)

            if json_response is None:
                logger.error("Login failed: No response")
                return False

            # Verify login response status
            if (json_response.get(FIELD_STATUS) == 200 and
                    json_response.get(FIELD_OPERATION) == OP_LOGIN and
                    json_response.get(FIELD_TYPE) == TYPE_AUTH):

                if FIELD_TOKEN in json_response:
                    self.token = json_response[FIELD_TOKEN]
                    self.username = username
                    logger.info(f"Login successful! User: {username}")
                    logger.info(f"Obtained Token: {self.token[:20]}...")
                    return True
                else:
                    logger.error("Token not found in login response")
                    return False
            else:
                status_msg = json_response.get(FIELD_STATUS_MSG, "Unknown error")
                logger.error(f"Login failed: {status_msg}")
                return False

        except Exception as e:
            logger.error(f"Error during login process: {e}")
            return False

    # Get current session authentication token
    def get_token(self):
        return self.token

    # Test server connection (Easter egg)
    def test_connection(self):
        try:
            test_data = {
                FIELD_DIRECTION: DIR_EARTH
            }

            packet = make_packet(test_data)
            self.socket.send(packet)

            json_response, bin_data = get_tcp_packet(self.socket)

            if json_response and json_response.get(FIELD_OPERATION) == '3BODY':
                logger.info(f"Easter egg response: {json_response.get(FIELD_STATUS_MSG)}")
                return True
            return False

        except Exception as e:
            logger.error(f"Connection test failed: {e}")
            return False

    # Request upload plan (SAVE)
    def request_upload_plan(self, total_size, key=None):
        try:
            self._ensure_connected()
            if not self.token:
                raise RuntimeError('Token not set, need to login first')

            req = {
                FIELD_OPERATION: OP_SAVE,
                FIELD_DIRECTION: DIR_REQUEST,
                FIELD_TYPE: TYPE_FILE,
                FIELD_TOKEN: self.token,
                FIELD_SIZE: int(total_size)
            }
            if key:
                req[FIELD_KEY] = key

            self.socket.send(make_packet(req))
            resp, b = get_tcp_packet(self.socket)
            if resp is None:
                return False, 'No response', None
            status = resp.get(FIELD_STATUS)
            if status == 200:
                return True, 'OK', {
                    'key': resp.get(FIELD_KEY, key),
                    'block_size': resp.get(FIELD_BLOCK_SIZE),
                    'total_block': resp.get(FIELD_TOTAL_BLOCK),
                    'size': resp.get(FIELD_SIZE, total_size)
                }
            else:
                return False, resp.get(FIELD_STATUS_MSG, 'Error'), resp
        except Exception as e:
            return False, str(e), None

    # Upload single block (UPLOAD)
    def upload_block(self, key, block_index, block_bytes, block_size):
        try:
            self._ensure_connected()
            req = {
                FIELD_OPERATION: OP_UPLOAD,
                FIELD_DIRECTION: DIR_REQUEST,
                FIELD_TYPE: TYPE_FILE,
                FIELD_TOKEN: self.token,
                FIELD_KEY: key,
                FIELD_BLOCK_INDEX: int(block_index),
                FIELD_BLOCK_SIZE: int(block_size)
            }
            self.socket.send(make_packet(req, block_bytes))
            resp, b = get_tcp_packet(self.socket)
            if resp is None:
                return False, 'No response', None
            status = resp.get(FIELD_STATUS)
            if status == 200:
                return True, 'OK', resp
            else:
                return False, resp.get(FIELD_STATUS_MSG, 'Error'), resp
        except Exception as e:
            return False, str(e), None

    # Get file MD5 (GET)
    def get_server_md5(self, key):
        try:
            self._ensure_connected()
            req = {
                FIELD_OPERATION: OP_GET,
                FIELD_DIRECTION: DIR_REQUEST,
                FIELD_TYPE: TYPE_FILE,
                FIELD_TOKEN: self.token,
                FIELD_KEY: key
            }
            self.socket.send(make_packet(req))
            resp, b = get_tcp_packet(self.socket)
            if resp is None:
                return False, 'No response', None
            if resp.get(FIELD_STATUS) == 200:
                return True, 'OK', resp
            else:
                return False, resp.get(FIELD_STATUS_MSG, 'Error'), resp
        except Exception as e:
            return False, str(e), None

def calc_file_md5(file_path):
    m = hashlib.md5()
    with open(file_path, 'rb') as f:
        while True:
            chunk = f.read(2048)
            if not chunk:
                break
            m.update(chunk)
    return m.hexdigest()

### Client Main Program ###
def main():
    global logger
    logger = set_logger()

    parser = argparse.ArgumentParser()
    parser.add_argument('--server_ip', required=True, help='Server IP address')
    parser.add_argument('--id', required=True, help='Student ID, used as login username')
    parser.add_argument('--f', required=True, dest='file_path', help='File path to upload')
    args = parser.parse_args()

    server_ip = args.server_ip
    server_port = 1379
    username = args.id
    file_path = args.file_path

    if not os.path.isfile(file_path):
        logger.error('File does not exist')
        return

    client = STEPClient(server_ip, server_port)
    if not client.connect():
        return

    try:
        # Login (password is the student ID itself, calculate MD5 of student ID as required)
        if not client.login(username, username):
            logger.error('Login failed, terminating process')
            return
        token = client.get_token()
        print(f'Token: {token}')
        with open('client_token.txt', 'w') as f:
            f.write(token)

        # Request upload plan
        total_size = os.path.getsize(file_path)
        base_key = os.path.basename(file_path)
        ok, msg, plan = client.request_upload_plan(total_size, key=base_key)
        if not ok:
            # If key already exists, try with timestamp suffix
            if plan and plan.get(FIELD_STATUS) == 402:
                alt_key = f"{base_key}.{int(time.time())}"
                logger.info(f'Key already exists, trying new key: {alt_key}')
                ok, msg, plan = client.request_upload_plan(total_size, key=alt_key)
            if not ok:
                logger.error(f'Upload plan request failed: {msg}')
                return

        key = plan['key']
        block_size = int(plan['block_size'])
        total_block = int(plan['total_block'])
        logger.info(f'Upload plan: key={key}, block_size={block_size}, total_block={total_block}')

        # Block upload
        with open(file_path, 'rb') as f, tqdm(total=total_block, unit='blocks') as pbar:
            for block_index in range(total_block):
                if block_index == total_block - 1:
                    current_size = total_size - block_size * block_index
                else:
                    current_size = block_size
                f.seek(block_size * block_index)
                data = f.read(current_size)
                ok, msg, resp = client.upload_block(key, block_index, data, current_size)
                if not ok:
                    if resp and resp.get(FIELD_STATUS) == 406:
                        logger.warning('Block size mismatch, retrying this block')
                        ok2, msg2, resp2 = client.upload_block(key, block_index, data, current_size)
                        if not ok2:
                            logger.error(f'Upload failed: {msg2}')
                            return
                    else:
                        logger.error(f'Upload failed: {msg}')
                        return
                pbar.update(1)

        # Integrity check
        ok, msg, resp = client.get_server_md5(key)
        if not ok:
            logger.error(f'Failed to get server MD5: {msg}')
            return
        server_md5 = resp.get(FIELD_MD5)
        local_md5 = calc_file_md5(file_path)
        if server_md5 and server_md5.lower() == local_md5.lower():
            logger.info('MD5 verification consistent, upload complete')
        else:
            logger.error(f'MD5 mismatch, local:{local_md5}, server:{server_md5}')
            return

    except KeyboardInterrupt:
        logger.info('User interrupted operation')
    except Exception as e:
        logger.error(f'Error occurred: {e}')
    finally:
        client.close()


if __name__ == '__main__':
    main()