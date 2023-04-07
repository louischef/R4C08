import socket
import rsa
import random
import pyAesCrypt
import hashlib
import os

INPUT_FILE = "input/filename.txt"
OUTPUT_FILE = "output/finalfilename.txt"
BUFFER_SIZE = 8096
RSA_KEY_SIZE = 512

class Server:
    def __init__(self, port):
        self.host = socket.gethostname()
        self.server_socket = socket.socket()
        self.server_socket.bind((self.host, port))
        self.conn = None

    def waitForConnection(self):
        self.server_socket.listen(2)
        self.conn, address = self.server_socket.accept()
        print("Connection from: " + str(address))

    def sendMessage(self, msg: str):
        print("Sending:", msg)
        self.conn.send(str.encode(msg))

    def receiveMessage(self):
        return self.conn.recv(1024).decode()

    def sendFile(self, filename: str):
        print("Sending:", filename)
        with open(filename, 'rb') as f:
            raw = f.read()
        self.conn.sendall(len(raw).to_bytes(8, 'big'))
        self.conn.send(raw)

    def generateKeys(self):
        return rsa.newkeys(512)

    def close(self):
        if not self.conn == None:
            self.conn.close()
        else:
            raise Exception(
                "Erreur: la connection a été fermée avant d'être instanciée.")


def sumfile(filePath):
    with open(filePath, 'rb') as fileObj:
        m = hashlib.md5()
        for d in iter(lambda: fileObj.read(8096), b""):
            m.update(d)
    return m.hexdigest()


def encrypt_file(file, key):
    pyAesCrypt.encryptFile(file, file + ".aes", key)


def get_aes_key():
    return str(random.randint(1, 1000000000000000000))


def encrypt_aes_key(aes_key, pub_key):
    aes_encrypt = rsa.encrypt(str.encode(aes_key), pub_key)
    return aes_encrypt


def handle_client(server):
    try:
        # Generate RSA key pair
        (public_key_s, private_key_s) = rsa.newkeys(RSA_KEY_SIZE)
        
        server.waitForConnection()
        # Send public key to client

        server.sendMessage(str(public_key_s.e))
        server.sendMessage(str(public_key_s.n))
        # Receive client's public key
        public_key_c_parts = server.receiveMessage().split(':')
        public_key_c = rsa.PublicKey(int(public_key_c_parts[0]), int(public_key_c_parts[1]))

        # Generate AES key
        aes_key = str(random.randint(1, 1000000000000000000))
        # Encrypt AES key with client's public key
        encrypted_aes_key = encrypt_aes_key(aes_key, public_key_c)
        print("ici?")
        server.sendMessage(str(encrypted_aes_key))
        # Encrypt input file with AES key
        encrypt_file(INPUT_FILE, aes_key)

        # Calculate hash of input file
        input_file_hash = sumfile(INPUT_FILE + ".aes")

        # Send hash to client
        server.sendMessage(input_file_hash)

        # Send encrypted input file to client
        server.sendFile(INPUT_FILE + ".aes")

        # Decrypt input file with AES key
        pyAesCrypt.decryptFile(INPUT_FILE + ".aes", OUTPUT_FILE, aes_key)

        # Close server connection
        server.close()

    except Exception as e:
        print(f"Error handling client: {e}")
        server.close()


if __name__ == '__main__':
    server = Server(5000)
    #appel de la fonction handleclient
    handle_client(server)