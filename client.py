import rsa
import socket
from rsa.key import *

class Client:
    def __init__(self, port):
        self.host = socket.gethostname()  # as both code is running on same pc
        self.port = port
        self.client_socket = socket.socket()  # instantiate
        self.bfile = None

    def connect(self):
        self.client_socket.connect((self.host, self.port))  # connect to the server

    def receiveFile(self):
        # receive the size of the file
        expected_size = b""
        while len(expected_size) < 8:
            more_size = self.client_socket.recv(8 - len(expected_size))
            if not more_size:
                raise Exception("Short file length received")
            expected_size += more_size

        # Convert to int, the expected file length
        expected_size = int.from_bytes(expected_size, 'big')

        # Until we've received the expected amount of data, keep receiving
        self.bfile = b""  # Use bytes, not str, to accumulate
        while len(self.bfile) < expected_size:
            buffer = self.client_socket.recv(expected_size - len(self.bfile))
            if not buffer:
                raise Exception("Incomplete file received")
            self.bfile += buffer
        return self.bfile

    def receiveMessage(self):
        return self.client_socket.recv(1024).decode()

    def sendMessage(self, msg: str):
        
        print("Sending:", msg)
        self.client_socket.send(str.encode(msg))

    def saveFile(self, bytes: b"", filename: str):
        with open(filename, 'wb') as f:
            f.write(self.bfile)

    def generateKeys(self):
        return rsa.newkeys(512)

    def close(self):
        if not self.client_socket == None:
            self.client_socket.close()  # close the connection
        else:
            raise Exception("Erreur: la connection a été fermée avant d'être instanciée.")

if __name__ == '__main__':
    
    client = Client(5000)
    #generation des clées public et private
    (publicKeyC, privKeyC) = client.generateKeys()
    #declaration de E et N
    (publicKeyCE, publicKeyCN) = str(publicKeyC.e), str(publicKeyC.n)

    client.connect()
    #envoi du E de la clée publique
    client.sendMessage(msg=publicKeyCE)
    #envoi du N de la clée publique
    client.sendMessage(msg=publicKeyCN)
    # f = "output/filename"
    # client.saveFile(bytes=bfile, filename=f)
    
    #reception de la clée publique 
    publicKeySE = client.receiveMessage()
    publicKeySN = client.receiveMessage()
    pubKeyS = PublicKey(int(publicKeySE), int(publicKeySN))
    #reception de la clée AES
    encrpyt_aesServerKey = client.receiveMessage()
    #conversion en bytes
    bytes_aesServer =eval(encrpyt_aesServerKey)
    #decryptage avec clée privée
    decrpytedAesServerKey = rsa.decrypt(bytes_aesServer, privKeyC)

    print(decrpytedAesServerKey)
    client.close()