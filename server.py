
import socket
import rsa
from rsa.key import *
import random
import pyAesCrypt
import hashlib


class Server:
    def __init__(self, port):
        # get the hostname
        host = socket.gethostname()
        self.server_socket = socket.socket()  # get instance
        # look closely. The bind() function takes tuple as argument
        # bind host address and port together
        self.server_socket.bind((host, port))
        self.conn = None

    def waitForConnection(self):
        # configure how many client the server can listen simultaneously
        self.server_socket.listen(2)
        self.conn, address = self.server_socket.accept()  # accept new connection
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
        # Send actual length ahead of data, with fixed byteorder and size
        self.conn.sendall(len(raw).to_bytes(8, 'big'))
        self.conn.send(raw)  # send data to the client

    def generateKeys(self):
        return rsa.newkeys(512)

    def close(self):
        if not self.conn == None:
            self.conn.close()  # close the connection
        else:
            raise Exception(
                "Erreur: la connection a été fermée avant d'être instanciée.")

def sumfile(filePath):
    fileObj = open(filePath, 'rb')
    m = hashlib.md5()
    while True:
        d = fileObj.read(8096)
        if not d:
            break
        m.update(d)
    return m.hexdigest()


if __name__ == '__main__':
    server = Server(5000)
    # generation des clées public et private
    (publicKeyS, privKeyS) = server.generateKeys()
    # print(privKeyS)
    # print(publicKeyS)
    # declaration de E et N
    (publicKeySE, publicKeySN) = str(publicKeyS.e), str(publicKeyS.n)

    server.waitForConnection()
    # reception des clées publique client
    publicKeyCE = server.receiveMessage()
    publicKeyCN = server.receiveMessage()
    # envoi du E de la clée publique
    server.sendMessage(msg=publicKeySE)
    # envoi du N de la clée publique
    server.sendMessage(msg=publicKeySN)
    pubKeyC = PublicKey(int(publicKeyCN), int(publicKeyCE))
    # génération de la clée AES
    AES = str(random.randint(1, 1000000000000000000))
    AES_asbyes = str.encode(AES)
    # cryptage de la clée AES avec la clée publique du client
    aes_encrypt = rsa.encrypt(AES_asbyes, pubKeyC)
    # sending AES key
    server.sendMessage(str(aes_encrypt))

    # cryptage du fichier
    pyAesCrypt.encryptFile("input/filename.txt", "input/filename.txt.aes", AES)
    # calcul du hash du fichier
    hash = sumfile("input/filename.txt.aes")

    server.sendMessage(hash)
    server.sendFile("input/filename.txt.aes")
    server.close()
