import rsa
import socket
from rsa.key import *
import pyAesCrypt
import hashlib

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

def sumfile(filePath):
    fileObj = open(filePath, 'rb')
    m = hashlib.md5()
    while True:
        d = fileObj.read(8096)
        if not d:
            break
        m.update(d)
    return m.hexdigest()

#check si le hash client = hash server si oui: decrypte si non erreur et fermeture client 
def checkHash(hashC, hashS, intAesServerKey):
    if str(hashC) == str(hashS):
        pyAesCrypt.decryptFile("output/filename.txt.aes", "output/finalfilename.txt", intAesServerKey)
    else:
        print("mauvais hash calculé.")
        client.close()

if __name__ == '__main__':
    
    client = Client(5000)
    #generation des clées public et private
    (publicKeyC, privKeyC) = client.generateKeys()
    #declaration de E et N
    (publicKeyCE, publicKeyCN) = str(publicKeyC.e), str(publicKeyC.n)

    client.connect()
    #envoi du E et N de la clée publique
    client.sendMessage(f"{publicKeyCE}:{publicKeyCN}")

    
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
    #decodage de la clée aes
    intAesServerKey = (decrpytedAesServerKey.decode())
    #reception du hash du serveur
    hashserver = client.receiveMessage()
    #reception du fichier crypté
    aesfile = client.receiveFile()
    #declaration du chemin du fichier crypté reçu
    fout = "output/filename.txt.aes"
    #save le fichier crypté dans le bon chemin
    client.saveFile(bytes=aesfile, filename=fout)
    #calcul du hash
    hashclient = sumfile("output/filename.txt.aes")
    #appel de la fonction checkhash pour comparer les deux hash pour decrypter le fichier
    checkHash(hashC=hashclient, hashS=hashserver, intAesServerKey=intAesServerKey)
    client.close()