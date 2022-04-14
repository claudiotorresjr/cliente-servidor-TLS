from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as Cipher_PKCS1_v1_5
from Crypto.Cipher import AES

def encrypt(pubkey_path, msg):
    #abre o e lê a chave pública
    with open(pubkey_path, 'r') as f1:
        pubkey = f1.read()

    keyPub = RSA.importKey(pubkey) # import the public key
    cipher = Cipher_PKCS1_v1_5.new(keyPub)
    cipher_text = cipher.encrypt(msg.encode()) # now we have the cipher
    return cipher_text


def decrypt(privkey_path, cipher_text):
    #abre e lê a chave privada
    with open(privkey_path, 'r') as f1:
        privkey = f1.read()

    keyPriv = RSA.importKey(privkey) # import the private key
    cipher = Cipher_PKCS1_v1_5.new(keyPriv)
    plaintext = cipher.decrypt(cipher_text, "ERROR")

    return plaintext