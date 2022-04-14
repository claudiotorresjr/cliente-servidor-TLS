from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as Cipher_PKCS1_v1_5
from Crypto.Cipher import AES

def encrypt(pubkey, msg):
    keyPub = RSA.importKey(pubkey) # import the public key
    cipher = Cipher_PKCS1_v1_5.new(keyPub)
    cipher_text = cipher.encrypt(msg.encode()) # now we have the cipher
    return cipher_text


def decrypt (privkey, ciphertext):
    keyPriv = RSA.importKey(privkey) # import the private key
    cipher = Cipher_PKCS1_v1_5.new(keyPriv)
    plaintext = cipher.decrypt(cipher_text,"")
    return plaintext


#abre o e lê a chave pública
with open("rsakeys/rsa.public", 'r') as f1:
    pubkey = f1.read()

#abre e lê a chave privada
with open("rsakeys/rsa.private", 'r') as f1:
    privkey = f1.read()

msg = input("Enter String to be encrypted: ")

cipher_text = encrypt(pubkey,msg)
print("cipher text->", cipher_text)
plaintext = decrypt(privkey, cipher_text)
print("Real text->", plaintext.decode())
