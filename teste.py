from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as Cipher_PKCS1_v1_5

with open("rsakeys/rsa.public", 'r') as f1:
    pubkey = f1.read()

msg = input("Enter String to be encrypted: ")
print("raw string->", msg)

keyPub = RSA.importKey(pubkey) # import the public key
cipher = Cipher_PKCS1_v1_5.new(keyPub)
cipher_text = cipher.encrypt(msg.encode()) # now we have the cipher
print("cipher text->", cipher_text)
