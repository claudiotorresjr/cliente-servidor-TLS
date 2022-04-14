import rsa_utils

msg = input("Enter String to be encrypted: ")

pubkey_path = "rsakeys/clientrsa.public"
cipher_text = rsa_utils.encrypt(pubkey_path, msg)
print("cipher text->", cipher_text)

privkey_path = "rsakeys/clientrsa.private"
plaintext = rsa_utils.decrypt(privkey_path, cipher_text)
print("Real text->", plaintext.decode())