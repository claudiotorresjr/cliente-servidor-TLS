import socket
import ssl
import sys
import time

import rsa_utils

# IP address and the port number of the server
sslServerIP = "127.0.0.1"

# Create an SSL context
context = ssl.SSLContext()
context.verify_mode = ssl.CERT_REQUIRED

# Load CA certificate with which the client will validate the server certificate
context.load_verify_locations("certificates/ca-cert.pem")

# Load client certificate
context.load_cert_chain(certfile="certificates/client-cert.pem", keyfile="certificates/client-key.pem")

# Create a client socket
clientSocket = socket.socket()

# Make the client socket suitable for secure communication
secureClientSocket = context.wrap_socket(clientSocket)
secureClientSocket.connect((sslServerIP, int(sys.argv[1])))

# Obtain the certificate from the server
server_cert = secureClientSocket.getpeercert()

# Validate whether the Certificate is indeed issued to the server
subject = dict(item[0] for item in server_cert['subject'])
commonName = subject['commonName']

if not server_cert:
    raise Exception("Unable to retrieve server certificate")
    
if commonName != '127.0.0.1':
    raise Exception("Incorrect common name in server certificate")

notAfterTimestamp = ssl.cert_time_to_seconds(server_cert['notAfter'])
notBeforeTimestamp = ssl.cert_time_to_seconds(server_cert['notBefore'])
currentTimeStamp = time.time()

if currentTimeStamp > notAfterTimestamp:
    raise Exception("Expired server certificate")
    
if currentTimeStamp < notBeforeTimestamp:
    raise Exception("Server certificate not yet active")

#encrypt message with server public key
pubkey_path = "rsakeys/serverrsa.public"
cipher_text = rsa_utils.encrypt(pubkey_path, sys.argv[2])

print(f"Securely sent '{sys.argv[2]}' to SERVER")
print(f" -> Ciphered msg is: {cipher_text}")

cipher_text = b'\xa2\xeb\xbbs\x82\xdet\xd6\xfb\x16*\x8a~\xc4U\xda\xea\xcf\x0c\n\x86\x0f0\xc1\xd5\x1b\xc3\x16P\xcdi\xb7H\xe1c\t<\xae\xb3R\x8cPV0\x8f\xf0S\xe9d\xab\x96F\x95\xf8\x18\x07m\x0fv$\x16\xc9\xd7\x82\x84\xfd\xc1\xffT\x1d\x1d\xd90\xd7\xf2lb\x05J\x99\xc7\xed\xa7A\xbcv\x0c\x84\xed%\x82\xec\x0fx\xb0\x02\xe9\\\xd8\xfa@\xbe\x945Z\x1e\x0c\x9a$^\x81\xb5z\xeb\x18\xce\x9d\x9by\xcb\x1c4\xb2\x92\xcf\x88\x9c\xde'
# Safe to proceed with the communication
secureClientSocket.send(cipher_text)

#decrypt message with server private key
privkey_path = "rsakeys/clientrsa.private"

data = secureClientSocket.recv(1024)
decripted_msg = rsa_utils.decrypt(privkey_path, data)
    
print(f"Secure communication received from server: {decripted_msg}")

# Close the sockets
secureClientSocket.close()
clientSocket.close()