# Example SSL server program that listens at port 15001
import ssl
import sys
import socket
import datetime
import time

import rsa_utils


ip_address = "127.0.0.1"

# Create a server socket 
serverSocket = socket.socket()
serverSocket.bind((ip_address, int(sys.argv[1])))

# Listen for incoming connections
serverSocket.listen()
print("Server listening:")

while(True):
    # Keep accepting connections from clients
    (clientConnection, clientAddress) = serverSocket.accept()
    
    # Make the socket connection to the clients secure through SSLSocket
    secureClientSocket = ssl.wrap_socket(clientConnection, 
                                        server_side=True, 
                                        ca_certs="certificates/ca-cert.pem", 
                                        certfile="certificates/server-cert.pem",
                                        keyfile="certificates/server-key.pem",
                                        cert_reqs=ssl.CERT_REQUIRED,
                                        ssl_version=ssl.PROTOCOL_TLSv1_2)

    # Get certificate from the client
    client_cert = secureClientSocket.getpeercert()
    
    clt_subject = dict(item[0] for item in client_cert['subject'])
    clt_commonName = clt_subject['commonName']

    # Check the client certificate bears the expected name as per server's policy
    if not client_cert:
        raise Exception("Unable to get the certificate from the client")
        
    if clt_commonName != "127.0.0.1":
        raise Exception("Incorrect common name in client certificate")

    # Check time validity of the client certificate
    t1  = ssl.cert_time_to_seconds(client_cert['notBefore'])
    t2  = ssl.cert_time_to_seconds(client_cert['notAfter'])
    ts  = time.time()

    if ts < t1:
        raise Exception("Client certificate not yet active")
        
    if ts > t2:
        raise Exception("Expired client certificate")

    #decrypt message with server private key
    privkey_path = "rsakeys/serverrsa.private"
    data = secureClientSocket.recv(1024)
    decripted_msg = rsa_utils.decrypt(privkey_path, data)

    print(f"Secure communication received from client: {decripted_msg}")

    # Send current server time to the client
    # serverTimeNow = "%s"%datetime.datetime.now()
    # secureClientSocket.send(serverTimeNow.encode())

    #encrypt message with client public key
    pubkey_path = "rsakeys/clientrsa.public"
    msg = "bem vindo ao servidor :D"
    cipher_text = rsa_utils.encrypt(pubkey_path, msg)
    secureClientSocket.send(cipher_text)

    print(f"Securely sent {msg} to CLIENT")
    print(f" -> Ciphered msg is: {cipher_text}")

    # Close the connection to the client
    secureClientSocket.close()