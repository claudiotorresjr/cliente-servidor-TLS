import ssl
import sys
import socket
import M2Crypto

ip_address = "127.0.0.1"

#cria o socket para o servidor
serverSocket = socket.socket()
serverSocket.bind((ip_address, int(sys.argv[1])))

#esperar por conexoes
serverSocket.listen()
print("Servidor esperando conexoes...")

while(True):
    #fica esperando conexoes do cliente
    (clientConnection, clientAddress) = serverSocket.accept()

    #faz a conexao segura entre o socket e o cliente por meio do SSLSocket
    #utiliza:
    #o certificado do CA que emitiou o certificado do servidor
    #o certificado do servidor
    #cave privada do servidor
    secureClientSocket = ssl.wrap_socket(clientConnection, 
                                        server_side=True, 
                                        ca_certs="certificates/ca-cert.pem", 
                                        certfile="certificates/server-cert.pem",
                                        keyfile="certificates/server-key.pem",
                                        cert_reqs=ssl.CERT_REQUIRED,
                                        ssl_version=ssl.PROTOCOL_TLSv1_2)

    #pega o certificado do cliente conectado
    client_cert = secureClientSocket.getpeercert(1)

    #carrea o certiicado com o M2Crypto para manipulacao
    cert = M2Crypto.X509.load_cert_string(client_cert, M2Crypto.X509.FORMAT_DER)
    #extrai a chave publica relacionada a esse certificado (chave publica do cliente)
    client_rsa_public = cert.get_pubkey().get_rsa()

    #recebe a mensagem do cliente
    data = secureClientSocket.recv(1024)

    #recebe a assinatura utilizada para assinar a mensagem recebida anteriormente
    #autenticando quem realmente a enviou
    signature = secureClientSocket.recv(1024)

    #verifica a assinatura da mensagem criptografada
    MsgDigest = M2Crypto.EVP.MessageDigest('sha256')
    MsgDigest.update(data)
    if client_rsa_public.verify_rsassa_pss(MsgDigest.digest(), signature):
        print("Assinatura correta")
    else:
        print("Assinatura incorreta!")
        continue
    
    #carrega a chave privada do servidor
    ReadRSA = M2Crypto.RSA.load_key("certificates/server-key.pem")

    #tenta descriptografar a mensagem utilizando a chave privada do servidor
    #se a chave for a errada, ocorrera um erro
    plain_text = ""
    try:
        plain_text = ReadRSA.private_decrypt(
            data, M2Crypto.RSA.pkcs1_oaep_padding)
    except:
        print("Error: Possivelmente a chave utilizada na descriptografia esta incorreta")
        continue

    print(f"Comunicacao segura recebida do cliente:")
    print(f" -> Mensagem criptografada: '{data}'")
    print(f" -> Mensagem descriptografada: '{plain_text}'\n")

    msg = "bem vindo ao servidor :D"
    #prepara a mensagem que sera enviada ao cliente (mensagem criptografada)
    cipher_text = client_rsa_public.public_encrypt(msg.encode(),
    M2Crypto.RSA.pkcs1_oaep_padding)

    print(f"Preparando resposta para o cliente:")
    print(f" -> Enviando para o cliente: '{msg}'")
    print(f" -> Mensaem cifrada: {cipher_text}")

    #assina a mensagem para que o cliente saiba que foi mandada realmente por esse servidor
    MsgDigest = M2Crypto.EVP.MessageDigest('sha1')
    MsgDigest.update(cipher_text)

    #assina a mensagem criptografada com a chave privada desse servidor
    WriteRSA = M2Crypto.RSA.load_key("certificates/server-key.pem")
    signature = WriteRSA.sign_rsassa_pss(MsgDigest.digest())
    print("Assinatura gerada:")
    print(f" -> {signature}")

    #apos criptografar a mensagem, estamos prontos para enviar para o cliente
    #envia a mensagem cifrada
    secureClientSocket.send(cipher_text)
    #envia a assinatura
    secureClientSocket.send(signature)

    #fecha a conexao com o cliente
    secureClientSocket.close()

    print("-"*20)

    #python server.py 15001