import socket
import ssl
import sys
import M2Crypto

sslServerIP = "127.0.0.1"

#cria um contexto SSL
context = ssl.SSLContext()
context.verify_mode = ssl.CERT_REQUIRED

# Load CA certificate with which the client will validate the server certificate
#carrega o certificado do CA que o cliente ira validar o certificado do servidor
context.load_verify_locations("certificates/ca-cert.pem")

#carrega o certificado e a chave privada do cliente
context.load_cert_chain(certfile="certificates/client-cert.pem", keyfile="certificates/client-key.pem")

#cria o socket do cliente
clientSocket = socket.socket()

#faz o socket do cliente adequado para comunicação segura
secureClientSocket = context.wrap_socket(clientSocket)
secureClientSocket.connect((sslServerIP, int(sys.argv[1])))

#pega o certificado do servidor
server_cert = secureClientSocket.getpeercert(1)

#carrea o certiicado com o M2Crypto para manipulacao
cert = M2Crypto.X509.load_cert_string(server_cert, M2Crypto.X509.FORMAT_DER)
#extrai a chave publica relacionada a esse certificado (chave publica do servidor)
server_rsa_public = cert.get_pubkey().get_rsa()

    #prepara a mensagem que sera enviada ao servidor (mensagem criptografada)
cipher_text = server_rsa_public.public_encrypt(sys.argv[2].encode(),
    M2Crypto.RSA.pkcs1_oaep_padding)

print(f"Preparando resposta para o servidor:")
print(f" -> Enviando para o servidor: '{sys.argv[2]}'")
print(f" -> Mensaem cifrada: {cipher_text}\n")

#assina a mensagem para que o servidor saiba que foi mandada realmente por esse cliente
MsgDigest = M2Crypto.EVP.MessageDigest('sha1')
MsgDigest.update(cipher_text)

print(cipher_text[2])
#assina a mensagem criptografada com a chave privada desse cliente
WriteRSA = M2Crypto.RSA.load_key("certificates/client-key.pem")
signature = WriteRSA.sign_rsassa_pss(MsgDigest.digest())
print("Assinatura gerada:")
print(f" -> {signature}")

#apos criptografar a mensagem, estamos prontos para enviar para o servidor
#envia a mensagem cifrada
secureClientSocket.send(cipher_text)
#envia a assinatura
secureClientSocket.send(signature)

#recebe o retorno do servidor, que foi uma mensagem assinada com a chave publica do cliente
data = secureClientSocket.recv(1024)
#recebe a assinatura utilizada para assinar a mensagem recebida anteriormente
#autenticando quem realmente a enviou
signature = secureClientSocket.recv(1024)

#verifica a assinatura da mensagem criptografada
MsgDigest = M2Crypto.EVP.MessageDigest('sha1')
MsgDigest.update(data)
if server_rsa_public.verify_rsassa_pss(MsgDigest.digest(), signature):
    print("Assinatura correta")
else:
    print("Assinatura incorreta!")
    exit()

#carrega a chave privada do cliente
ReadRSA = M2Crypto.RSA.load_key("certificates/client-key.pem")

#tenta descriptografar a mensagem utilizando a chave privada do cliente
#se a chave for a errada, ocorrera um erro
plain_text = ""
try:
    plain_text = ReadRSA.private_decrypt(
        data, M2Crypto.RSA.pkcs1_oaep_padding)
except:
    print("Error: Possivelmente a chave utilizada na descriptografia esta incorreta")
    exit()
    
print(f"Comunicacao segura recebida do servidor:")
print(f" -> Mensagem criptografada: '{data}'")
print(f" -> Mensagem descriptografada: '{plain_text}'\n")

#fecha a conexao com o servidor
secureClientSocket.close()
clientSocket.close()

#python client.py 15001 "testando mensagem"