import socket
import ssl

HOST = "127.0.0.1"
PORT = 4433

context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE

with socket.create_connection((HOST, PORT)) as sock:
    with context.wrap_socket(sock, server_hostname=HOST) as ssock:
        cert = ssock.getpeercert()
        print(cert)
        print("Connected using:", ssock.version())
        ssock.sendall(b"Hello OpenSSL server\n")
        data = ssock.recv(4096)
        print("Received:", data)


