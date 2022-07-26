import socket
import ssl

context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.load_verify_locations('../cert/cert.pem')

with socket.create_connection(('127.0.0.1', 8443)) as sock:
    with context.wrap_socket(sock, server_hostname='thegreath.ir') as ssock:
        data = input()
        ssock.write(data.encode('utf8'))
        result = ssock.read(1024)
        print(result.decode('utf8'))
        ssock.close()