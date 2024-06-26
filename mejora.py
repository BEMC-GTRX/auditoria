import concurrent.futures
import socket
import requests
import ssl
from urllib.parse import urlparse
import http.client

def scan_port(ip, port):
    """
    Escanea un puerto específico en una dirección IP para ver si está abierto.

    Args:
        ip (str): La dirección IP a escanear.
        port (int): El puerto a escanear.
    """
    try:
        socket.setdefaulttimeout(1)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((ip, port))
        if result == 0:
            print(f"[*] Port {port}/TCP is open")
            check_http(ip, port)
            check_https(ip, port)
        sock.close()
    except KeyboardInterrupt:
        print("[-] Scan aborted.")
        exit()
    except socket.gaierror:
        print("[-] Hostname could not be resolved.")
        exit()
    except socket.error:
        print("[-] Couldn't connect to server.")
        exit()

def check_http(ip, port):
    """
    Verifica si el protocolo HTTP está activo en un puerto específico.

    Args:
        ip (str): La dirección IP a verificar.
        port (int): El puerto a verificar.
    """
    try:
        conn = http.client.HTTPConnection(ip, port, timeout=1)
        conn.request("HEAD", "/")
        response = conn.getresponse()
        print(f"[*] HTTP Protocol active on port {port}")
        print(f"[*] Server header: {response.getheader('server')}")
        conn.close()
    except:
        pass

def check_https(ip, port):
    """
    Verifica si el protocolo HTTPS está activo en un puerto específico.

    Args:
        ip (str): La dirección IP a verificar.
        port (int): El puerto a verificar.
    """
    try:
        context = ssl.create_default_context()
        with socket.create_connection((ip, port)) as sock:
            with context.wrap_socket(sock, server_hostname=ip) as ssock:
                ssock.sendall(b"HEAD / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\nConnection: close\r\n\r\n")
                response = ssock.recv(1024).decode()
                if response.startswith("HTTP/1.1"):
                    print(f"[*] HTTPS Protocol active on port {port}")
                    url = urlparse(f"https://{ip}:{port}")
                    headers = requests.head(url.geturl()).headers
                    print(f"[*] Server header: {headers.get('Server')}")
    except:
        pass

def main():
    """
    Función principal que solicita la dirección IP objetivo y realiza el escaneo de puertos.
    """
    target = input("Enter target IP address: ")
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        for port in range(1, 65536):
            executor.submit(scan_port, target, port)

if __name__ == "__main__":
    main()
