import concurrent.futures
import socket
import requests
import ssl
from urllib.parse import urlparse
import http.client
from ftplib import FTP

def scan_port(ip, port):
    """
    Escanea un puerto específico en una dirección IP para ver si está abierto.

    Args:
        ip (str): La dirección IP o nombre de dominio a escanear.
        port (int): El puerto a escanear.
    """
    try:
        socket.setdefaulttimeout(1)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((ip, port))
        if result == 0:
            print(f"[*] Port {port}/TCP is open on {ip}")
            check_http(ip, port)
            check_https(ip, port)
            check_ftp(ip, port)
        sock.close()
    except KeyboardInterrupt:
        print("[-] Scan aborted.")
        exit()
    except socket.gaierror:
        print(f"[-] Hostname {ip} could not be resolved.")
    except socket.error:
        print(f"[-] Couldn't connect to server on {ip}.")

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
        print(f"[*] HTTP Protocol active on port {port} of {ip}")
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
                    print(f"[*] HTTPS Protocol active on port {port} of {ip}")
                    url = urlparse(f"https://{ip}:{port}")
                    headers = requests.head(url.geturl()).headers
                    print(f"[*] Server header: {headers.get('Server')}")
    except:
        pass

def check_ftp(ip, port):
    """
    Verifica si el protocolo FTP está activo en un puerto específico.

    Args:
        ip (str): La dirección IP a verificar.
        port (int): El puerto a verificar.
    """
    try:
        ftp = FTP()
        ftp.connect(ip, port, timeout=1)
        ftp.login()
        print(f"[*] FTP Protocol active on port {port} of {ip}")
        ftp.quit()
    except:
        pass

def scan_ip_range(ip_range, start_port, end_port):
    """
    Escanea un rango de direcciones IP y puertos.

    Args:
        ip_range (list): Lista de direcciones IP a escanear.
        start_port (int): Puerto inicial del rango.
        end_port (int): Puerto final del rango.
    """
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        for ip in ip_range:
            for port in range(start_port, end_port + 1):
                executor.submit(scan_port, ip, port)

def interactive_scan():
    """
    Función interactiva para que el usuario ingrese direcciones IP o nombres de dominio y seleccione los tipos de escaneo.
    """
    ip_range = input("Enter IP addresses or domains to scan (comma separated): ").split(',')
    start_port = int(input("Enter the starting port number: "))
    end_port = int(input("Enter the ending port number: "))
    scan_ip_range(ip_range, start_port, end_port)

def main():
    """
    Función principal que solicita las direcciones IP objetivo y realiza el escaneo de puertos.
    """
    interactive_scan()

if __name__ == "__main__":
    main()
