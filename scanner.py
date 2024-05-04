import subprocess
import requests
import nmap
from urllib.parse import urljoin
import zoomeye

def verificar_diretorios(site, diretorios):
    for diretorio in diretorios:
        url = urljoin(site, diretorio)
        response = requests.get(url)
        if response.status_code == 200:
            print(f"[+] Diretório encontrado: {url}")
            # Você pode adicionar aqui a lógica para analisar com o ZoomEye
        elif response.status_code == 403:
            print(f"[-] Acesso proibido: {url}")
        elif response.status_code == 404:
            print(f"[-] Diretório não encontrado: {url}")
        else:
            print(f"[?] Código de status desconhecido ({response.status_code}): {url}")

def carregar_diretorios():
    with open("lista_diretorios.txt", "r") as file:
        return file.read().splitlines()

def listar_ips_na_rede():
    try:
        command = "arp -a"
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = process.communicate()

        if error:
            print(f"[!] Ocorreu um erro ao listar os IPs na rede: {error.decode()}")
            return []

        ips = []
        lines = output.decode().split("\n")
        for line in lines:
            parts = line.split()
            if len(parts) >= 2:
                ip = parts[1].strip('()')
                ips.append(ip)

        return list(set(ips))  # Remover duplicatas
    except Exception as e:
        print(f"[!] Ocorreu um erro ao listar os IPs na rede: {str(e)}")
        return []

def escanear_ips_na_rede(ips):
    scanner = nmap.PortScanner()
    for i, ip in enumerate(ips, start=1):
        print(f"{i}. {ip}")

    escolha_ip = input("Escolha o número do IP para escanear: ")
    try:
        escolha_ip = int(escolha_ip)
        if 1 <= escolha_ip <= len(ips):
            escolha_ip = ips[escolha_ip - 1]

            print(f"Escaneando IP {escolha_ip} com Nmap...")
            scanner.scan(escolha_ip, arguments='-sV --script vuln')
            print(f"Ip: {escolha_ip}")
            for host in scanner.all_hosts():
                print('Host : %s (%s)' % (host, scanner[host].hostname()))
                print('State : %s' % scanner[host].state())
                for proto in scanner[host].all_protocols():
                    print('----------')
                    print('Protocol : %s' % proto)

                    lport = scanner[host][proto].keys()
                    lport = sorted(lport)
                    for port in lport:
                        print('port : %s\tstate : %s' % (port, scanner[host][proto][port]['state']))
        else:
            print("Escolha inválida.")
    except ValueError:
        print("Escolha inválida.")

def main():
    print("Escolha o tipo de scan:")
    print("1. Site")
    print("2. IP Específico")
    print("3. Listar IPs na Rede Local")
    print("4. Escanear Todos IPs na Rede Local")
    escolha = input("Escolha a opção: ")

    if escolha == '1':
        site = input("Digite o site para verificar os diretórios: ")
        diretorios = carregar_diretorios()
        verificar_diretorios(site, diretorios)
    elif escolha == '2':
        ip = input("Digite o IP para escanear: ")
        diretorios = carregar_diretorios()
        verificar_diretorios(ip, diretorios)
    elif escolha == '3':
        # Lógica para listar IPs na rede local usando ZoomEye
        api_key = input("Digite sua chave de API do ZoomEye: ")
        try:
            zm = zoomeye.ZoomEye(api_key=api_key)
            results = zm.host_search()
            ips = [result['ip'] for result in results['matches']]
            print("Lista de IPs na rede local:")
            for i, ip in enumerate(ips, start=1):
                print(f"{i}. {ip}")
        except zoomeye.ZoomEyeException as e:
            print('Erro ao listar IPs na rede:', str(e))
    elif escolha == '4':
        # Lógica para escanear todos os IPs na rede local usando ZoomEye
        api_key = input("Digite sua chave de API do ZoomEye: ")
        try:
            zm = zoomeye.ZoomEye(api_key=api_key)
            results = zm.host_search()
            ips = [result['ip'] for result in results['matches']]
            escanear_ips_na_rede(ips)
        except zoomeye.ZoomEyeException as e:
            print('Erro ao escanear IPs na rede:', str(e))
    else:
        print("Opção inválida.")

if __name__ == "__main__":
    main()
