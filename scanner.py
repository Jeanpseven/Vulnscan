import subprocess
import requests
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
    for ip in ips:
        print(f"Escaneando IP {ip} com Nmap...")
        try:
            result = subprocess.run(["nmap", "-sV", "--script", "vuln", ip], capture_output=True, text=True)
            print(result.stdout)
        except Exception as e:
            print(f"Erro ao escanear o IP {ip}:", str(e))

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
        ips = listar_ips_na_rede()
        if ips:
            print("Lista de IPs na rede local:")
            for i, ip in enumerate(ips, start=1):
                print(f"{i}. {ip}")
        else:
            print("Não foi possível encontrar IPs na rede local.")
    elif escolha == '4':
        ips = listar_ips_na_rede()
        if ips:
            escanear_ips_na_rede(ips)
        else:
            print("Não foi possível encontrar IPs na rede local.")
    else:
        print("Opção inválida.")

if __name__ == "__main__":
    main()
