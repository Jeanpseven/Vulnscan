import subprocess
import requests
from urllib.parse import urljoin
import ascii
import netifaces

ascii.exibir_ascii_art()

def banner():
    print("===============================")
    print("      VERIFICAÇÃO DE DIRETÓRIOS")
    print("===============================")

def carregar_diretorios():
    with open("lista_diretorios.txt", "r") as file:
        diretorios = file.readlines()
        diretorios = [diretorio.strip() for diretorio in diretorios]
    return diretorios

def procurar_diretorios_robots(site):
    url_robots = urljoin(site, "robots.txt")
    response = requests.get(url_robots)

    if response.status_code == 200:
        linhas = response.text.split("\n")
        diretorios_permitidos = []
        diretorios_desautorizados = []

        for linha in linhas:
            linha = linha.strip()
            if linha.startswith("Allow:"):
                diretorio = linha.split("Allow:")[1].strip()
                diretorios_permitidos.append(diretorio)
            elif linha.startswith("Disallow:"):
                diretorio = linha.split("Disallow:")[1].strip()
                diretorios_desautorizados.append(diretorio)

        print("[+] Diretórios permitidos encontrados no robots.txt:")
        for diretorio in diretorios_permitidos:
            print(urljoin(site, diretorio))
        
        print("\n[-] Diretórios desautorizados encontrados no robots.txt:")
        for diretorio in diretorios_desautorizados:
            print(urljoin(site, diretorio))
    elif response.status_code == 404:
        print("[-] Arquivo robots.txt não encontrado.")
    else:
        print(f"[?] Erro ao acessar o arquivo robots.txt. Código de status: {response.status_code}")

def analisar_exploit_db(diretorio):
    # Implemente a pesquisa no Exploit Database aqui
    print(f"    [-] Nenhuma exploração encontrada para {diretorio}.")

def verificar_diretorios(site, diretorios):
    for diretorio in diretorios:
        url = urljoin(site, diretorio)
        response = requests.get(url)

        if response.status_code == 200:
            print(f"[+] Diretório encontrado: {url}")
            analisar_exploit_db(diretorio)
        elif response.status_code == 403:
            print(f"[-] Acesso proibido: {url}")
        elif response.status_code == 404:
            print(f"[-] Diretório não encontrado: {url}")
        else:
            print(f"[?] Código de status desconhecido ({response.status_code}): {url}")

def analisar_portas_e_servicos(target):
    print(f"\n[+] Verificando portas e serviços em {target} com Nmap:")
    try:
        command = f"nmap -sV --script vuln {target}"
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = process.communicate()

        print(output.decode())

        if error:
            print(f"[!] Ocorreu um erro ao executar o Nmap: {error.decode()}")

    except Exception as e:
        print('Erro ao verificar portas e serviços:', str(e))

def listar_ips_na_rede():
    try:
        command = "arp -a"
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = process.communicate()

        if error:
            print(f"[!] Ocorreu um erro ao listar os IPs na rede: {error.decode()}")
            return []

        ips = []
        for line in output.decode().split('\n'):
            parts = line.split()
            if len(parts) >= 2:
                ip = parts[1]
                ips.append(ip)
        
        return ips

    except Exception as e:
        print('Erro ao listar os IPs na rede:', str(e))
        return []

def escanear_ip(ip):
    diretorios = carregar_diretorios()
    verificar_diretorios(f"http://{ip}", diretorios)
    procurar_diretorios_robots(f"http://{ip}")
    analisar_portas_e_servicos(ip)

def main():
    banner()
    print("Escolha o tipo de scan:")
    print("1. Site")
    print("2. IP Específico")
    print("3. Listar IPs na Rede Local")
    print("4. Escanear Todos IPs na Rede Local")
    escolha = input("Opção: ")

    if escolha == '1':
        target = input("Digite o site para verificar os diretórios: ")
        diretorios = carregar_diretorios()
        verificar_diretorios(target, diretorios)
        procurar_diretorios_robots(target)
        analisar_portas_e_servicos(target)
    elif escolha == '2':
        target = input("Digite o endereço IP para verificar os diretórios: ")
        escanear_ip(target)
    elif escolha == '3':
        ips = listar_ips_na_rede()
        if ips:
            print("Lista de IPs na rede local:")
            for i, ip in enumerate(ips):
                print(f"{i+1}. {ip}")
            escolha_ip = input("Escolha o número do IP para escanear: ")
            try:
                escolha_ip = int(escolha_ip)
                if 1 <= escolha_ip <= len(ips):
                    escolha_ip = ips[escolha_ip - 1]
                    escanear_ip(escolha_ip)
                else:
                    print("Escolha inválida.")
            except ValueError:
                print("Escolha inválida.")
        else:
            print("Não foi possível encontrar IPs na rede local.")
    elif escolha == '4':
        ips = listar_ips_na_rede()
        if ips:
            for ip in ips:
                print(f"\n[+] Escaneando IP: {ip}")
                escanear_ip(ip)
        else:
            print("Não foi possível encontrar IPs na rede local.")
    else:
        print("Opção inválida.")

if __name__ == "__main__":
    main()
