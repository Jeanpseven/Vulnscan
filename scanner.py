import subprocess
import requests
from urllib.parse import urljoin
import ascii
import socket
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

def main():
    banner()
    print("Escolha o tipo de scan:")
    print("1. Site")
    print("2. IP Específico")
    print("3. IP na Rede Local")
    escolha = input("Opção: ")

    if escolha == '1':
        target = input("Digite o site para verificar os diretórios: ")
        diretorios = carregar_diretorios()
        verificar_diretorios(target, diretorios)
        procurar_diretorios_robots(target)
        analisar_portas_e_servicos(target)
    elif escolha == '2':
        target = input("Digite o endereço IP para verificar os diretórios: ")
        diretorios = carregar_diretorios()
        verificar_diretorios(f"http://{target}", diretorios)
        analisar_portas_e_servicos(target)
    elif escolha == '3':
        local_ip = get_local_ip()
        if local_ip:
            print("Endereço IP local encontrado:", local_ip)
            analisar_portas_e_servicos(local_ip)
        else:
            print("Não foi possível obter o endereço IP local.")
    else:
        print("Opção inválida.")

if __name__ == "__main__":
    main()
