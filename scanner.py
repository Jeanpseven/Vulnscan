import subprocess
import requests
import ascii
from urllib.parse import urljoin
import sys
import os

API_KEY = "628333AE-BaB2-F0732-77c6-f3cb4c84e51"
ZOOM_EYE_URL = "https://github.com/knownsec/ZoomEye-python/archive/refs/heads/main.zip"
ZOOM_EYE_DIR = "ZoomEye-python-main"

def verificar_root():
    return os.getuid() == 0

if not verificar_root():
    ascii.exibir_ascii_art()
    print("Este script deve ser executado como root.")
    sys.exit(1)

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

import netifaces

def listar_ips_na_rede():
    ips = []
    try:
        interfaces = netifaces.interfaces()
        for interface in interfaces:
            addresses = netifaces.ifaddresses(interface)
            if netifaces.AF_INET in addresses:
                for link in addresses[netifaces.AF_INET]:
                    ips.append(link['addr'])
    except Exception as e:
        print(f"Ocorreu um erro ao listar os IPs na rede: {str(e)}")
    return ips

def escolher_ip(ips):
    print("Lista de IPs na rede local:")
    for i, ip in enumerate(ips, start=1):
        print(f"{i}. {ip}")
    escolha = input("Escolha o número do IP para escanear: ")
    try:
        escolha = int(escolha)
        if 1 <= escolha <= len(ips):
            ip_escolhido = ips[escolha - 1]
            escanear_ip(ip_escolhido)  # Chamando a função escanear_ip() com o IP selecionado
        else:
            print("Escolha inválida.")
    except ValueError:
        print("Escolha inválida.")

def escanear_ip(ip):
    try:
        result = subprocess.run(["nmap", "-v", "-sS -Pn --open", "--script", "vuln", ip], capture_output=True, text=True)
        resultnikto = subprocess.run(["nikto", "-h", ip], capture_output=True, text=True)
        print(result.stdout)
        print(resultnikto.stdout)
    except Exception as e:
        print(f"Erro ao escanear o IP {ip}:", str(e))

def search_devices(query, ip_prefix):
    # Realiza a pesquisa de dispositivos no ZoomEye com base no prefixo do IP
    try:
        import zipfile
        import shutil

        # Baixar e extrair o módulo ZoomEye
        response = requests.get(ZOOM_EYE_URL)
        with open("ZoomEye-python-main.zip", "wb") as f:
            f.write(response.content)
        with zipfile.ZipFile("ZoomEye-python-main.zip", "r") as zip_ref:
            zip_ref.extractall(".")
        
        # Adicionar o diretório do módulo ao path
        sys.path.append(os.path.abspath(ZOOM_EYE_DIR))

        import zoomeye

        zm = zoomeye.ZoomEye(API_KEY)
        results = zm.dork_search(query, ip_prefix=ip_prefix)

        # Exibe os resultados da pesquisa
        print('--- Resultados da Pesquisa ---')
        print('Dispositivos encontrados:', results['total'])
        for i, result in enumerate(results['matches'], start=1):
            print(f"{i}. IP: {result['ip']} Portas abertas: {result['portinfo']['port']}")
        return results['matches']
    except Exception as e:
        print('Erro ao pesquisar dispositivos:', str(e))
        return []

def main():
    verificar_root()
    ascii.exibir_ascii_art()
    print("Escolha o tipo de scan:")
    print("1. Site")
    print("2. IP Específico")
    print("3. Listar IPs na Rede Local")
    print("4. Escanear Todas as Vulnerabilidades de Todos os IPs na Rede Local")
    escolha = input("Escolha a opção: ")

    if escolha == '1':
        site = input("Digite o site para verificar os diretórios: ")
        diretorios = carregar_diretorios()
        verificar_diretorios(site, diretorios)
    elif escolha == '2':
        ip = input("Digite o IP para escanear: ")
        escanear_ip(ip)
    elif escolha == '3':
        ips = listar_ips_na_rede()
        if ips:
            print("Lista de IPs na rede local:")
            for i, ip in enumerate(ips, start=1):
                print(f"{i}. {ip}")
            escolha_ip = input("Escolha o número do IP para escanear (ou pressione Enter para digitar manualmente): ")
            if escolha_ip.strip():  # Verifica se a entrada não está vazia
                try:
                    escolha_ip = int(escolha_ip)
                    if 1 <= escolha_ip <= len(ips):
                        ip_escolhido = ips[escolha_ip - 1]
                        escanear_ip(ip_escolhido)
                    else:
                        print("Escolha inválida.")
                except ValueError:
                    print("Escolha inválida.")
            else:
                ip_manual = input("Digite o IP ou alvo do host manualmente: ")
                escanear_ip(ip_manual)
        else:
            print("Não foi possível encontrar IPs na rede local.")
    elif escolha == '4':
        ips = listar_ips_na_rede()
        if ips:
            for ip in ips:
                escanear_ip(ip)
        else:
            print("Não foi possível encontrar IPs na rede local.")
    else:
        print("Opção inválida.")

if __name__ == "__main__":
    main()
