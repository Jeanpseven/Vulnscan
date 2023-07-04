import subprocess
import requests
from urllib.parse import urljoin
import ascii
import zoomeye
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
            analisar_exploit_db(diretorio)
        
        print("\n[-] Diretórios desautorizados encontrados no robots.txt:")
        for diretorio in diretorios_desautorizados:
            print(urljoin(site, diretorio))
            analisar_exploit_db(diretorio)
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

def analisar_portas_e_servicos(site):
    # Implemente a verificação de portas e serviços aqui

    print("    [-] Verificação de portas e serviços não implementada.")

def verificar_com_nikto(site):
    print("\n[+] Verificando com Nikto:")

    # Executar o comando do Nikto no terminal
    command = f"nikto -h {site}"
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = process.communicate()

    # Exibir a saída do Nikto
    print(output.decode())

    if error:
        print(f"[!] Ocorreu um erro ao executar o Nikto: {error.decode()}")

def get_local_ip():
    # Obtém o endereço IP local
    interfaces = netifaces.interfaces()
    for interface in interfaces:
        try:
            addresses = netifaces.ifaddresses(interface)
            ip = addresses[netifaces.AF_INET][0]['addr']
            if ip.startswith('192.168.'):
                return ip
        except KeyError:
            pass
    return None

def get_ip_prefix(ip):
    # Obtém o prefixo do endereço IP
    ip_parts = ip.split('.')
    return '.'.join(ip_parts[:3])

def search_devices(query, ip_prefix):
    # Realiza a pesquisa de dispositivos no ZoomEye com base no prefixo do IP
    try:
        zm = zoomeye.ZoomEye()
        results = zm.dork_search(query, ip_prefix=ip_prefix)

        # Exibe os resultados da pesquisa
        print('--- Resultados da Pesquisa ---')
        print('Dispositivos encontrados:', results['total'])
        for result in results['matches']:
            print('IP:', result['ip'])
            print('Portas abertas:', result['portinfo']['port'])
            print('---')
    except zoomeye.ZoomEyeException as e:
        print('Erro ao pesquisar dispositivos:', str(e))

def search_vulnerabilities(ip):
    # Realiza a pesquisa de vulnerabilidades no ZoomEye
    try:
        zm = zoomeye.ZoomEye()
        results = zm.host_search(ip)

        # Exibe os resultados da pesquisa
        print('--- Resultados da Pesquisa ---')
        print('IP:', results['ip'])
        print('Vulnerabilidades encontradas:', results['vulnerabilities'])
        print('---')
    except zoomeye.ZoomEyeException as e:
        print('Erro ao pesquisar vulnerabilidades:', str(e))

def main():
    banner()
    site = input("Digite o site para verificar os diretórios: ")
    diretorios = carregar_diretorios()

    escolha = input("Escolha a opção:\n1. Verificar dispositivos físicos\n2. Verificar hosts virtuais\n")
    if escolha == '1':
        # Verificar dispositivos físicos
        query = input("Insira a consulta de pesquisa para encontrar dispositivos: ")

        # Obter endereço IP local
        local_ip = get_local_ip()
        if local_ip:
            print("Endereço IP local encontrado:", local_ip)
        else:
            print("Não foi possível obter o endereço IP local.")

        # Obter o prefixo do endereço IP local
        ip_prefix = get_ip_prefix(local_ip) if local_ip else None

        # Realizar a pesquisa de dispositivos
        if ip_prefix:
            print('--- Pesquisando dispositivos ---')
            search_devices(query, ip_prefix)
        else:
            print('Não é possível pesquisar dispositivos sem o endereço IP local.')

        # Pesquisar vulnerabilidades para cada dispositivo encontrado
        if ip_prefix:
            print('--- Pesquisando vulnerabilidades ---')
            try:
                zm = zoomeye.ZoomEye()
                results = zm.host_search(local_ip)

                for result in results['matches']:
                    ip = result['ip']
                    print('Pesquisando vulnerabilidades para:', ip)
                    search_vulnerabilities(ip)
            except zoomeye.ZoomEyeException as e:
                print('Erro ao pesquisar vulnerabilidades:', str(e))
        else:
            print('Não é possível pesquisar vulnerabilidades sem o endereço IP local.')
    elif escolha == '2':
        # Verificar hosts virtuais
        verificar_diretorios(site, diretorios)
        procurar_diretorios_robots(site)
        analisar_portas_e_servicos(site)
        verificar_com_nikto(site)
    else:
        print("Opção inválida.")

if __name__ == "__main__":
    try:
        subprocess.check_call(["pip", "install", "requests", "zoomeye", "netifaces"])
        print("Instalação bem-sucedida dos pacotes necessários.")
    except subprocess.CalledProcessError as e:
        print("Erro ao instalar pacotes necessários:", str(e))

    main()
