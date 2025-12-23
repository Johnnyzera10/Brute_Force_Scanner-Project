print("Hello World!\n")

#Objetivo do projeto:
#1. Ler log bruto
#2. Limpar log           → events (texto)
#3. Salvar log limpo
#4. Regex (data/hora/ip) → buscas_ordenadas
#5. datetime             → eventos
#6. Agrupar por IP
#7. Janela de tempo      → timestamp
#8. Alerta               → relatório


import re
from pathlib import Path
from collections import Counter
from datetime import datetime, timedelta
from collections import defaultdict, deque


#Caminhos dos arquivos utilizados
projeto = Path(__file__).resolve().parent
logs = projeto / "logs"
output = projeto / "output"
caminho_arquivo_log = logs / "log_ficticio_brute_force.txt"
caminho_log_clean = logs / "log_requisicoes_ips_clean.txt"
caminho_relatorio_arquivo = output / "relatorio_seguranca.txt"
logs.mkdir(exist_ok=True)
output.mkdir(exist_ok=True)

#Tratamento de possível erro ao abrir arquivo de log fictício
try:    
    with open(caminho_arquivo_log, 'r', encoding='utf-8') as arquivo:
        conteudo = arquivo.read()
except FileNotFoundError:
    print(f"Erro ao encontrar o arquivo no caminho: {caminho_arquivo_log}")
    exit()
    
else:
    print("Conteúdo do arquivo:\n")
    print(conteudo)

#Regex que identifica datas no formato do log (YYYY-MM-DD) para separar os eventos ocorridos
regex_data = r"\d{4}-\d{2}-\d{2}"
div_linhas = re.split(f"({regex_data})", conteudo)

#Criação da Lista de eventos normalizados (data + conteúdo da linha)
events = []

#Divide as linhas das datas e conteúdos
for i in range(1, len(div_linhas), 2):
    data = div_linhas[i]
    texto = div_linhas[i + 1]
    texto_limpo = " ".join(texto.split())
    events.append(f"{data} {texto_limpo}")

#Cria o arquivo limpo e tratado
with open(caminho_log_clean, "w", encoding="utf-8") as f:
    for evento in events:
        f.write(evento + "\n")

print("Arquivo limpo gerado com sucesso!\n")

print("---Conteúdo do arquivo limpo ---\n")

#Abre o arquivo tratado e exibe ele na tela
with open(caminho_log_clean, "r", encoding="utf-8") as file_clean:
    conteudo_clean = file_clean.read()
    print(f"{conteudo_clean}")


#Regex utilizados
# r'\d{1,3}[.]\d{1,3}[.]\d{1,3}[.]\d{1,3}' regex IP versão simplificada
# r'(\d{4}-\d{2}-\d{2})\s+' regex data
# r'(\d{2}:\d{2}:\d{2})' regex horário


pattern_regex_data_hora_ip_resto = r'(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})\s+(\d{1,3}[.]\d{1,3}[.]\d{1,3}[.]\d{1,3})\s+(.*)'

#Variáveis de busca de regex no arquivo tratado
buscas = re.findall(pattern_regex_data_hora_ip_resto, conteudo_clean)
buscas_ordenadas = sorted(buscas)

eventos = []

#Desempacota as tuplas e converte o texto (date/time) em timestamp (tempo real)
for data, hora, ip, resto in buscas_ordenadas:
    timestamp = datetime.strptime(
        f"{data} {hora}",
        "%Y-%m-%d %H:%M:%S"
    )
    eventos.append((timestamp, ip, resto))

#Criação de um dicionário padrão para cada requisição do IP e os timestamps
requisicoes_por_ip = defaultdict(list)

for timestamp, ip, resto in eventos:
    requisicoes_por_ip[ip].append(timestamp)

for ip in requisicoes_por_ip:
    requisicoes_por_ip[ip].sort()

#Contador de ocorrências de cada IP
ips = [ip for data, hora, ip, resto in buscas_ordenadas]
contagem_ips = Counter(ips)

print()

print(f'Total de IPs encontrados no log: {len(buscas_ordenadas)}\n')

print(f"Total de IPs únicos: {len(contagem_ips)}\n")


ips_suspeitos = []

#Criação de uma janela de tempo (limite) para as requisições de cada IP
janela = timedelta(seconds=60)
limite_suspeito = 10

#Loops que acusam IPs com requisições acima do limite suspeito dentro da janela de tempo (60s) e contabilizam o máximo de requisições feitas dentro da janela
for ip, timestamps in requisicoes_por_ip.items():
    window = deque()
    max_requisicoes = 0
    max_timestamp = None

    for ts in timestamps:
        window.append(ts)

        while window and (ts - window[0]) > janela:
            window.popleft()

        if len(window) > max_requisicoes:
            max_requisicoes = len(window)
            max_timestamp = ts

    if max_requisicoes >= limite_suspeito:
        ips_suspeitos.append((ip, max_timestamp, max_requisicoes))
        


#Criação de listas e limites de requisições de IP fora da janela 
limite_amarelo = 15
limite_vermelho = 25

ips_amarelos = []
ips_vermelhos = []

#Criação de um set para colocar os IPs já classificados como suspeitos e poder classificar demais IPs corretamente
ips_suspeitos_set = {ip for ip, timestamp, qtd in ips_suspeitos}

#Loop for que verifica se as requisições de cada IP no log fora da janela foram acima dos limites criados
for ip, qtd in contagem_ips.items():
    print("IP: ", ip, "-- Quantidade: ", qtd) 

    if ip in ips_suspeitos_set:
        continue

    if qtd >= limite_vermelho:
            ips_vermelhos.append((ip, qtd))

    elif qtd >= limite_amarelo:
                ips_amarelos.append((ip, qtd))    
    

#Exibição dos IPs suspeitos, amarelos e vermelhos em forma de lista
print("\nIPs suspeitos - Possível ataque de brute force: ")
for ip, timestamp, qtd in ips_suspeitos:
    print(f'IP: {ip} -- Requisições: {qtd} -- Data e hora da última requisição dentro de 1 min: {timestamp}\n')
if ips_amarelos:
    print("IPs com atividade elevada:")
    for ip, qtd in ips_amarelos:
        print(f'IP: {ip} -- Requisições: {qtd}\n')
else:
    print("Nenhuma atividade elevada detectada (Acima de 15 requisições no log)\n")
if ips_vermelhos:
    print("IPs com atividade extrema:")
    for ip, qtd in ips_vermelhos:
        print(f'IP: {ip} -- Requisições: {qtd}\n')
else:
    print("Nenhuma atividade extrema detectada (Acima de 25 requisições no log)")


# Resultado final:
# - ips_suspeitos: brute force em curto período
# - ips_amarelos: alto volume no log
# - ips_vermelhos: volume crítico de requisições


#Exibição dos logs geral e conteúdo de cada linha na busca
print('\n --- LOGS CAPTURADOS ---')
for data, hora, ip, linha in buscas_ordenadas:
    print(f'{data} -- {hora} | IP: {ip} | Conteúdo linha: {linha}\n')

#Criação de um arquivo documentando os resultados
with open(caminho_relatorio_arquivo, "w", encoding="utf-8") as file_relatorio:
    file_relatorio.write(f"Relatório gerado em: {datetime.now()}\n\n")
    file_relatorio.write(f"Total de IPs únicos analisados: {len(contagem_ips)}\n")
    file_relatorio.write(f"Total de requisições: {len(buscas_ordenadas)}\n\n")

    file_relatorio.write(f"IPs suspeitos: {len(ips_suspeitos)}\n")
    file_relatorio.write(f"IPs amarelos: {len(ips_amarelos)}\n")
    file_relatorio.write(f"IPs vermelhos: {len(ips_vermelhos)}\n")

#Exibição dos IPs de forma limpa usando o loop for
    if ips_suspeitos:
        file_relatorio.write('\n --- IPs suspeitos -- Possível Brute force -- Muitas requisições dentro de 1 min ---\n')
        for ip, timestamp, qtd in ips_suspeitos:
            file_relatorio.write(f'IP: {ip} -- Requisições: {qtd} -- Timestamp: {timestamp}\n')

    if ips_amarelos:
        file_relatorio.write('\n --- IPs amarelos - Atividade Elevada (acima de 15 requisições no log) ---\n')
        for ip, qtd in ips_amarelos:
            file_relatorio.write(f'IP: {ip} -- Requisições: {qtd}\n')

    if ips_vermelhos:
        file_relatorio.write('\n --- IPs vermelhos - Atividade Extrema (acima de 25 requisições no log) ---\n')
        for ip, qtd in ips_vermelhos:
            file_relatorio.write(f'IP: {ip} -- Requisições: {qtd}\n')

#Confirmação do relatório criado e salvo
print(f"Relatório salvo em: {caminho_relatorio_arquivo}")