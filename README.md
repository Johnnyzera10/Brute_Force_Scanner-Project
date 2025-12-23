# Brute Force Scanner em Python

## Descrição do projeto
O código lê arquivos de registros de log, organiza e 'limpa' e salva os arquivos tratados. Após o tratamento dos dados identifica as requisições feitas por IPs e as contabiliza, e se passarem de um limite pré estabelecido em uma pequena janela de tempo, o programa acusa o possível ataque de **Brute Force**, além de contabilizar as requisições feitas fora da janela de tempo e acusar atividade elevada e extrema de IPs. E por último um arquivo com o **relatório de segurança** das informações é salvo.

## Objetivo do projeto
Eu desenvolvi este projeto com o intuito de aprender e estudar **análise e leitura defensiva de logs** por conta do meu interesse crescente na área de Perícia Forense. Com este projeto pude colocar a mão na massa e de fato entender como funciona uma análise de log com IPs e limite seguro de atividades, além de solidificar conhecimentos que eu já tinha e me garantir o primeiro contato com outros diversos conceitos e bibliotecas das quais nunca havia utilizado.

## Fluxo do Projeto 
O fluxo do projeto segue as seguintes etapas:

- Leitura do arquivo de log
- Tratamento e limpeza dos dados
- Extração de IPs utilizando expressões regulares (Regex)
- Contabilização de requisições por IP
- Análise das requisições com base em limite e janela de tempo
- Identificação de possíveis ataques ou atividades suspeitas
- Exibição das informações no terminal
- Geração de relatório final em arquivo de texto

## Estrutura do projeto
brute_force_scanner/
├── brute_force_scanner.py
├── README.md
├── logs/
│ ├── log_ficticio_brute_force.txt
│ └── log_requisicoes_ips.log
└── output/
└── relatorio_seguranca.txt

## Tecnologias utilizadas
- Python
- Regex
- datetime
- Manipulação de arquivos

## Como executar
1. Clone o repositório:
```bash
git clone https://https://github.com/Johnnyzera10/Brute_Force_Scanner-Project.git

2. Acesse a pasta do projeto:
cd brute_force_scanner

3. Execute o script:
python brute_force_scanner.py

## Observações
- Os arquivos de log utilizados neste projeto são fictícios e tem finalidade exclusivamente de estudos
- Este projeto faz parte do meu portifólio de estudos de cibersegurança em Python
- O projeto é de um nível básico/intermediário e está longe de ser perfeito e é passível de melhorias no futuro, como a análise dos tipos de requisições realizadas e seu potencial impacto na segurança
- E é claro que o 'Hello World' é padrão em todo início de projeto para garantir boa sorte!