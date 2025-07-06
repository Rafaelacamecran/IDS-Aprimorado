# Nome do projeto:
IDS Aprimorado (Detecção Rápida e Análise de Scan)

# Descrição:
É um Sistema de Detecção de Intrusão (IDS), projetado especificamente para identificar e analisar com alta velocidade e precisão as varreduras de rede, que são frequentemente a primeira etapa de um ciberataque.
As varreduras de rede, ou scans, são técnicas utilizadas por atacantes para descobrir hosts ativos, portas abertas, serviços em execução e vulnerabilidades em uma infraestrutura de TI. A detecção precoce e a análise aprofundada dessas atividades são cruciais para uma defesa proativa.

# Instalação:
Como Instalar/configurar o projeto IDS Aprimorado (Detecção Rápida e Análise de Scan)
Guia de Instalação e Uso do IDS Aprimorado (Detecção Rápida e Análise de Scan) com Nmap e Wireshark
Este guia iforma o processo completo para instalar e executar o script do Sistema de Detecção de Intrusão (IDS) em seu computador.

Passo 1: Pré-requisitos Essenciais
Antes de executar o script, você precisa garantir que os seguintes programas e componentes estejam instalados em seu sistema.
Python 3: O script foi escrito em Python. Se você não o tiver, baixe a versão mais recente em python.org.
Durante a instalação no Windows, marque a opção "Add Python to PATH".
Nmap: A ferramenta de análise de rede. É fundamental para a funcionalidade de análise do IDS.
Download: nmap.org/download.html

Instalação (Windows): Baixe o instalador.exe e siga as instruções.
É importante deixar marcada a opção de adicionar o Nmap ao PATH do sistema durante a instalação.

Instalação (Linux - Debian/Ubuntu):
sudo apt update
sudo apt install nmap

Instalação (macOS com Homebrew):
brew install nmap

Npcap (Apenas para Windows): A Scapy, biblioteca de manipulação de pacotes, precisa do Npcap para funcionar no Windows. Ele geralmente é instalado automaticamente junto com o Nmap se você usar o instalador oficial. Certifique-se de que a opção de "instalar Npcap em modo de compatibilidade com WinPcap" esteja marcada.

Wireshark: Embora o script não execute o Wireshark diretamente, ele gera filtros que você pode usar no programa para uma análise manual mais profunda.
Download: www.wireshark.org/download.html

Passo 2: Instalação das Bibliotecas Python
Com o Python instalado, abra o seu terminal (Prompt de Comando, PowerShell ou Terminal do Linux/macOS) e instale a biblioteca scapy com o seguinte comando:
pip install scapy
A biblioteca tkinter, usada para a interface gráfica, já vem inclusa na maioria das instalações padrão do Python.

Passo 3: Salvar e Executar o Script do IDS Aprimorado (Detecção Rápida e Análise de Scan)
Salve o Código: Copie todo o código Python que você recebeu e cole-o em um arquivo de texto. Salve este arquivo com o nome IDS Aprimorado (Detecção Rápida e Análise de Scan).py (ou qualquer outro nome com a extensão.py).
Execute com Privilégios Elevados: Para capturar o tráfego de rede, o script precisa ser executado com permissões de administrador.

No Windows:
a. Abra o Prompt de Comando ou PowerShell como Administrador.
b. Navegue até a pasta onde você salvou o arquivo IDS Aprimorado (Detecção Rápida e Análise de Scan).py.
c. Execute o script com o comando:
python .\IDS Aprimorado (Detecção Rápida e Análise de Scan).py

No Linux ou macOS:
a. Abra o Terminal.
b. Navegue até a pasta onde você salvou o arquivo.
c. Execute o script usando sudo:
sudo python3 IDS Aprimorado (Detecção Rápida e Análise de Scan).py

Ao executar, a interface gráfica do IDS deverá aparecer.

Passo 4: Usando o IDS e Analisando os Logs
A Interface Gráfica
Iniciar/Parar Captura: Use estes botões para ligar e desligar o monitoramento.
Alertas em Tempo Real: A caixa de texto principal à esquerda exibirá todos os eventos e alertas detectados em tempo real. Alertas críticos (como um Port Scan confirmado) aparecerão em vermelho e negrito.
Scanners Detectados: À direita, a lista "Scanners Ativos (IP)" será preenchida com os endereços de IP que demonstraram comportamento suspeito. Os IPs permanecem na lista por 2 minutos após a última atividade detectada.

Analisar com Nmap: Selecione um IP na lista de scanners e clique no botão. O IDS executará uma varredura Nmap detalhada contra o alvo para descobrir serviços e versões, exibindo o resultado na caixa de texto "Resultado da Análise Nmap".

Copiar Filtro Wireshark: Selecione um IP e clique para copiar um filtro para sua área de transferência. Você pode colar isso diretamente no Wireshark para isolar e analisar todo o tráfego de/para aquele IP.

O Arquivo de Log: MonitorIDS_log.log
O objetivo principal do script é salvar um registro persistente de todas as atividades para análise posterior.

No log contém:
Alertas: Todas as mensagens que aparecem na interface, com data e hora.

Resultados do Nmap: Quando você executa uma análise Nmap, o resultado completo e sem cortes é salvo no arquivo de log, delimitado por cabeçalhos para fácil identificação, isso é extremamente útil para análises forenses.

# Funcionalidades:
A funcionalidade do projeto é muito importante para: 
1- Monitoramento Contínuo e Veloz: Vigia constante do tráfego de rede para identificar atividades suspeitas em tempo real.
2- Identificação Precisa de Ameaças: Distinção entre atividades benignas e maliciosas com um baixo índice de falsos positivos.
3- Análise Detalhada de Incidentes: Fornecimento de informações ricas e contextuais sobre as ameaças detectadas para facilitar a resposta.
4- Suporte à Resposta a Incidentes: Geração de relatórios e evidências que auxiliam as equipes de segurança a neutralizar a ameaça e a fortalecer as defesas da rede.

# Tecnologias usadas:
Linguagem Python, Nmap e Wireshark
