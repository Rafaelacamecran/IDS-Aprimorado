import sys
import os
import time
import logging
import threading
import queue
import subprocess
import shutil
from collections import defaultdict

# Importar a Scapy e desativar o output
os.environ["SCAPY_LOG_LEVEL"] = "ERROR"
from scapy.all import *

# Importar a biblioteca para a interface gráfica
try:
    import tkinter as tk
    from tkinter import scrolledtext, messagebox, simpledialog, font
except ImportError:
    print("[ERRO] A biblioteca Tkinter não está instalada. Por favor, instale-a (geralmente vem com o Python).")
    sys.exit(1)

# --- Configurações Iniciais ---
LOG_DIR_WINDOWS = "C:\Logs\MonitorIDS_log"
LOG_DIR_UNIX = os.path.join(os.path.expanduser("~"), "Logs")
LOG_FILENAME = "MonitorIDS_log.log"
SCAN_TRACKER_TIMEOUT = 120 # Aumentado para 2 minutos para melhor rastreamento

# --- Módulo de Logging ---
def setup_logging():
    log_dir = LOG_DIR_WINDOWS if os.name == 'nt' else LOG_DIR_UNIX
    try:
        os.makedirs(log_dir, exist_ok=True)
    except OSError as e:
        messagebox.showerror("Erro de Log", f"Não foi possível criar o diretório de log: {e}")
        return None
    log_filepath = os.path.join(log_dir, LOG_FILENAME)
    logger = logging.getLogger('IDS_Logger')
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        handler = logging.FileHandler(log_filepath)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%d-%m-%Y %H:%M:%S')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    return logger

logger = setup_logging()

class IDS_GUI:
    def __init__(self, root):
        self.root = root
        self.root.title("IDS com Análise Integrada (Nmap/Wireshark)")
        self.root.geometry("800x600")

        self.is_running = False
        self.sniffer_thread = None
        self.alert_queue = queue.Queue()
        
        # Estruturas de dados para detecção
        self.contagem_icmp = defaultdict(list)
        # scan_tracker TCP e UDP
        self.scan_tracker = defaultdict(lambda: {'tcp_ports': set(), 'udp_ports': set(), 'last_seen': 0.0, 'alerted_tcp': False, 'alerted_udp': False})

        # Fontes
        self.default_font = font.nametofont("TkDefaultFont")
        self.default_font.configure(family="Helvetica", size=10)
        self.bold_font = font.Font(family="Helvetica", size=10, weight="bold")
        self.mono_font = font.Font(family="Consolas", size=10)
        
        # Frame de Controle Superior
        self.control_frame = tk.Frame(root)
        self.control_frame.pack(pady=10, padx=10, fill="x")

        self.start_button = tk.Button(self.control_frame, text="Iniciar Captura", command=self.start_sniffing, font=self.bold_font, fg="Blue")
        self.start_button.pack(side="left", padx=5)

        self.stop_button = tk.Button(self.control_frame, text="Parar Captura", command=self.stop_sniffing, state="disabled", font=self.bold_font, fg="red")
        self.stop_button.pack(side="left", padx=5)
        
        self.config_frame = tk.LabelFrame(self.control_frame, text="Configurações de Detecção", padx=10, pady=5)
        self.config_frame.pack(side="right", padx=10)

        self.port_scan_threshold_var = tk.IntVar(value=15)
        tk.Label(self.config_frame, text="Limite Port Scan:").pack(side="left")
        tk.Entry(self.config_frame, textvariable=self.port_scan_threshold_var, width=5).pack(side="left", padx=(0,10))

        self.icmp_limit_var = tk.IntVar(value=10)
        tk.Label(self.config_frame, text="Limite ICMP/s:").pack(side="left")
        tk.Entry(self.config_frame, textvariable=self.icmp_limit_var, width=5).pack(side="left")

        # Frame Principal (dividido em 3)
        self.main_frame = tk.Frame(root)
        self.main_frame.pack(pady=5, padx=10, expand=True, fill="both")
        
        # Painel de Alertas Gerais
        self.alerts_panel = tk.LabelFrame(self.main_frame, text="Alertas em Tempo Real", padx=5, pady=5)
        self.alerts_panel.pack(side="left", expand=True, fill="both", padx=(0, 5))
        self.alert_area = scrolledtext.ScrolledText(self.alerts_panel, wrap=tk.WORD, state="disabled", font=self.mono_font)
        self.alert_area.pack(expand=True, fill="both")

        # Frame da Direita (Scanners e Análise Nmap)
        self.right_frame = tk.Frame(self.main_frame)
        self.right_frame.pack(side="right", fill="both", ipadx=5, expand=True)

        # Painel de Análise de Scanners
        self.scan_panel = tk.LabelFrame(self.right_frame, text="Scanners Detectados", padx=5, pady=5)
        self.scan_panel.pack(side="top", fill="both", expand=True)
        
        tk.Label(self.scan_panel, text="Scanners Ativos (IP):").pack(anchor="w")
        self.scanners_listbox = tk.Listbox(self.scan_panel, width=30, height=10)
        self.scanners_listbox.pack(expand=True, fill="both", pady=(0,5))
        self.scanners_listbox.bind('<<ListboxSelect>>', self.on_scanner_select)
        
        # Frame para botões de análises
        self.analysis_button_frame = tk.Frame(self.scan_panel)
        self.analysis_button_frame.pack(fill="x", pady=5)
        
        self.nmap_button = tk.Button(self.analysis_button_frame, text="Analisar com Nmap", command=self.run_nmap_analysis, state="disabled")
        self.nmap_button.pack(side="left", expand=True, fill="x", padx=(0,2))
        
        self.wireshark_button = tk.Button(self.analysis_button_frame, text="Copiar Filtro Wireshark", command=self.copy_wireshark_filter, state="disabled")
        self.wireshark_button.pack(side="right", expand=True, fill="x", padx=(2,0))
        
        # Painel para resultados do Nmap
        self.nmap_panel = tk.LabelFrame(self.right_frame, text="Resultado da Análise Nmap", padx=5, pady=5)
        self.nmap_panel.pack(side="bottom", fill="both", expand=True, pady=(5,0))
        self.nmap_result_area = scrolledtext.ScrolledText(self.nmap_panel, wrap=tk.WORD, state="disabled", font=self.mono_font, bg="#f0f0f0")
        self.nmap_result_area.pack(expand=True, fill="both")

        self.status_bar = tk.Label(root, text="Status: Parado", bd=1, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill="x")

        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.nmap_path = shutil.which("nmap") # Verificar se nmap existe no PATH
        if not self.nmap_path:
            self.log_and_display_alert("[AVISO] Executável 'nmap' não encontrado no PATH do sistema. A análise com Nmap será desativada.\n")
            
        self.process_queue()

    def log_and_display_alert(self, message, is_major_alert=False):
        prefix = "[!!] " if is_major_alert else ""
        full_message = f"{prefix}{message}"
        self.alert_queue.put(full_message)
        if logger:
            logger.warning(message.strip()) if is_major_alert else logger.info(message.strip())

    def process_queue(self):
        try:
            while True:
                message = self.alert_queue.get_nowait()
                self.alert_area.config(state="normal")
                tag = "major_alert" if message.startswith("[!!]") else "normal_alert"
                self.alert_area.tag_configure("major_alert", foreground="red", font=self.bold_font)
                self.alert_area.insert(tk.END, message, tag)
                self.alert_area.see(tk.END)
                self.alert_area.config(state="disabled")
        except queue.Empty:
            pass
        finally:
            self.root.after(100, self.process_queue)

    def start_sniffing(self):
        if os.name == 'nt':
            try:
                import ctypes
                if not ctypes.windll.shell32.IsUserAnAdmin():
                    messagebox.showerror("Erro de Permissão", "Este script precisa ser executado como Administrador no Windows para capturar pacotes.")
                    return
            except (NameError, AttributeError, ImportError):
                pass
        
        self.is_running = True
        self.start_button.config(state="disabled")
        self.stop_button.config(state="normal")

        # Filtro BPF para incluir UDP
        bpf_filter = "tcp or icmp or udp"
        self.status_bar.config(text=f"Status: Rodando... Filtro BPF Ativo: '{bpf_filter}'")
        self.log_and_display_alert("Iniciando a captura de pacotes...\n")
        self.sniffer_thread = threading.Thread(target=self.run_sniffer, args=(bpf_filter,), daemon=True)
        self.sniffer_thread.start()

        # Inicia a limpeza periódica de scanners
        self.root.after(SCAN_TRACKER_TIMEOUT * 1000, self.periodic_scanner_cleanup)

    def stop_sniffing(self):
        self.is_running = False
        self.start_button.config(state="normal")
        self.stop_button.config(state="disabled")
        self.status_bar.config(text="Status: Parado")
        self.log_and_display_alert("Captura de pacotes parada pelo usuário.\n")

    def run_sniffer(self, bpf_filter):
        self.log_and_display_alert(f"Sniffer iniciado em uma thread separada (Filtro: {bpf_filter}).\n")
        try:
            sniff(prn=self.analisador_de_pacotes, 
                  filter=bpf_filter, 
                  stop_filter=lambda p: not self.is_running, 
                  store=0)
        except (PermissionError, OSError):
            self.log_and_display_alert("[ERRO] Permissão negada para capturar pacotes. Execute como administrador/root.\n", True)
            self.root.after(0, self.stop_sniffing)
        except Exception as e:
            self.log_and_display_alert(f"[ERRO] Falha na captura: {e}\n", True)
            self.root.after(0, self.stop_sniffing)

    def on_closing(self):
        if self.is_running:
            if messagebox.askokcancel("Sair", "O IDS está rodando. Deseja parar e sair?"):
                self.stop_sniffing()
                self.root.destroy()
        else:
            self.root.destroy()
            
    def periodic_scanner_cleanup(self):
        if self.is_running:
            self.update_scanners_list()
            self.root.after(SCAN_TRACKER_TIMEOUT * 1000, self.periodic_scanner_cleanup)
            
    def update_scanners_list(self):
        current_selection = self.scanners_listbox.curselection()
        selected_ip = self.scanners_listbox.get(current_selection) if current_selection else None
        
        self.scanners_listbox.delete(0, tk.END)
        
        current_time = time.time()
        inactive_scanners = [ip for ip, data in self.scan_tracker.items() if current_time - data['last_seen'] > SCAN_TRACKER_TIMEOUT]
        if inactive_scanners:
             self.log_and_display_alert(f"Removendo scanners inativos: {', '.join(inactive_scanners)}\n")
        for ip in inactive_scanners:
            del self.scan_tracker[ip]

        active_scanners = sorted(self.scan_tracker.keys())
        new_idx = -1
        for i, ip in enumerate(active_scanners):
            self.scanners_listbox.insert(tk.END, ip)
            if ip == selected_ip:
                new_idx = i

        if new_idx != -1:
            self.scanners_listbox.selection_set(new_idx)
            self.scanners_listbox.see(new_idx)

    def on_scanner_select(self, event=None):
        selection_indices = self.scanners_listbox.curselection()
        if not selection_indices:
            self.nmap_button.config(state="disabled")
            self.wireshark_button.config(state="disabled")
            return
        
        self.nmap_button.config(state="normal" if self.nmap_path else "disabled")
        self.wireshark_button.config(state="normal")
        
    def get_selected_ip(self):
        selection_indices = self.scanners_listbox.curselection()
        if not selection_indices:
            return None
        return self.scanners_listbox.get(selection_indices[0])

    def run_nmap_analysis(self):
        ip = self.get_selected_ip()
        if not ip:
            messagebox.showwarning("Nmap", "Nenhum IP selecionado para análise.")
            return

        if not self.nmap_path:
            messagebox.showerror("Nmap", "O Nmap não foi encontrado. Verifique a instalação.")
            return

        self.log_and_display_alert(f"Iniciando análise Nmap em {ip}...\n")
        self.nmap_result_area.config(state="normal", bg="#ffffff")
        self.nmap_result_area.delete(1.0, tk.END)
        self.nmap_result_area.insert(tk.END, f"Executando 'nmap -sV -T4 {ip}'...\n\nAguarde, isso pode levar alguns minutos.\n")
        self.nmap_result_area.config(state="disabled")
        
        # Executa o Nmap em uma thread separada para não travar a GUI
        threading.Thread(target=self._execute_nmap, args=(ip,), daemon=True).start()

    def _execute_nmap(self, ip):
        try:
            # -sV: Detecção de versão, -T4: Template agressivo (mais rápido)
            command = [self.nmap_path, "-sV", "-T4", ip]
            # Usamos Popen para capturar o output em tempo real se quiséssemos, mas para simplificar, usamos run.
            result = subprocess.run(command, capture_output=True, text=True, check=True, encoding='utf-8', errors='ignore')
            output = result.stdout
        except subprocess.CalledProcessError as e:
            output = f"Erro ao executar o Nmap:\n{e}\n\nOutput (stderr):\n{e.stderr}"
        except Exception as e:
            output = f"Ocorreu um erro inesperado: {e}"

        # Envia o resultado para a fila para ser exibido na thread principal da GUI
        self.alert_queue.put(f"Análise Nmap em {ip} concluída. Resultado salvo no log.\n")
        
        # Formata e salva o resultado completo do Nmap no arquivo de log
        if logger:
            log_header = f"\n=============== INÍCIO DO RESULTADO NMAP PARA {ip} ===============\n"
            log_footer = f"================ FIM DO RESULTADO NMAP PARA {ip} =================\n"
            logger.info(f"{log_header}{output}{log_footer}")

        # Função para atualizar a GUI do nmap
        def update_nmap_gui():
            self.nmap_result_area.config(state="normal")
            self.nmap_result_area.delete(1.0, tk.END)
            self.nmap_result_area.insert(tk.END, output)
            self.nmap_result_area.config(state="disabled")
        
        # Agenda a atualização da GUI na thread principal
        self.root.after(0, update_nmap_gui)

    def copy_wireshark_filter(self):
        ip = self.get_selected_ip()
        if not ip:
            return
        
        filter_string = f"ip.addr == {ip}"
        self.root.clipboard_clear()
        self.root.clipboard_append(filter_string)
        self.log_and_display_alert(f"Filtro Wireshark '{filter_string}' copiado para a área de transferência.\n")
        messagebox.showinfo("Filtro Copiado", f"Filtro Wireshark '{filter_string}' copiado!\nCole no campo de filtro do Wireshark.")

    # Lógica de Detecção Aprimorada
    
    def handle_scan_detection(self, src_ip, dport, proto):
        tracker = self.scan_tracker[src_ip]
        tracker['last_seen'] = time.time()
        
        port_scan_threshold = self.port_scan_threshold_var.get()
        alert_triggered = False

        if proto == "tcp":
            tracker['tcp_ports'].add(dport)
            if len(tracker['tcp_ports']) > port_scan_threshold and not tracker['alerted_tcp']:
                tracker['alerted_tcp'] = True
                port_list = ", ".join(map(str, sorted(list(tracker['tcp_ports']))))
                self.log_and_display_alert(f"TCP PORT SCAN DETECTADO de {src_ip}! Portas: {port_list[:150]}...\n", True)
                alert_triggered = True
        elif proto == "udp":
            tracker['udp_ports'].add(dport)
            if len(tracker['udp_ports']) > port_scan_threshold and not tracker['alerted_udp']:
                tracker['alerted_udp'] = True
                port_list = ", ".join(map(str, sorted(list(tracker['udp_ports']))))
                self.log_and_display_alert(f"UDP PORT SCAN DETECTADO de {src_ip}! Portas: {port_list[:150]}...\n", True)
                alert_triggered = True

        if alert_triggered:
            self.root.after(0, self.update_scanners_list)

    def analisador_de_pacotes(self, pacote):
        if not self.is_running: return

        if pacote.haslayer(IP):
            src_ip = pacote[IP].src
            dst_ip = pacote[IP].dst

            # Detecção de Scans TCP
            if pacote.haslayer(TCP):
                dport = pacote[TCP].dport
                flags = pacote[TCP].flags
                scan_type = None

                # Scans Stealth
                if flags == 0: scan_type = "NULL Scan"
                elif flags == 'F': scan_type = "FIN Scan"
                elif flags == 'FPU': scan_type = "Xmas Scan"
                # NOVO: Detecção de SYN Scan (o mais comum)
                elif flags == 'S': scan_type = "SYN Scan/Connect" 
                
                if scan_type:
                    self.log_and_display_alert(f"Atividade TCP suspeita ({scan_type}) de {src_ip} para {dst_ip}:{dport}\n")
                    self.handle_scan_detection(src_ip, dport, "tcp")
            
            # Detecção de Scans UDP
            elif pacote.haslayer(UDP):
                dport = pacote[UDP].dport
                self.log_and_display_alert(f"Atividade UDP detectada de {src_ip} para {dst_ip}:{dport}\n")
                self.handle_scan_detection(src_ip, dport, "udp")

            # Detecção de Ping Flood / ICMP Scan
            elif pacote.haslayer(ICMP) and pacote[ICMP].type == 8:
                current_time = time.time()
                self.contagem_icmp[src_ip].append(current_time)
                # Limpa pings mais antigos que 1 segundo
                self.contagem_icmp[src_ip] = [t for t in self.contagem_icmp[src_ip] if current_time - t <= 1]
                
                icmp_limit = self.icmp_limit_var.get()
                if len(self.contagem_icmp[src_ip]) > icmp_limit:
                    self.log_and_display_alert(f"Potencial Ping Flood/ICMP Scan de {src_ip} ({len(self.contagem_icmp[src_ip])} pings/s)\n", True)
                    # Adiciona à lista de scanners para possível análise Nmap
                    self.scan_tracker[src_ip]['last_seen'] = current_time
                    self.root.after(0, self.update_scanners_list)


if __name__ == "__main__":
    root = tk.Tk()
    app = IDS_GUI(root)
    root.mainloop()