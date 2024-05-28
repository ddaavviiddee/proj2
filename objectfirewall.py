import customtkinter as ctk
import tkinter as tk
import subprocess
import re
from CTkMessagebox import CTkMessagebox

class FirewallManagerApp:
    def __init__(self, root):

        # Inizializzazione della finestra, controlla se abbiamo inserito la password
        self.root = root
        self.domain_ip_map = {}
        self.sudo_password = self.ask_sudo_password()

        # Se non abbiamo inserito una password allora non possiamo accedere all'applicazione
        if not self.sudo_password:
            CTkMessagebox(title="Errore", message="Password sudo richiesta per eseguire i comandi iptables.", icon="cancel")
            self.root.destroy()
            return

        self.setup_ui()

    # Input per la password
    def ask_sudo_password(self):
        while True:
            password_dialog = ctk.CTkInputDialog(title="Password sudo", text="Inserisci la password sudo:")
            password_dialog.configure(show="*")
            password = password_dialog.get_input()

            if not password:
                return None
            if self.validate_sudo_password(password):
                return password
            else:
                CTkMessagebox(title="Errore", message="Password sudo non valida. Riprova.", icon="cancel")

    # Funzione che valida la password inserita
    def validate_sudo_password(self, password):
        try:
            # Viene eseguito un processo che effettua un'operazione con sudo
            # se l'operazione ha successo allora la password è corretta
            # e ritornerà process.returncode == 0
            # altrimenti ritorna false
            process = subprocess.Popen(['sudo', '-S', 'echo', 'password_check'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = process.communicate(input=password + '\n', timeout=5)
            return process.returncode == 0
        except subprocess.TimeoutExpired:
            process.kill()
            return False
        except subprocess.CalledProcessError:
            return False

    # Funzione generale per l'esecuzione dei comandi iptables, gestisce anche gli errori
    def run_iptables_command(self, command, show_message=True):
        try:
            result = subprocess.run(['sudo', '-S'] + command.split(), input=self.sudo_password + '\n', text=True, capture_output=True)
            if result.returncode == 0:
                if show_message:
                    CTkMessagebox(title="Successo", message="Azione avvenuta con successo.", icon="check", master=root)
            else:
                CTkMessagebox(title="Errore", message=f"Errore nell'esecuzione del comando: {result.stderr}", icon="cancel", master=root)
        except subprocess.CalledProcessError as e:
            CTkMessagebox(title="Errore", message=f"Errore nell'esecuzione del comando: {e}", icon="cancel", master=root)

    # Questa funzione serve a risolvere i domini prendendo tutti gli ip che gli appartengono
    def resolve_domain(self, domain):
        result = subprocess.run(['dig', '+short', domain], capture_output=True, text=True)
        return result.stdout.splitlines()

    # Funzioni per bloccare/sbloccare ip
    def block_ip(self):
        ip = self.entry_ip.get()
        if ip:
            self.run_iptables_command(f"iptables -A INPUT -s {ip} -j DROP")
            self.show_rules()
        else:
            CTkMessagebox(title="Attenzione", message="Inserisci un indirizzo IP valido.", icon="warning", master=root)

    def unblock_ip(self):
        ip = self.entry_ip.get()
        if ip:
            self.run_iptables_command(f"iptables -D INPUT -s {ip} -j DROP")
            self.show_rules()
        else:
            CTkMessagebox(title="Attenzione", message="Inserisci un indirizzo IP valido.", icon="warning", master=root)

    # Funzioni per bloccare/sbloccare porte con relativi protocolli
    def block_port(self):
        port = self.entry_port.get()
        protocol = self.protocol_selector.get()
        if port and protocol:
            self.run_iptables_command(f"iptables -A INPUT -p {protocol} --dport {port} -j DROP")
            self.show_rules()
        else:
            CTkMessagebox(title="Attenzione", message="Inserisci una porta e un protocollo validi.", icon="warning", master=root)

    def unblock_port(self):
        port = self.entry_port.get()
        protocol = self.protocol_selector.get()
        if port and protocol:
            self.run_iptables_command(f"iptables -D INPUT -p {protocol} --dport {port} -j DROP")
            self.show_rules()
        else:
            CTkMessagebox(title="Attenzione", message="Inserisci una porta e un protocollo validi.", icon="warning", master=root)

    # Funzione che mostra le regole iptables
    def show_rules(self):
        result = subprocess.run(['sudo', '-S', 'iptables', '-L', '-n'], input=self.sudo_password + '\n', text=True, capture_output=True)
        cleaned_output = self.clean_iptables_output(result.stdout)
        self.rules_listbox.delete(0, tk.END)
        for line in cleaned_output.splitlines():
            self.rules_listbox.insert(tk.END, line)

    # Funzione che cancella tutte le regole iptables
    def flush_rules(self):
        msg = CTkMessagebox(title="Conferma", message="Sei sicuro di voler cancellare tutte le regole?", icon="question", option_1="Annulla", option_2="Conferma", master=root)
        response = msg.get()
        if response == "Conferma":
            self.run_iptables_command("iptables -F")
            self.show_rules()

    # Funzione utile a ripulire l'output di -L, in modo da mostrare in modo più organizzato
    # le informazioni a utenti non esperti
    def clean_iptables_output(self, output):
        lines = output.splitlines()
        filtered_lines = []
        for line in lines:
            if re.search(r'\bDROP\b', line):
                ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                if ip_match:
                    ip = ip_match.group(1)
                    domain = next((d for d, ips in self.domain_ip_map.items() if ip in ips), ip)
                    filtered_lines.append(f"{line.strip()} ({domain})")
        if not filtered_lines:
            return "Nessuna regola trovata."
        return "\n".join(filtered_lines)

    # Funzione per l'inserimento di regole personalizzate
    def add_custom_rule(self):
        rule = self.custom_rule_entry.get()
        if rule:
            self.run_iptables_command(f"iptables {rule}")
            self.show_rules()
        else:
            CTkMessagebox(title="Attenzione", message="Inserisci una regola valida.", icon="warning", master=root)

    # Funzione che blocca/sblocca tutti gli ip appartenenti ad un dominio
    def block_domain(self):
        domain = self.entry_domain.get()
        if domain:
            ips = self.resolve_domain(domain)
            if ips:
                self.domain_ip_map[domain] = ips
                for i, ip in enumerate(ips):
                    show_message = i == len(ips) - 1
                    self.run_iptables_command(f"iptables -A INPUT -s {ip} -j DROP", show_message=show_message)
                self.show_rules()
            else:
                CTkMessagebox(title="Errore", message=f"Impossibile risolvere il dominio: {domain}", icon="cancel", master=root)
        else:
            CTkMessagebox(title="Attenzione", message="Inserisci un dominio valido.", icon="warning", master=root)

    def unblock_domain(self):
        domain = self.entry_domain.get()
        if domain in self.domain_ip_map:
            for ip in self.domain_ip_map[domain]:
                self.run_iptables_command(f"iptables -D INPUT -s {ip} -j DROP", show_message=False)
            del self.domain_ip_map[domain]
            CTkMessagebox(title="Successo", message=f"Dominio sbloccato con successo! ({domain})", icon="check", master=root)
            self.show_rules()
        else:
            CTkMessagebox(title="Attenzione", message="Dominio non trovato nella lista dei domini bloccati.", icon="warning", master=root)
    
    # Funzione utile a rimuovere una regola tramite la selezione 
    # Capisce in automatico se rimuovere un ip o una porta
    def remove_selected_rule(self):
        selected_index = self.rules_listbox.curselection()
        if selected_index:
            selected_rule = self.rules_listbox.get(selected_index)
            print(selected_rule)

            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', selected_rule)
            ip = ip_match.group(1)

            if ip_match and ip != "0.0.0.0":
                self.run_iptables_command(f"iptables -D INPUT -s {ip} -j DROP")
                self.show_rules()
            else:
                port_protocol_match = re.search(r'\s(tcp|udp|icmp)\sdpt:(\d+)', selected_rule)
                protocol = port_protocol_match.group(1)
                port = port_protocol_match.group(2)
                if port_protocol_match:
                    self.run_iptables_command(f"iptables -D INPUT -p {protocol} --dport {port} -j DROP")
                    self.show_rules()
                else:
                    CTkMessagebox(title="Errore", message="Impossibile trovare le informazioni sulla porta e sul protocollo nella regola selezionata.", icon="cancel", master=root)
        else:
            CTkMessagebox(title="Attenzione", message="Seleziona una regola da rimuovere.", icon="warning", master=root)

    # Inizializzazione della UI
    def setup_ui(self):
        ctk.set_appearance_mode("System")
        ctk.set_default_color_theme("dark-blue")

        frame = ctk.CTkFrame(self.root, width=200, height=200)
        frame.pack(pady=20)

        label_ip = ctk.CTkLabel(frame, text="Inserisci indirizzo IP:")
        label_ip.grid(row=0, column=0, padx=5, pady=5)

        self.entry_ip = ctk.CTkEntry(frame, width=200)
        self.entry_ip.grid(row=0, column=1, padx=5, pady=5)

        btn_block = ctk.CTkButton(frame, text="Blocca IP", command=self.block_ip)
        btn_block.grid(row=0, column=3, padx=5, pady=10)

        btn_unblock = ctk.CTkButton(frame, text="Sblocca IP", command=self.unblock_ip)
        btn_unblock.grid(row=0, column=4, padx=5, pady=10)

        label_port = ctk.CTkLabel(frame, text="Inserisci porta:")
        label_port.grid(row=1, column=0, padx=5, pady=5)

        self.entry_port = ctk.CTkEntry(frame, width=100)
        self.entry_port.grid(row=1, column=1, padx=5, pady=5)

        label_protocol = ctk.CTkLabel(frame, text="Protocollo:")
        label_protocol.grid(row=2, column=0, padx=5, pady=5)

        self.protocol_selector = ctk.CTkComboBox(frame, values=["tcp", "udp", "icmp"])
        self.protocol_selector.grid(row=2, column=1, padx=5, pady=5)
        self.protocol_selector.set("tcp")

        btn_block_port = ctk.CTkButton(frame, text="Blocca Porta", command=self.block_port)
        btn_block_port.grid(row=1, column=3, padx=5, pady=5)

        btn_unblock_port = ctk.CTkButton(frame, text="Sblocca Porta", command=self.unblock_port)
        btn_unblock_port.grid(row=1, column=4, padx=5, pady=5)

        custom_rule_label = ctk.CTkLabel(frame, text="Regola Personalizzata:")
        custom_rule_label.grid(row=3, column=0, padx=5, pady=5)

        self.custom_rule_entry = ctk.CTkEntry(frame, width=300)
        self.custom_rule_entry.grid(row=3, column=1, columnspan=3, padx=5, pady=5)

        btn_add_custom_rule = ctk.CTkButton(frame, text="Aggiungi Regola", command=self.add_custom_rule)
        btn_add_custom_rule.grid(row=3, column=4, padx=5, pady=5)

        label_domain = ctk.CTkLabel(frame, text="Inserisci dominio:")
        label_domain.grid(row=4, column=0, padx=5, pady=5)

        self.entry_domain = ctk.CTkEntry(frame, width=200)
        self.entry_domain.grid(row=4, column=1, padx=5, pady=5)

        btn_block_domain = ctk.CTkButton(frame, text="Blocca Dominio", command=self.block_domain)
        btn_block_domain.grid(row=4, column=3, padx=5, pady=5)

        btn_unblock_domain = ctk.CTkButton(frame, text="Sblocca Dominio", command=self.unblock_domain)
        btn_unblock_domain.grid(row=4, column=4, padx=5, pady=5)

        btn_show = ctk.CTkButton(frame, text="Mostra Regole", command=self.show_rules)
        btn_show.grid(row=5, column=0, padx=5, pady=20)

        btn_flush = ctk.CTkButton(frame, text="Cancella Tutte le Regole", command=self.flush_rules)
        btn_flush.grid(row=5, column=4, padx=5, pady=20)

        self.rules_listbox = tk.Listbox(self.root, height=15, width=80)
        self.rules_listbox.pack(pady=20)

        btn_remove_selected_rule = ctk.CTkButton(self.root, text="Rimuovi Regola Selezionata", command=self.remove_selected_rule)
        btn_remove_selected_rule.pack(pady=10)

    def start(self):
        self.root.mainloop()

if __name__ == "__main__":
    root = ctk.CTk()
    root.title("Gestore Firewall con Iptables")

    app = FirewallManagerApp(root)
    app.start()
