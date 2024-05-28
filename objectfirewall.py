import customtkinter as ctk
import tkinter as tk
from tkinter import simpledialog, messagebox
import subprocess
import re

class FirewallManagerApp:
    def __init__(self, root):
        self.root = root
        self.domain_ip_map = {}
        self.sudo_password = self.ask_sudo_password()
        
        # La password è richiesta in quanto iptables funziona solo con sudo
        if not self.sudo_password:
            messagebox.showerror("Errore", "Password sudo richiesta per eseguire i comandi iptables.")
            self.root.destroy()
            return

        self.setup_ui()

    # Iput per la password
    def ask_sudo_password(self):
        return simpledialog.askstring("Password sudo", "Inserisci la password sudo:", show='*')

    # Metodo per il comando da runnare
    def run_iptables_command(self, command, show_message=True):
        try:
            result = subprocess.run(['sudo', '-S'] + command.split(), input=self.sudo_password + '\n', text=True, capture_output=True)
            if result.returncode == 0:
                if show_message:
                    messagebox.showinfo("Successo", "Comando eseguito con successo!")
            else:
                messagebox.showerror("Errore", f"Errore nell'esecuzione del comando: {result.stderr}")
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Errore", f"Errore nell'esecuzione del comando: {e}")

    # Questo metodo usa dig per risalire a tutti gli IP del dominio inserito
    # in quanto iptables funziona tramite IP
    def resolve_domain(self, domain):
        result = subprocess.run(['dig', '+short', domain], capture_output=True, text=True)
        return result.stdout.splitlines()

    # Metodo che blocca l'IP inserito
    def block_ip(self):
        ip = self.entry_ip.get()
        if ip:
            self.run_iptables_command(f"iptables -A INPUT -s {ip} -j DROP")
            self.show_rules()
        else:
            messagebox.showwarning("Attenzione", "Inserisci un indirizzo IP valido.")

    def unblock_ip(self):
        ip = self.entry_ip.get()
        if ip:
            self.run_iptables_command(f"iptables -D INPUT -s {ip} -j DROP")
            self.show_rules()
        else:
            messagebox.showwarning("Attenzione", "Inserisci un indirizzo IP valido.")

    def block_port(self):
        port = self.entry_port.get()
        protocol = self.protocol_selector.get()
        if port and protocol:
            self.run_iptables_command(f"iptables -A INPUT -p {protocol} --dport {port} -j DROP")
            self.show_rules()
        else:
            messagebox.showwarning("Attenzione", "Inserisci una porta e un protocollo validi.")

    def unblock_port(self):
        port = self.entry_port.get()
        protocol = self.protocol_selector.get()
        if port and protocol:
            self.run_iptables_command(f"iptables -D INPUT -p {protocol} --dport {port} -j DROP")
            self.show_rules()
        else:
            messagebox.showwarning("Attenzione", "Inserisci una porta e un protocollo validi.")

    def show_rules(self):
        result = subprocess.run(['sudo', '-S', 'iptables', '-L', '-n'], input=self.sudo_password + '\n', text=True, capture_output=True)
        cleaned_output = self.clean_iptables_output(result.stdout)
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert(tk.END, cleaned_output)

    def flush_rules(self):
        self.run_iptables_command("iptables -F")
        self.show_rules()

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

    def add_custom_rule(self):
        rule = self.custom_rule_entry.get()
        if rule:
            self.run_iptables_command(f"iptables {rule}")
            self.show_rules()
        else:
            messagebox.showwarning("Attenzione", "Inserisci una regola iptables valida.")

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
                messagebox.showerror("Errore", f"Impossibile risolvere il dominio: {domain}")
        else:
            messagebox.showwarning("Attenzione", "Inserisci un dominio valido.")

    def unblock_domain(self):
        domain = self.entry_domain.get()
        if domain in self.domain_ip_map:
            for ip in self.domain_ip_map[domain]:
                self.run_iptables_command(f"iptables -D INPUT -s {ip} -j DROP", show_message=False)
            del self.domain_ip_map[domain]
            messagebox.showinfo("Successo", f"Dominio sbloccato con successo! ({domain})")
            self.show_rules()
        else:
            messagebox.showwarning("Attenzione", "Dominio non trovato nella lista dei domini bloccati.")

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
        self.protocol_selector.set("tcp")  # Seleziona di default il primo protocollo (tcp)

        btn_block_port = ctk.CTkButton(frame, text="Blocca Porta", command=self.block_port)
        btn_block_port.grid(row=1, column=3, padx=5, pady=10)

        btn_unblock_port = ctk.CTkButton(frame, text="Sblocca Porta", command=self.unblock_port)
        btn_unblock_port.grid(row=1, column=4, padx=5, pady=10)

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

        self.output_text = ctk.CTkTextbox(self.root, height=300, width=600, padx=10, pady=10)
        self.output_text.pack(pady=20)

    def start(self):
        self.root.mainloop()

if __name__ == "__main__":
    root = ctk.CTk()
    root.title("Gestore Firewall con Iptables")

    app = FirewallManagerApp(root)
    app.start()
