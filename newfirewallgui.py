import customtkinter as ctk
import tkinter as tk
from CTkMessagebox import CTkMessagebox
from tkinter import simpledialog, messagebox
import subprocess
import re

# Funzione per eseguire comandi iptables
def run_iptables_command(command, show_message=True):
    try:
        result = subprocess.run(['sudo', '-S'] + command.split(), input=sudo_password + '\n', text=True, capture_output=True)
        if result.returncode == 0:
            if show_message:
                messagebox.showinfo("Successo", "Comando eseguito con successo!")
        else:
            messagebox.showerror("Errore", f"Errore nell'esecuzione del comando: {result.stderr}")
    except subprocess.CalledProcessError as e:
        messagebox.showerror("Errore", f"Errore nell'esecuzione del comando: {e}")

# Funzione per risolvere un dominio in IP
def resolve_domain(domain):
    result = subprocess.run(['dig', '+short', domain], capture_output=True, text=True)
    return result.stdout.splitlines()

# Mappatura dei domini agli IP
domain_ip_map = {}

# Funzione per bloccare un IP
def block_ip():
    ip = entry_ip.get()
    if ip:
        run_iptables_command(f"iptables -A INPUT -s {ip} -j DROP")
        show_rules()
    else:
        messagebox.showwarning("Attenzione", "Inserisci un indirizzo IP valido.")

# Funzione per sbloccare un IP
def unblock_ip():
    ip = entry_ip.get()
    if ip:
        run_iptables_command(f"iptables -D INPUT -s {ip} -j DROP")
        show_rules()
    else:
        messagebox.showwarning("Attenzione", "Inserisci un indirizzo IP valido.")

# Funzione per bloccare una porta
def block_port():
    port = entry_port.get()
    protocol = protocol_selector.get()
    if port and protocol:
        run_iptables_command(f"iptables -A INPUT -p {protocol} --dport {port} -j DROP")
        show_rules()
    else:
        messagebox.showwarning("Attenzione", "Inserisci una porta e un protocollo validi.")

# Funzione per sbloccare una porta
def unblock_port():
    port = entry_port.get()
    protocol = protocol_selector.get()
    if port and protocol:
        run_iptables_command(f"iptables -D INPUT -p {protocol} --dport {port} -j DROP")
        show_rules()
    else:
        messagebox.showwarning("Attenzione", "Inserisci una porta e un protocollo validi.")

# Funzione per mostrare le regole
def show_rules():
    result = subprocess.run(['sudo', '-S', 'iptables', '-L', '-n'], input=sudo_password + '\n', text=True, capture_output=True)
    cleaned_output = clean_iptables_output(result.stdout)
    output_text.delete("1.0", tk.END)
    output_text.insert(tk.END, cleaned_output)

# Funzione per cancellare tutte le regole
def flush_rules():
    run_iptables_command("iptables -F")
    show_rules()

# Funzione per pulire l'output di iptables -L
def clean_iptables_output(output):
    lines = output.splitlines()
    filtered_lines = []
    for line in lines:
        if re.search(r'\bDROP\b', line):
            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
            if ip_match:
                ip = ip_match.group(1)
                domain = next((d for d, ips in domain_ip_map.items() if ip in ips), ip)
                filtered_lines.append(f"{line.strip()} ({domain})")
    if not filtered_lines:
        return "Nessuna regola trovata."
    return "\n".join(filtered_lines)

# Funzione per aggiungere una regola iptables personalizzata
def add_custom_rule():
    rule = custom_rule_entry.get()
    if rule:
        run_iptables_command(f"iptables {rule}")
        show_rules()
    else:
        messagebox.showwarning("Attenzione", "Inserisci una regola iptables valida.")

# Funzione per bloccare un dominio
def block_domain():
    domain = entry_domain.get()
    if domain:
        ips = resolve_domain(domain)
        if ips:
            domain_ip_map[domain] = ips
            for i, ip in enumerate(ips):
                show_message = i == len(ips) - 1
                run_iptables_command(f"iptables -A INPUT -s {ip} -j DROP", show_message=show_message)
            show_rules()
        else:
            messagebox.showerror("Errore", f"Impossibile risolvere il dominio: {domain}")
    else:
        messagebox.showwarning("Attenzione", "Inserisci un dominio valido.")

# Funzione per sbloccare un dominio
def unblock_domain():
    domain = entry_domain.get()
    if domain in domain_ip_map:
        for ip in domain_ip_map[domain]:
            run_iptables_command(f"iptables -D INPUT -s {ip} -j DROP", show_message=False)
        del domain_ip_map[domain]
        messagebox.showinfo("Successo", f"Dominio sbloccato con successo! ({domain})")
        show_rules()
    else:
        messagebox.showwarning("Attenzione", "Dominio non trovato nella lista dei domini bloccati.")

# Creazione della GUI con customtkinter
ctk.set_appearance_mode("System")  # Imposta il tema scuro o chiaro
ctk.set_default_color_theme("dark-blue")  # Imposta il tema colore

root = ctk.CTk()
root.title("Gestore Firewall con Iptables")

frame = ctk.CTkFrame(root, width=200, height=200)
frame.pack(pady=20)

# Creazione di un widget Entry per l'inserimento di regole personalizzate
custom_rule_label = ctk.CTkLabel(frame, text="Regola Personalizzata:")
custom_rule_label.grid(row=3, column=0, padx=5, pady=5)

custom_rule_entry = ctk.CTkEntry(frame, width=300)
custom_rule_entry.grid(row=3, column=1, columnspan=3, padx=5, pady=5)

btn_add_custom_rule = ctk.CTkButton(frame, text="Aggiungi Regola", command=add_custom_rule)
btn_add_custom_rule.grid(row=3, column=4, padx=5, pady=5)

label_ip = ctk.CTkLabel(frame, text="Inserisci indirizzo IP:")
label_ip.grid(row=0, column=0, padx=5, pady=5)

entry_ip = ctk.CTkEntry(frame, width=200)
entry_ip.grid(row=0, column=1, padx=5, pady=5)

btn_block = ctk.CTkButton(frame, text="Blocca IP", command=block_ip)
btn_block.grid(row=0, column=3, padx=5, pady=5)

btn_unblock = ctk.CTkButton(frame, text="Sblocca IP", command=unblock_ip)
btn_unblock.grid(row=0, column=4, padx=5, pady=5)

label_port = ctk.CTkLabel(frame, text="Inserisci porta:")
label_port.grid(row=1, column=0, padx=5, pady=5)

entry_port = ctk.CTkEntry(frame, width=100)
entry_port.grid(row=1, column=1, padx=5, pady=5)

label_protocol = ctk.CTkLabel(frame, text="Protocollo:")
label_protocol.grid(row=2, column=0, padx=5, pady=5)

protocol_selector = ctk.CTkComboBox(frame, values=["tcp", "udp", "icmp"])
protocol_selector.grid(row=2, column=1, padx=5, pady=5)
protocol_selector.set("tcp")  # Seleziona di default il primo protocollo (tcp)

btn_block_port = ctk.CTkButton(frame, text="Blocca Porta", command=block_port)
btn_block_port.grid(row=1, column=3, padx=5, pady=10)

btn_unblock_port = ctk.CTkButton(frame, text="Sblocca Porta", command=unblock_port)
btn_unblock_port.grid(row=1, column=4, padx=5, pady=10)

label_domain = ctk.CTkLabel(frame, text="Inserisci dominio:")
label_domain.grid(row=4, column=0, padx=5, pady=5)

entry_domain = ctk.CTkEntry(frame, width=200)
entry_domain.grid(row=4, column=1, padx=5, pady=5)

btn_block_domain = ctk.CTkButton(frame, text="Blocca Dominio", command=block_domain)
btn_block_domain.grid(row=4, column=3, padx=5, pady=5)

btn_unblock_domain = ctk.CTkButton(frame, text="Sblocca Dominio", command=unblock_domain)
btn_unblock_domain.grid(row=4, column=4, padx=5, pady=5)

output_text = ctk.CTkTextbox(root, height=300, width=600, padx=10, pady=10)
output_text.pack(pady=20)

btn_show = ctk.CTkButton(frame, text="Mostra Regole", command=show_rules)
btn_show.grid(row=5, column=0, padx=5, pady=20)

btn_flush = ctk.CTkButton(frame, text="Cancella Tutte le Regole", command=flush_rules)
btn_flush.grid(row=5, column=4, padx=5, pady=20)

# Richiesta della password sudo all'avvio
sudo_password = simpledialog.askstring("Password sudo", "Inserisci la password sudo:", show='*')
if not sudo_password:
    messagebox.showerror("Errore", "Password sudo richiesta per eseguire i comandi iptables.")
    root.destroy()

root.mainloop()

