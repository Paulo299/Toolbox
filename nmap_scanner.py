import tkinter as tk
from tkinter import messagebox
import nmap

def scan_ports():
    ip_address = entry_ip.get()
    if not ip_address:
        messagebox.showerror("Erreur", "Veuillez entrer une adresse IP valide.")
        return
    
    scanner = nmap.PortScanner()
    try:
        scanner.scan(ip_address, '1-1024')
        result_text.delete(1.0, tk.END)  # Clear previous results
        for host in scanner.all_hosts():
            result_text.insert(tk.END, f"Host: {host} ({scanner[host].hostname()})\n")
            result_text.insert(tk.END, f"State: {scanner[host].state()}\n")
            for proto in scanner[host].all_protocols():
                result_text.insert(tk.END, f"Protocol: {proto}\n")
                lport = scanner[host][proto].keys()
                for port in sorted(lport):
                    result_text.insert(tk.END, f"Port: {port}\tState: {scanner[host][proto][port]['state']}\n")
    except Exception as e:
        messagebox.showerror("Erreur", f"Une erreur s'est produite : {e}")

# Création de la fenêtre principale
root = tk.Tk()
root.title("Nmap Port Scanner")

# Création des widgets
label_ip = tk.Label(root, text="Adresse IP à scanner:")
label_ip.pack(pady=5)

entry_ip = tk.Entry(root, width=30)
entry_ip.pack(pady=5)

button_scan = tk.Button(root, text="Scanner", command=scan_ports)
button_scan.pack(pady=5)

result_text = tk.Text(root, width=80, height=20)
result_text.pack(pady=5)

# Lancement de la boucle principale de l'interface
root.mainloop()
