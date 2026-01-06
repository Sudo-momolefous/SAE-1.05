import tkinter as tk
from tkinter import filedialog, messagebox
import re
import pandas as pd
import matplotlib.pyplot as plt
from collections import Counter

# fonction pour analyser chaque ligne du fichier tcpdump
def parse_tcpdump_line(line):
    regex = r"(?P<timestamp>\d{2}:\d{2}:\d{2}\.\d{6})\s+IP\s+(?P<ip_src>[\d\.]+|\S+)\.(?P<src_port>\d+)\s+>\s+(?P<ip_dst>[\d\.]+|\S+)\.(?P<dst_port>\d+):\s+Flags\s\[(?P<flags>[A-Za-z\.\s]+)\],\s+seq\s(?P<seq>\d+):(?P<seq_end>\d+),\s+ack\s(?P<ack>\d+),\s+win\s(?P<win>\d+),\s+options\s\[[^\]]*\],\s+length\s(?P<length>\d+)"
    
    match = re.match(regex, line)
    
    if match:
        return match.groupdict()
    return None

# fonction pour lire un fichier texte et analyser les paquets
def process_tcpdump_file(file_path):
    try:
        with open(file_path, "r") as file:
            packets = []
            for line in file:
                packet_data = parse_tcpdump_line(line)
                if packet_data:
                    packets.append(packet_data)
            
            if packets:
                return packets
            else:
                return None
    except Exception as e:
        return str(e)

# fonction pour afficher les paquets dans la fenêtre de résultat
def display_results(packets):
    if packets:
        result_text.delete(1.0, tk.END)  # Efface le texte actuel
        for i, packet in enumerate(packets, start=1):
            result_text.insert(tk.END, f"Paquet #{i}:\n")
            result_text.insert(tk.END, f"  Horodatage : {packet['timestamp']}\n")
            result_text.insert(tk.END, f"  Source : {packet['ip_src']}:{packet['src_port']} -> {packet['ip_dst']}:{packet['dst_port']}\n")
            result_text.insert(tk.END, f"  Flags : {packet['flags']}\n")
            result_text.insert(tk.END, f"  Seq : {packet['seq']} -> {packet['seq_end']}, Ack : {packet['ack']}\n")
            result_text.insert(tk.END, f"  Window Size : {packet['win']}, Length : {packet['length']} octets\n")
            result_text.insert(tk.END, "-" * 40 + "\n")
    else:
        messagebox.showerror("Erreur", "Aucun paquet valide trouvé dans le fichier.")

# fonction pour générer le fichier CSV avec les informations des paquets
def generate_csv(packets, file_path):
    df = pd.DataFrame(packets)
    csv_path = file_path.replace('.txt', '_packets.csv')
    df.to_csv(csv_path, index=False)
    messagebox.showinfo("Succès", f"Le fichier CSV a été généré : {csv_path}")
    return csv_path

# fonction pour générer le graphique des ports utilisés
def generate_port_graph(packets):
    # collecter les ports source et destination
    src_ports = [packet['src_port'] for packet in packets]
    dst_ports = [packet['dst_port'] for packet in packets]

    # compter les occurrences des ports
    src_port_counts = Counter(src_ports)
    dst_port_counts = Counter(dst_ports)

    # tracer le graphique
    fig, ax = plt.subplots(figsize=(10, 6))

    ax.bar(src_port_counts.keys(), src_port_counts.values(), width=0.4, label="Ports Source", align='center')
    ax.bar(dst_port_counts.keys(), dst_port_counts.values(), width=0.4, label="Ports Destination", align='edge')

    ax.set_xlabel('Port')
    ax.set_ylabel('Nombre d\'occurrences')
    ax.set_title('Distribution des Ports Source et Destination')
    ax.legend()

    plt.xticks(rotation=90)
    plt.tight_layout()
    plt.show()

# fonction pour ouvrir la boîte de dialogue de sélection de fichier
def open_file():
    file_path = filedialog.askopenfilename(filetypes=[("Fichiers texte", "*.txt")])
    if file_path:
        packets = process_tcpdump_file(file_path)
        
        if packets:
            display_results(packets)
            
            # générer le fichier CSV
            csv_path = generate_csv(packets, file_path)
            
            # générer le graphique des ports
            generate_port_graph(packets)
        else:
            messagebox.showerror("Erreur", "Le fichier ne contient pas de paquets valides.")

# création de la fenêtre principale avec tkinter
root = tk.Tk()
root.title("Analyseur de Paquets")

# taille et position de la fenêtre
root.geometry("800x600")

# création du bouton pour ouvrir un fichier
open_button = tk.Button(root, text="Ouvrir un fichier .txt", command=open_file)
open_button.pack(pady=10)

# création d'une zone de texte pour afficher les résultats
result_text = tk.Text(root, wrap=tk.WORD, height=20, width=80)
result_text.pack(padx=10, pady=10)

# marre de défilement pour la zone de texte
scrollbar = tk.Scrollbar(root, command=result_text.yview)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
result_text.config(yscrollcommand=scrollbar.set)

# lancement de l'interface
root.mainloop()
