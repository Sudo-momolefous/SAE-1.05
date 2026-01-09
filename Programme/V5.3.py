import re
import csv
import json
import os
import tkinter as tk
from tkinter import filedialog
import webbrowser
from collections import Counter, defaultdict

pattern = re.compile(
    r'(?P<time>\d{2}:\d{2}:\d{2}\.\d+)\s+IP\s+'
    r'(?P<src>[^ ]+)\s+>\s+(?P<dst>[^:]+):'
    r'.*length\s+(?P<length>\d+)'
)

def extraire_ip(champ):
    if ":" in champ:
        champ = champ.split(":")[0]
    parties = champ.rsplit(".", 1)
    if parties[-1].isdigit():
        return parties[0]
    return champ

def lire_fichier_txt(chemin):
    trames = []
    with open(chemin, "r", encoding="utf-8") as f:
        for ligne in f:
            m = pattern.search(ligne)
            if m:
                d = m.groupdict()
                trames.append({
                    "src_ip": extraire_ip(d["src"]),
                    "dst_ip": extraire_ip(d["dst"]),
                    "length": int(d["length"])
                })
    return trames

def exporter_csv(trames):
    with open("trames.csv", "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["src_ip","dst_ip","length"],
            delimiter=";"
        )
        writer.writeheader()
        writer.writerows(trames)

def detecter_menaces(trames):
    alertes = []
    syn_like = defaultdict(int)

    for t in trames:
        syn_like[t["src_ip"]] += 1

    for ip, nb in syn_like.items():
        if nb > max(10, len(trames) * 0.2):
            alertes.append(f"suspicion activite anormale depuis {ip}")

    if not alertes:
        alertes.append("aucune menace evidente detectee")

    return alertes

def exporter_json(trames):
    src = Counter(t["src_ip"] for t in trames)
    dst = Counter(t["dst_ip"] for t in trames)
    menaces = detecter_menaces(trames)

    with open("data_ips_src.json","w",encoding="utf-8") as f:
        json.dump(dict(src.most_common(10)), f)

    with open("data_ips_dst.json","w",encoding="utf-8") as f:
        json.dump(dict(dst.most_common(10)), f)

    with open("data_menaces.json","w",encoding="utf-8") as f:
        json.dump(menaces, f)

def lancer_analyse(chemin):
    trames = lire_fichier_txt(chemin)
    exporter_csv(trames)
    exporter_json(trames)
    webbrowser.open("dashboard.html")

def choisir_fichier():
    chemin = filedialog.askopenfilename(
        title="selectionner un fichier tcpdump",
        filetypes=[("fichier texte","*.txt")]
    )
    if chemin:
        fenetre.destroy()
        lancer_analyse(chemin)

fenetre = tk.Tk()
fenetre.title("analyse trafic reseau")
fenetre.geometry("400x200")

tk.Button(fenetre, text="choisir fichier", command=choisir_fichier).pack(pady=60)
fenetre.mainloop()
