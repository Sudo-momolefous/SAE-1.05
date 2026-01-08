import csv
import re
from collections import Counter
import matplotlib.pyplot as plt
import tkinter as tk
from tkinter import filedialog

# expression reguliere pour extraire les informations
pattern = re.compile(
    r'(?P<time>\d{2}:\d{2}:\d{2}\.\d+)\s+IP\s+'
    r'(?P<src>[^ ]+)\s+>\s+(?P<dst>[^:]+):'
    r'.*Flags\s+\[(?P<flags>[^\]]+)\].*length\s+(?P<length>\d+)'
)

def separer_ip_port(champ):
    # separe ip et port ou service
    parties = champ.rsplit('.', 1)
    if len(parties) == 2:
        return parties[0], parties[1]
    return champ, ""

def lire_fichier_txt(chemin):
    # lit le fichier txt et extrait les trames
    trames = []

    with open(chemin, "r", encoding="utf-8") as f:
        for ligne in f:
            match = pattern.search(ligne)
            if match:
                d = match.groupdict()
                src_ip, src_port = separer_ip_port(d["src"])
                dst_ip, dst_port = separer_ip_port(d["dst"])

                trames.append({
                    "time": d["time"],
                    "src_ip": src_ip,
                    "src_port": src_port,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "flags": d["flags"],
                    "length": d["length"]
                })

    return trames

def ecrire_csv(trames, chemin_csv):
    # cree le fichier csv
    with open(chemin_csv, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["time", "src_ip", "src_port", "dst_ip", "dst_port", "flags", "length"],
            delimiter=";"
        )
        writer.writeheader()
        writer.writerows(trames)

def analyser_ports(trames):
    # compte les ports de destination
    ports = [t["dst_port"] for t in trames if t["dst_port"] != ""]
    return Counter(ports)

def tracer_diagramme(compteur):
    # affiche le diagramme
    ports = list(compteur.keys())
    valeurs = list(compteur.values())

    plt.figure(figsize=(8, 4))
    plt.bar(ports, valeurs)
    plt.xlabel("port de destination")
    plt.ylabel("nombre de trames")
    plt.title("utilisation des ports reseau")
    plt.tight_layout()
    plt.show()

def generer_markdown(trames, compteur, chemin_md):
    # cree le fichier markdown
    total_trames = len(trames)
    port_plus_utilise, nb = compteur.most_common(1)[0]

    with open(chemin_md, "w", encoding="utf-8") as f:
        f.write("# analyse des trames reseau\n\n")
        f.write("## informations generales\n\n")
        f.write(f"- nombre total de trames analysees {total_trames}\n")
        f.write(f"- port le plus utilise {port_plus_utilise}\n")
        f.write(f"- nombre de trames sur ce port {nb}\n\n")

        f.write("## repartition des ports\n\n")
        f.write("| port | nombre de trames |\n")
        f.write("|------|------------------|\n")

        for port, nombre in compteur.items():
            f.write(f"| {port} | {nombre} |\n")

        f.write("\n## conclusion\n\n")
        f.write(
            "lanalyse met en evidence un port majoritairement utilise\n"
            "ce port peut etre responsable dune saturation reseau\n"
            "une verification des services associes est recommandee\n"
        )

def afficher_port_plus_utilise(compteur):
    port, nombre = compteur.most_common(1)[0]
    print(f"le port le plus utilise est le port {port} avec {nombre} trames")

def lancer_analyse(chemin_fichier):
    print("lecture du fichier txt")
    trames = lire_fichier_txt(chemin_fichier)

    print("creation du fichier csv")
    ecrire_csv(trames, "trames.csv")

    print("analyse des ports")
    compteur_ports = analyser_ports(trames)

    afficher_port_plus_utilise(compteur_ports)

    print("creation du fichier markdown")
    generer_markdown(trames, compteur_ports, "resultats.md")

    print("affichage du diagramme")
    tracer_diagramme(compteur_ports)

def choisir_fichier():
    chemin = filedialog.askopenfilename(
        title="selectionner un fichier",
        filetypes=[("fichier texte", "*.txt"), ("tous les fichiers", "*.*")]
    )

    if chemin:
        label_chemin.config(text=f"fichier selectionne {chemin}")
        fenetre.destroy()
        lancer_analyse(chemin)
    else:
        label_chemin.config(text="aucun fichier selectionne")

def quitter():
    fenetre.destroy()

# interface graphique
fenetre = tk.Tk()
fenetre.title("analyse de trames reseau")
fenetre.geometry("500x220")

btn_choisir = tk.Button(fenetre, text="choisir un fichier", command=choisir_fichier)
btn_choisir.pack(pady=20)

label_chemin = tk.Label(fenetre, text="aucun fichier selectionne", wraplength=460)
label_chemin.pack(pady=10)

btn_quitter = tk.Button(fenetre, text="quitter", command=quitter)
btn_quitter.pack(pady=10)

fenetre.mainloop()
