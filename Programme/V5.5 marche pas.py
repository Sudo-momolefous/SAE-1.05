import re
import csv
import json
import tkinter as tk
from tkinter import filedialog, ttk
from collections import Counter
import webbrowser

# -----------------------------
# pattern tcpdump
pattern = re.compile(
    r'(?P<time>\d{2}:\d{2}:\d{2})\.\d+\s+IP\s+'
    r'(?P<src>[^ ]+)\s+>\s+(?P<dst>[^:]+):'
    r'.*length\s+(?P<length>\d+)'
)

# -----------------------------
def extraire_ip(champ):
    champ = champ.split(":")[0]
    p = champ.rsplit(".", 1)
    if p[-1].isdigit():
        return p[0]
    return champ

def lire_fichier_txt(chemin):
    trames = []
    with open(chemin, "r", encoding="utf-8") as f:
        for ligne in f:
            m = pattern.search(ligne)
            if m:
                d = m.groupdict()
                trames.append({
                    "time": d["time"],
                    "src": extraire_ip(d["src"]),
                    "dst": extraire_ip(d["dst"]),
                    "length": int(d["length"])
                })
    return trames

# -----------------------------
def analyser_trames(trames):
    src = Counter(t["src"] for t in trames)
    dst = Counter(t["dst"] for t in trames)
    heures = Counter(t["time"][:2] for t in trames)
    return src, dst, heures

# -----------------------------
def detecter_menaces(compteur, total):
    seuil = max(10, int(total * 0.2))
    menaces = []
    for ip, nb in compteur.items():
        if nb >= seuil:
            menaces.append(f"activite suspecte depuis {ip} ({nb} trames)")
    return menaces

# -----------------------------
def afficher_table(titre, compteur):
    fen = tk.Toplevel()
    fen.title(titre)
    fen.geometry("400x400")

    tree = ttk.Treeview(fen, columns=("ip", "nb"), show="headings")
    tree.heading("ip", text="adresse ip")
    tree.heading("nb", text="occurrences")
    tree.pack(expand=True, fill="both")

    for ip, nb in compteur.most_common(20):
        tree.insert("", "end", values=(ip, nb))

# -----------------------------
def generer_dashboard(src, dst, heures, menaces):
    with open("dashboard.html", "r", encoding="utf-8") as f:
        html = f.read()

    html = html.replace("SRC_DATA", json.dumps(dict(src.most_common(10))))
    html = html.replace("DST_DATA", json.dumps(dict(dst.most_common(10))))
    html = html.replace("TIME_DATA", json.dumps(dict(heures)))
    html = html.replace("ALERTS_DATA", json.dumps(menaces))

    with open("dashboard_genere.html", "w", encoding="utf-8") as f:
        f.write(html)

# -----------------------------
def lancer_analyse(chemin):
    trames = lire_fichier_txt(chemin)

    if not trames:
        print("aucune trame valide detectee")
        return

    src, dst, heures = analyser_trames(trames)
    menaces = detecter_menaces(src, len(trames))

    afficher_table("ip source les plus actives", src)
    afficher_table("ip destination les plus sollicitees", dst)

    generer_dashboard(src, dst, heures, menaces)

    webbrowser.open("dashboard_genere.html")

# -----------------------------
def choisir_fichier():
    chemin = filedialog.askopenfilename(
        title="selectionner un fichier tcpdump",
        filetypes=[("fichier texte", "*.txt")]
    )
    if chemin:
        root.destroy()
        lancer_analyse(chemin)

# -----------------------------
# interface principale
root = tk.Tk()
root.title("analyse trafic reseau")
root.geometry("400x200")

tk.Button(
    root,
    text="choisir fichier tcpdump",
    command=choisir_fichier
).pack(pady=60)

root.mainloop()
