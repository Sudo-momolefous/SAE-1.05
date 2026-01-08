# analyse_reseau_ports_complets.py
import csv
import re
import json
from collections import Counter, defaultdict
import matplotlib.pyplot as plt
import tkinter as tk
from tkinter import filedialog
import webbrowser
import os

# -----------------------------
# pattern pour extraire les informations
pattern = re.compile(
    r'(?P<time>\d{2}:\d{2}:\d{2}\.\d+)\s+IP\s+'
    r'(?P<src>[^ ]+)\s+>\s+(?P<dst>[^:]+):'
    r'.*Flags\s+\[(?P<flags>[^\]]+)\].*length\s+(?P<length>\d+)'
)

# -----------------------------
# fonctions d'analyse
def separer_ip_port(champ):
    # separe ip et port correctement
    if ':' in champ:
        ip, port = champ.split(':', 1)
        return ip, port
    parties = champ.rsplit('.', 1)
    if len(parties) == 2 and parties[1].isdigit():
        return parties[0], parties[1]
    return champ, ""

def lire_fichier_txt(chemin):
    trames = []
    if not os.path.exists(chemin):
        print("fichier non trouve")
        return trames
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
                    "length": int(d["length"])
                })
    return trames

def ecrire_csv(trames, chemin_csv):
    with open(chemin_csv, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["time","src_ip","src_port","dst_ip","dst_port","flags","length"],
            delimiter=";"
        )
        writer.writeheader()
        writer.writerows(trames)

def analyser_ports(trames, champ):
    # champ = "src_port" ou "dst_port"
    ports = [t[champ] for t in trames if t[champ] != ""]
    return Counter(ports)

def detecter_menaces(trames):
    alertes = []
    syn_count = defaultdict(int)
    trafic_ssh = defaultdict(int)
    for t in trames:
        if t["flags"] == "S":
            syn_count[t["src_ip"]] += 1
        if t["dst_port"] in ("ssh","22"):
            trafic_ssh[t["src_ip"]] += t["length"]
    for ip, nb in syn_count.items():
        if nb > 10:
            alertes.append("suspicion scan syn depuis "+ip)
    for ip, vol in trafic_ssh.items():
        if vol > 2000:
            alertes.append("trafic ssh important depuis "+ip)
    if not alertes:
        alertes.append("aucune menace detectee")
    return alertes

# -----------------------------
# rapport markdown
def generer_markdown(trames, compteur, champ, chemin_md):
    total_trames = len(trames)
    port_plus_utilise, nb = compteur.most_common(1)[0]
    champ_nom = "port source" if champ=="src_port" else "port destination"
    with open(chemin_md,"w",encoding="utf-8") as f:
        f.write("# analyse des trames reseau\n\n")
        f.write("## informations generales\n\n")
        f.write(f"- nombre total de trames analysees {total_trames}\n")
        f.write(f"- {champ_nom} le plus utilise {port_plus_utilise}\n")
        f.write(f"- nombre de trames sur ce port {nb}\n\n")
        f.write("## repartition des ports\n\n")
        f.write(f"| {champ_nom} | nombre de trames |\n")
        f.write("|------|------------------|\n")
        for port,nombre in compteur.items():
            f.write(f"| {port} | {nombre} |\n")
        f.write("\n## conclusion\n\n")
        f.write(f"lanalyse met en evidence un {champ_nom} majoritairement utilise\n")

# -----------------------------
# diagramme matplotlib
def tracer_diagramme(compteur, champ):
    ports=list(compteur.keys())
    valeurs=list(compteur.values())
    plt.figure(figsize=(8,4))
    plt.bar(ports,valeurs)
    plt.xlabel(champ)
    plt.ylabel("nombre de trames")
    plt.title(f"utilisation des {champ}")
    plt.tight_layout()
    plt.show()

def afficher_port_plus_utilise(compteur, champ):
    port,nombre = compteur.most_common(1)[0]
    print(f"le {champ} le plus utilise est {port} avec {nombre} trames")

# -----------------------------
# site web avec onglets port source / destination
def generer_site(src_ports, dst_ports, menaces):
    html_content = f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<title>analyse trafic reseau</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
body {{ font-family: arial; background-color: #f5f5f5; }}
section {{ background: white; padding: 15px; margin: 20px; border-radius: 8px; }}
button.tab {{ margin-right:10px; }}
</style>
</head>
<body>

<section>
<h2>choisir graphique</h2>
<button class="tab" onclick="choisirPort('src')">port source</button>
<button class="tab" onclick="choisirPort('dst')">port destination</button>
<select id="typeGraph">
<option value="bar">diagramme en barres</option>
<option value="pie">camembert</option>
</select>
<button onclick="dessiner()">afficher</button>
</section>

<section>
<canvas id="graphique"></canvas>
</section>

<section>
<h2>menaces detectees</h2>
<ul id="menaces"></ul>
</section>

<script>
let srcPorts = {json.dumps(src_ports)}
let dstPorts = {json.dumps(dst_ports)}
let menacesData = {json.dumps(menaces)}

let currentPorts = srcPorts
let chart = null

function choisirPort(type) {{
    currentPorts = (type=='src') ? srcPorts : dstPorts
    dessiner()
}}

function dessiner(){{
    let type = document.getElementById("typeGraph").value
    let ctx = document.getElementById("graphique")
    if(chart) chart.destroy()
    chart = new Chart(ctx,{{
        type:type,
        data:{{
            labels:Object.keys(currentPorts),
            datasets:[{{label:"nombre paquets par port",data:Object.values(currentPorts)}}]
        }}
    }})
}}

function afficherMenaces(){{
    let ul=document.getElementById("menaces")
    ul.innerHTML=""
    menacesData.forEach(m=>{{
        let li=document.createElement("li")
        li.textContent=m
        ul.appendChild(li)
    }})
}}

afficherMenaces()
</script>

</body>
</html>"""
    with open("index.html","w",encoding="utf-8") as f:
        f.write(html_content)
    print("fichier html genere")

def ouvrir_site():
    webbrowser.open("index.html", new=2)
    print("ouverture site web dans le navigateur")

# -----------------------------
# fonction principale
def lancer_analyse(chemin_fichier):
    print("lecture du fichier")
    trames = lire_fichier_txt(chemin_fichier)
    if not trames:
        print("aucune trame trouvee")
        return

    print("creation du csv")
    ecrire_csv(trames,"trames.csv")

    print("analyse des ports source")
    compteur_src = analyser_ports(trames,"src_port")
    afficher_port_plus_utilise(compteur_src,"port source")

    print("analyse des ports destination")
    compteur_dst = analyser_ports(trames,"dst_port")
    afficher_port_plus_utilise(compteur_dst,"port destination")

    print("creation du markdown")
    generer_markdown(trames,compteur_src,"src_port","resultats_src.md")
    generer_markdown(trames,compteur_dst,"dst_port","resultats_dst.md")

    print("detection des menaces")
    menaces = detecter_menaces(trames)
    print("menaces detectees :", menaces)

    print("creation du site web")
    generer_site(dict(compteur_src), dict(compteur_dst), menaces)
    ouvrir_site()

    print("affichage du diagramme")
    tracer_diagramme(compteur_src,"port source")
    tracer_diagramme(compteur_dst,"port destination")

# -----------------------------
# interface graphique
def choisir_fichier():
    chemin=filedialog.askopenfilename(
        title="selectionner un fichier",
        filetypes=[("fichier texte","*.txt"),("tous les fichiers","*.*")]
    )
    if chemin:
        label_chemin.config(text="fichier selectionne "+chemin)
        fenetre.destroy()
        lancer_analyse(chemin)
    else:
        label_chemin.config(text="aucun fichier selectionne")

def quitter():
    fenetre.destroy()

fenetre=tk.Tk()
fenetre.title("analyse de trames reseau")
fenetre.geometry("500x250")

btn_choisir=tk.Button(fenetre,text="choisir un fichier",command=choisir_fichier)
btn_choisir.pack(pady=20)

label_chemin=tk.Label(fenetre,text="aucun fichier selectionne",wraplength=460)
label_chemin.pack(pady=10)

btn_quitter=tk.Button(fenetre,text="quitter",command=quitter)
btn_quitter.pack(pady=10)

fenetre.mainloop()
