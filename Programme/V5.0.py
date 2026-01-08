# analyse_reseau_gui_web.py
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
    # separe ip et port ou service
    parties = champ.rsplit('.', 1)
    if len(parties) == 2:
        return parties[0], parties[1]
    return champ, ""

def lire_fichier_txt(chemin):
    # lit le fichier txt et extrait les trames
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
    # cree le fichier csv
    with open(chemin_csv, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["time","src_ip","src_port","dst_ip","dst_port","flags","length"],
            delimiter=";"
        )
        writer.writeheader()
        writer.writerows(trames)

def analyser_ports(trames):
    # compte les ports de destination
    ports = [t["dst_port"] for t in trames if t["dst_port"] != ""]
    return Counter(ports)

def detecter_menaces(trames):
    # detecte menaces simples
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

def exporter_json(trames):
    # exporte fichiers json pour site web
    ports = dict(analyser_ports(trames))
    menaces = detecter_menaces(trames)
    with open("donnees_ports.json","w",encoding="utf-8") as f:
        json.dump(ports,f)
    with open("menaces.json","w",encoding="utf-8") as f:
        json.dump(menaces,f)
    print("fichiers json generes")

# -----------------------------
# fonctions site web

def generer_site():
    # genere fichier html simple
    html_content = """<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<title>analyse trafic reseau</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
body { font-family: arial; background-color: #f5f5f5; }
section { background: white; padding: 15px; margin: 20px; border-radius: 8px; }
</style>
</head>
<body>

<section>
<h2>options affichage</h2>
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
let portsData = {}
let menacesData = []

fetch("donnees_ports.json")
.then(r => r.json())
.then(d => portsData = d)

fetch("menaces.json")
.then(r => r.json())
.then(d => {menacesData=d;afficherMenaces()})

let chart = null
function dessiner(){
    let type=document.getElementById("typeGraph").value
    let ctx=document.getElementById("graphique")
    if(chart) chart.destroy()
    chart=new Chart(ctx,{
        type:type,
        data:{labels:Object.keys(portsData),
        datasets:[{label:"nombre paquets par port",data:Object.values(portsData),backgroundColor:"rgba(75,192,192,0.5)"}]}
    })
}
function afficherMenaces(){
    let ul=document.getElementById("menaces")
    ul.innerHTML=""
    menacesData.forEach(m=>{
        let li=document.createElement("li")
        li.textContent=m
        ul.appendChild(li)
    })
}
</script>

</body>
</html>"""
    with open("index.html","w",encoding="utf-8") as f:
        f.write(html_content)
    print("fichier html genere")

def ouvrir_site():
    webbrowser.open("index.html",new=2)
    print("ouverture site dans le navigateur")

# -----------------------------
# fonctions rapport markdown

def generer_markdown(trames, compteur, chemin_md):
    total_trames=len(trames)
    port_plus_utilise, nb=compteur.most_common(1)[0]
    with open(chemin_md,"w",encoding="utf-8") as f:
        f.write("# analyse des trames reseau\n\n")
        f.write("## informations generales\n\n")
        f.write(f"- nombre total de trames analysees {total_trames}\n")
        f.write(f"- port le plus utilise {port_plus_utilise}\n")
        f.write(f"- nombre de trames sur ce port {nb}\n\n")
        f.write("## repartition des ports\n\n")
        f.write("| port | nombre de trames |\n")
        f.write("|------|------------------|\n")
        for port,nombre in compteur.items():
            f.write(f"| {port} | {nombre} |\n")
        f.write("\n## conclusion\n\n")
        f.write("lanalyse met en evidence un port majoritairement utilise\nce port peut etre responsable dune saturation reseau\nune verification des services associes est recommande\n")

# -----------------------------
# fonctions diagramme matplotlib

def tracer_diagramme(compteur):
    ports=list(compteur.keys())
    valeurs=list(compteur.values())
    plt.figure(figsize=(8,4))
    plt.bar(ports,valeurs)
    plt.xlabel("port de destination")
    plt.ylabel("nombre de trames")
    plt.title("utilisation des ports reseau")
    plt.tight_layout()
    plt.show()

def afficher_port_plus_utilise(compteur):
    port,nombre=compteur.most_common(1)[0]
    print(f"le port le plus utilise est {port} avec {nombre} trames")

# -----------------------------
# fonction principale

def lancer_analyse(chemin_fichier):
    print("lecture du fichier")
    trames=lire_fichier_txt(chemin_fichier)

    if not trames:
        print("aucune trame trouvee")
        return

    print("creation du csv")
    ecrire_csv(trames,"trames.csv")

    print("analyse des ports")
    compteur_ports=analyser_ports(trames)
    afficher_port_plus_utilise(compteur_ports)

    print("creation du markdown")
    generer_markdown(trames,compteur_ports,"resultats.md")

    print("creation des fichiers json")
    exporter_json(trames)

    print("creation du site web")
    generer_site()

    print("ouverture du site web")
    ouvrir_site()

    print("affichage du diagramme")
    tracer_diagramme(compteur_ports)

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
