# V5.3_final_corrected.py
import csv
import re
import json
from collections import Counter
import matplotlib.pyplot as plt
import tkinter as tk
from tkinter import filedialog, simpledialog
import webbrowser
import os

# -----------------------------
# pattern pour extraire IP
pattern = re.compile(
    r'(?P<time>\d{2}:\d{2}:\d{2}\.\d+)\s+IP\s+'
    r'(?P<src>[^ ]+)\s+>\s+(?P<dst>[^:]+):'
    r'.*length\s+(?P<length>\d+)'
)

# -----------------------------
def extraire_ip(champ):
    if ':' in champ:
        return champ.split(':')[0]
    parties = champ.rsplit('.', 1)
    if parties[-1].isdigit():
        return parties[0]
    return champ

def lire_fichier_txt(chemin):
    trames = []
    if not os.path.exists(chemin):
        return trames
    with open(chemin,"r",encoding="utf-8") as f:
        for ligne in f:
            m = pattern.search(ligne)
            if m:
                d = m.groupdict()
                trames.append({
                    "time": d["time"],
                    "src_ip": extraire_ip(d["src"]),
                    "dst_ip": extraire_ip(d["dst"]),
                    "length": int(d["length"])
                })
    return trames

def ecrire_csv(trames):
    with open("trames.csv","w",newline="",encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f,fieldnames=["time","src_ip","dst_ip","length"],delimiter=";")
        writer.writeheader()
        writer.writerows(trames)

def analyser_ips(trames, champ):
    return Counter(t[champ] for t in trames)

def detecter_menaces_ips(compteur, total):
    menaces = {}
    seuil = max(10,int(total*0.2))
    for ip, nb in compteur.items():
        if nb >= seuil:
            menaces[ip] = nb
    return menaces

# -----------------------------
def generer_markdown(compteur_src, compteur_dst):
    with open("resultats.md","w",encoding="utf-8") as f:
        f.write("# Analyse des adresses IP\n\n")
        f.write("## IP source les plus presentes\n\n")
        for ip, nb in compteur_src.most_common(10):
            f.write(f"- {ip} : {nb}\n")
        f.write("\n## IP destination les plus presentes\n\n")
        for ip, nb in compteur_dst.most_common(10):
            f.write(f"- {ip} : {nb}\n")

# -----------------------------
def tracer_diagramme(compteur, titre):
    choix = simpledialog.askstring("Type de diagramme", f"Choisir type de diagramme pour {titre} (bar ou pie)")
    if choix not in ["bar","pie"]:
        choix = "bar"
    plt.figure(figsize=(8,4))
    if choix=="bar":
        plt.bar(compteur.keys(), compteur.values())
        plt.xticks(rotation=45, ha="right")
    else:
        plt.pie(compteur.values(), labels=list(compteur.keys()), autopct='%1.1f%%')
    plt.title(titre)
    plt.tight_layout()
    plt.show()

# -----------------------------
def generer_site(src_ips, dst_ips, menaces):
    # tout le JS est dans cette chaîne
    html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<title>Analyse trafic reseau</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
body {{ font-family: arial; background:#f4f4f4; margin:0; padding:0; }}
header {{ background:#2c3e50; color:white; padding:15px; text-align:center; font-size:1.2em; }}
.container {{ display:flex; flex-wrap: wrap; justify-content:space-around; padding:20px; }}
.graph {{ flex:1; min-width:350px; background:white; padding:20px; border-radius:10px; margin:10px; }}
.tableau {{ flex:1; min-width:250px; background:white; padding:20px; border-radius:10px; margin:10px; }}
h2 {{ margin-top:0; }}
table {{ border-collapse: collapse; width:100%; }}
th, td {{ border:1px solid #ddd; padding:8px; text-align:left; }}
th {{ background:#3498db; color:white; }}
ul {{ padding-left:20px; }}
select {{ margin-right:10px; }}
</style>
</head>
<body>

<header>Analyse du trafic reseau</header>

<section class="container">
  <div class="graph">
    <h2>Camembert / Bar IP</h2>
    <select id="typeGraph">
      <option value="bar">Barres</option>
      <option value="pie">Camembert</option>
    </select>
    <select id="typeIP" onchange="updateChart()">
      <option value="src">IP Source</option>
      <option value="dst">IP Destination</option>
    </select>
    <canvas id="chart"></canvas>
  </div>
  <div class="tableau">
    <h2>Tableau de score</h2>
    <table id="scoreTable"><tr><th>IP</th><th>Occurrences</th></tr></table>
    <h2>Menaces potentielles</h2>
    <ul id="menacesList"></ul>
  </div>
</section>

<script>
let srcData = {json.dumps(src_ips)}
let dstData = {json.dumps(dst_ips)}
let menaces = {json.dumps(menaces)}
let currentData = srcData

const ctx = document.getElementById('chart').getContext('2d')
let chart = new Chart(ctx,{{
    type:'bar',
    data:{{
        labels:Object.keys(currentData),
        datasets:[{{data:Object.values(currentData), backgroundColor:[
            '#e74c3c','#3498db','#2ecc71','#f1c40f','#9b59b6','#1abc9c','#e67e22','#34495e','#95a5a6','#16a085']}}]
    }}
}})

function updateChart(){{
    let typeG = document.getElementById('typeGraph').value
    let typeI = document.getElementById('typeIP').value
    currentData = (typeI=='src') ? srcData : dstData
    chart.config.type = typeG
    chart.data.labels = Object.keys(currentData)
    chart.data.datasets[0].data = Object.values(currentData)
    chart.update()
    updateTable()
}}

function updateTable(){{
    let table = document.getElementById('scoreTable')
    table.innerHTML='<tr><th>IP</th><th>Occurrences</th></tr>'
    Object.entries(currentData).sort((a,b)=>b[1]-a[1]).forEach(([ip,val])=>{
        let row = table.insertRow()
        row.insertCell(0).textContent = ip
        row.insertCell(1).textContent = val
    })
}}

function afficherMenaces(){{
    let ul = document.getElementById('menacesList')
    ul.innerHTML=''
    if(Object.keys(menaces).length===0){{
        ul.innerHTML='<li>Aucune menace evidente</li>'
    }} else {{
        for(let ip in menaces){{
            let li=document.createElement('li')
            li.textContent=ip + ' (' + menaces[ip] + ' occurrences)'
            ul.appendChild(li)
        }}
    }}
}}

updateTable()
afficherMenaces()
</script>

</body>
</html>"""
    with open("index.html","w",encoding="utf-8") as f:
        f.write(html)

def ouvrir_site():
    webbrowser.open("index.html", new=2)

# -----------------------------
def lancer_analyse(chemin):
    trames = lire_fichier_txt(chemin)
    if not trames:
        print("aucune trame")
        return

    ecrire_csv(trames)

    compteur_src = analyser_ips(trames,"src_ip")
    compteur_dst = analyser_ips(trames,"dst_ip")

    menaces_src = detecter_menaces_ips(compteur_src,len(trames))
    menaces_dst = detecter_menaces_ips(compteur_dst,len(trames))
    menaces = {**menaces_src, **menaces_dst}

    generer_markdown(compteur_src, compteur_dst)
    generer_site(
        dict(compteur_src.most_common(10)),
        dict(compteur_dst.most_common(10)),
        menaces
    )
    ouvrir_site()

    tracer_diagramme(compteur_src,"IP Source")
    tracer_diagramme(compteur_dst,"IP Destination")

# -----------------------------
def choisir_fichier():
    chemin = filedialog.askopenfilename(
        title="Selectionner un fichier",
        filetypes=[("Fichier texte","*.txt")]
    )
    if chemin:
        fenetre.destroy()
        lancer_analyse(chemin)

fenetre = tk.Tk()
fenetre.title("Analyse IP reseau")
fenetre.geometry("450x250")
tk.Button(fenetre,text="Choisir fichier",command=choisir_fichier).pack(pady=50)
fenetre.mainloop()
