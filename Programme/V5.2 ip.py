# analyse_reseau_ip_complete.py
import csv
import re
import json
from collections import Counter
import matplotlib.pyplot as plt
import tkinter as tk
from tkinter import filedialog
import webbrowser
import os

# -----------------------------
# pattern extraction tcpdump
pattern = re.compile(
    r'(?P<time>\d{2}:\d{2}:\d{2}\.\d+)\s+IP\s+'
    r'(?P<src>[^ ]+)\s+>\s+(?P<dst>[^:]+):'
    r'.*length\s+(?P<length>\d+)'
)

# -----------------------------
def extraire_ip(champ):
    # supprime port si present
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
    with open(chemin, "r", encoding="utf-8") as f:
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
    with open("trames.csv", "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["time","src_ip","dst_ip","length"],
            delimiter=";"
        )
        writer.writeheader()
        writer.writerows(trames)

def analyser_ips(trames, champ):
    return Counter(t[champ] for t in trames)

def detecter_menaces_ips(compteur, total):
    menaces = {}
    seuil = max(10, int(total * 0.2))
    for ip, nb in compteur.items():
        if nb >= seuil:
            menaces[ip] = nb
    return menaces

# -----------------------------
def generer_markdown(compteur_src, compteur_dst):
    with open("resultats.md", "w", encoding="utf-8") as f:
        f.write("# analyse des adresses ip\n\n")
        f.write("## ip source les plus presentes\n\n")
        for ip, nb in compteur_src.most_common(10):
            f.write(f"- {ip} : {nb}\n")
        f.write("\n## ip destination les plus presentes\n\n")
        for ip, nb in compteur_dst.most_common(10):
            f.write(f"- {ip} : {nb}\n")

# -----------------------------
def tracer_diagramme(compteur, titre):
    plt.figure(figsize=(8,4))
    plt.bar(compteur.keys(), compteur.values())
    plt.xticks(rotation=45, ha="right")
    plt.title(titre)
    plt.tight_layout()
    plt.show()

# -----------------------------
def generer_site(src_ips, dst_ips, menaces):
    html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<title>analyse trafic reseau</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
body {{ font-family: arial; background:#f4f4f4 }}
section {{ background:white; padding:15px; margin:20px; border-radius:8px }}
</style>
</head>
<body>

<section>
<h2>ip source les plus frequentes</h2>
<canvas id="src"></canvas>
</section>

<section>
<h2>ip destination les plus frequentes</h2>
<canvas id="dst"></canvas>
</section>

<section>
<h2>menaces potentielles</h2>
<ul id="menaces"></ul>
</section>

<script>
const srcData = {json.dumps(src_ips)}
const dstData = {json.dumps(dst_ips)}
const menaces = {json.dumps(menaces)}

function draw(id, data) {{
 new Chart(document.getElementById(id), {{
  type:'bar',
  data:{{
   labels:Object.keys(data),
   datasets:[{{data:Object.values(data)}}]
  }}
 }})
}}

draw("src", srcData)
draw("dst", dstData)

let ul = document.getElementById("menaces")
if(Object.keys(menaces).length===0){{
 ul.innerHTML="<li>aucune menace evidente</li>"
}} else {{
 for(let ip in menaces){{
  let li=document.createElement("li")
  li.textContent = ip + " (" + menaces[ip] + " occurrences)"
  ul.appendChild(li)
 }}
}}
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

    tracer_diagramme(compteur_src,"ip source")
    tracer_diagramme(compteur_dst,"ip destination")

# -----------------------------
def choisir_fichier():
    chemin = filedialog.askopenfilename(
        title="selectionner un fichier",
        filetypes=[("fichier texte","*.txt")]
    )
    if chemin:
        fenetre.destroy()
        lancer_analyse(chemin)

fenetre = tk.Tk()
fenetre.title("analyse ip reseau")
fenetre.geometry("400x200")

tk.Button(fenetre,text="choisir fichier",command=choisir_fichier).pack(pady=40)
fenetre.mainloop()
