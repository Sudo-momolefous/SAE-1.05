import re
import csv
import json
import tkinter as tk
from tkinter import filedialog, ttk
from collections import Counter
import webbrowser

# ---------------- pattern tcpdump
pattern = re.compile(
    r'(?P<time>\d{2}:\d{2}:\d{2}\.\d+)\s+IP\s+'
    r'(?P<src>[^ ]+)\s+>\s+(?P<dst>[^:]+):'
    r'.*length\s+(?P<length>\d+)'
)

def extraire_ip(champ):
    champ = champ.split(":")[0]
    p = champ.rsplit(".",1)
    if p[-1].isdigit():
        return p[0]
    return champ

def lire_fichier(chemin):
    trames=[]
    with open(chemin,"r",encoding="utf-8") as f:
        for l in f:
            m=pattern.search(l)
            if m:
                d=m.groupdict()
                trames.append({
                    "src":extraire_ip(d["src"]),
                    "dst":extraire_ip(d["dst"]),
                    "length":int(d["length"])
                })
    return trames

def analyser(trames):
    src = Counter(t["src"] for t in trames)
    dst = Counter(t["dst"] for t in trames)
    return src, dst

def detecter_menaces(compteur, total):
    seuil = max(10, int(total*0.2))
    return {ip:nb for ip,nb in compteur.items() if nb>=seuil}

# ---------------- tkinter affichage
def afficher_table(titre, compteur):
    fen = tk.Toplevel()
    fen.title(titre)
    tree = ttk.Treeview(fen, columns=("ip","nb"), show="headings")
    tree.heading("ip", text="adresse ip")
    tree.heading("nb", text="occurrences")
    tree.pack(expand=True, fill="both")

    for ip,nb in compteur.most_common(20):
        tree.insert("", "end", values=(ip,nb))

def generer_dashboard(src, dst, menaces):
    html = f"""
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<title>dashboard securite reseau</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
body {{
 background:#0f172a;
 color:#e5e7eb;
 font-family:arial;
}}
section {{
 background:#020617;
 margin:20px;
 padding:20px;
 border-radius:12px;
}}
.grid {{
 display:grid;
 grid-template-columns:1fr 1fr;
 gap:20px;
}}
.alert {{
 background:#7f1d1d;
 padding:10px;
 border-radius:6px;
 margin-top:5px;
}}
</style>
</head>

<body>

<section>
<select id="type">
<option value="bar">barres</option>
<option value="pie">camembert</option>
</select>
<button onclick="draw()">appliquer</button>
</section>

<section class="grid">
<canvas id="src"></canvas>
<canvas id="dst"></canvas>
</section>

<section>
<h3>menaces potentielles</h3>
<div id="menaces"></div>
</section>

<script>
const srcData = {json.dumps(dict(src.most_common(10)))}
const dstData = {json.dumps(dict(dst.most_common(10)))}
const menaces = {json.dumps(menaces)}

let c1=null,c2=null

function draw(){{
 let t=document.getElementById("type").value
 if(c1) c1.destroy()
 if(c2) c2.destroy()

 c1=new Chart(src,{{
  type:t,
  data:{{labels:Object.keys(srcData),datasets:[{{data:Object.values(srcData)}}]}}
 }})

 c2=new Chart(dst,{{
  type:t,
  data:{{labels:Object.keys(dstData),datasets:[{{data:Object.values(dstData)}}]}}
 }})
}}

let m=document.getElementById("menaces")
if(Object.keys(menaces).length===0){{
 m.innerHTML="<div class='alert'>aucune menace evidente</div>"
}} else {{
 for(let ip in menaces){{
  let d=document.createElement("div")
  d.className="alert"
  d.textContent=ip+" "+menaces[ip]+" occurrences"
  m.appendChild(d)
 }}
}}
</script>

</body>
</html>
"""
    with open("dashboard.html","w",encoding="utf-8") as f:
        f.write(html)

def lancer_analyse(chemin):
    trames = lire_fichier(chemin)
    src,dst = analyser(trames)

    menaces = detecter_menaces(src,len(trames))
    generer_dashboard(src,dst,menaces)

    afficher_table("ip source", src)
    afficher_table("ip destination", dst)

    webbrowser.open("dashboard.html")

def choisir():
    chemin = filedialog.askopenfilename(filetypes=[("txt","*.txt")])
    if chemin:
        root.destroy()
        lancer_analyse(chemin)

root=tk.Tk()
root.title("analyse trafic reseau")
root.geometry("400x200")
tk.Button(root,text="choisir fichier",command=choisir).pack(pady=60)
root.mainloop()
