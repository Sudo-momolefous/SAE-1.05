import re
import json
import tkinter as tk
from tkinter import filedialog, ttk
from collections import Counter
import webbrowser

# -------- pattern tcpdump
pattern = re.compile(
    r'(?P<time>\d{2}:\d{2}:\d{2})\.\d+\s+IP\s+'
    r'(?P<src>[^ ]+)\s+>\s+(?P<dst>[^:]+):.*length\s+(?P<length>\d+)'
)

def extraire_ip(champ):
    return champ.split(":")[0]

def lire_fichier(chemin):
    trames = []
    with open(chemin, "r", encoding="utf-8") as f:
        for ligne in f:
            m = pattern.search(ligne)
            if m:
                d = m.groupdict()
                trames.append({
                    "src": extraire_ip(d["src"]),
                    "dst": extraire_ip(d["dst"])
                })
    return trames

def analyser(trames):
    src = Counter(t["src"] for t in trames)
    dst = Counter(t["dst"] for t in trames)
    return src, dst

def detecter_menaces(src, total):
    seuil = max(10, int(total * 0.2))
    return {ip: nb for ip, nb in src.items() if nb >= seuil}

def afficher_table(titre, compteur):
    fen = tk.Toplevel()
    fen.title(titre)
    tree = ttk.Treeview(fen, columns=("ip", "nb"), show="headings")
    tree.heading("ip", text="IP")
    tree.heading("nb", text="Occurrences")
    tree.pack(expand=True, fill="both")
    for ip, nb in compteur.most_common(20):
        tree.insert("", "end", values=(ip, nb))

def generer_dashboard(src, dst, menaces):
    src10 = dict(src.most_common(10))
    dst10 = dict(dst.most_common(10))

    html = f"""
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<title>Dashboard Sécurité Réseau</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
body {{
 background:#0f172a;
 color:#e5e7eb;
 font-family:Arial;
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
 margin-top:6px;
}}
table {{
 width:100%;
 border-collapse:collapse;
}}
th,td {{
 border:1px solid #334155;
 padding:8px;
 text-align:center;
}}
th {{ background:#1e293b; }}

.pie-small {{
 max-width:300px;
 max-height:300px;
 margin:auto;
}}
</style>
</head>
<body>

<section>
<select id="type">
<option value="bar">Barres</option>
<option value="pie">Camembert</option>
</select>
<button onclick="draw()">Appliquer</button>
</section>

<section class="grid">
<canvas id="srcChart" class="pie-small"></canvas>
<canvas id="dstChart"></canvas>
</section>

<section>
<h3>Score des IP source les plus actives</h3>
<table>
<tr><th>IP source</th><th>Score</th></tr>
{''.join(f"<tr><td>{ip}</td><td>{nb}</td></tr>" for ip,nb in src10.items())}
</table>
</section>

<section>
<h3>Menaces détectées (IP source uniquement)</h3>
<div id="menaces"></div>
</section>

<script>
const srcData = {json.dumps(src10)};
const dstData = {json.dumps(dst10)};
const menaces = {json.dumps(menaces)};

const colors = [
 '#3b82f6','#22c55e','#eab308','#ef4444',
 '#a855f7','#14b8a6','#f97316','#ec4899',
 '#84cc16','#06b6d4'
];

let c1=null,c2=null;

function draw(){{
 let t=document.getElementById("type").value;
 if(c1) c1.destroy();
 if(c2) c2.destroy();

 c1=new Chart(srcChart,{{
  type:t,
  data:{{
   labels:Object.keys(srcData),
   datasets:[{{data:Object.values(srcData),backgroundColor:colors}}]
  }}
 }});

 c2=new Chart(dstChart,{{
  type:t,
  data:{{
   labels:Object.keys(dstData),
   datasets:[{{data:Object.values(dstData),backgroundColor:colors}}]
  }}
 }});
}}

let m=document.getElementById("menaces");
if(Object.keys(menaces).length===0){{
 m.innerHTML="<div class='alert'>Aucune menace détectée</div>";
}} else {{
 for(let ip in menaces){{
  let d=document.createElement("div");
  d.className="alert";
  d.textContent=ip+" → "+menaces[ip]+" trames";
  m.appendChild(d);
 }}
}}

draw();
</script>
</body>
</html>
"""
    with open("dashboard.html","w",encoding="utf-8") as f:
        f.write(html)

def lancer_analyse(chemin):
    trames = lire_fichier(chemin)
    src, dst = analyser(trames)
    menaces = detecter_menaces(src, len(trames))

    afficher_table("IP source", src)
    afficher_table("IP destination", dst)

    generer_dashboard(src, dst, menaces)
    webbrowser.open("dashboard.html")

def choisir():
    chemin = filedialog.askopenfilename(filetypes=[("txt","*.txt")])
    if chemin:
        root.destroy()
        lancer_analyse(chemin)

root = tk.Tk()
root.title("Analyse trafic réseau")
root.geometry("400x200")
tk.Button(root,text="Choisir fichier TCPDump",command=choisir).pack(pady=60)
root.mainloop()
