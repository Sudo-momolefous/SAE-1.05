import re
import json
import tkinter as tk
from tkinter import filedialog, ttk
from collections import Counter
import webbrowser

# ---------------- pattern tcpdump
pattern = re.compile(
    r'(?P<time>\d{2}:\d{2}:\d{2})\.\d+\s+IP\s+'
    r'(?P<src>[^ ]+)\s+>\s+(?P<dst>[^:]+):.*length\s+(?P<length>\d+)'
)

# ---------------- extraction IP avec normalisation
def extraire_ip(champ):
    # Séparer le port s'il y a
    champ = champ.split(":")[0]
    # Supprimer suffixe HTTPS/HTTP
    champ = re.sub(r'\.https$', '', champ)
    champ = re.sub(r'\.http$', '', champ)
    # Supprimer un éventuel ".<num>" à la fin pour BP-Linux8.34862 → BP-Linux8
    champ = re.sub(r'\.\d+$', '', champ)
    return champ

# ---------------- lecture fichier
def lire_fichier(chemin):
    trames = []
    with open(chemin, "r", encoding="utf-8") as f:
        for ligne in f:
            m = pattern.search(ligne)
            if m:
                d = m.groupdict()
                trames.append({
                    "src": extraire_ip(d["src"])
                })
    return trames

# ---------------- analyse trames
def analyser(trames):
    src = Counter(t["src"] for t in trames)
    return src

# ---------------- détection menaces (IP source uniquement)
def detecter_menaces(src, total):
    seuil = max(10, int(total * 0.2))
    return {ip: nb for ip, nb in src.items() if nb >= seuil}

# ---------------- affichage Tkinter
def afficher_table(titre, compteur):
    fen = tk.Toplevel()
    fen.title(titre)
    tree = ttk.Treeview(fen, columns=("ip", "nb"), show="headings")
    tree.heading("ip", text="IP")
    tree.heading("nb", text="Nombre de requêtes")
    tree.pack(expand=True, fill="both")
    for ip, nb in compteur.most_common(20):
        tree.insert("", "end", values=(ip, nb))

# ---------------- génération dashboard HTML
def generer_dashboard(src, menaces):
    src10 = dict(src.most_common(10))

    html = f"""
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<title>Dashboard IP Source</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
body {{
 background:#0f172a;
 color:#e5e7eb;
 font-family:Arial;
 margin:0;
}}
section {{
 background:#020617;
 margin:20px;
 padding:20px;
 border-radius:12px;
}}
.chart-small {{
 max-width:500px;
 max-height:400px;
 margin:auto;
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
 margin-top:10px;
}}
th,td {{
 border:1px solid #334155;
 padding:8px;
 text-align:center;
}}
th {{ background:#1e293b; }}
.grid {{
 display:grid;
 grid-template-columns:1fr 1fr;
 gap:20px;
 justify-items:center;
}}
@media (max-width: 800px) {{
 .grid {{
   grid-template-columns:1fr;
 }}
}}
</style>
</head>
<body>

<section class="grid">
<canvas id="barChart" class="chart-small"></canvas>
<canvas id="pieChart" class="chart-small"></canvas>
</section>

<section>
<h3>Score des IP source (nombre de requêtes)</h3>
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
const menaces = {json.dumps(menaces)};
const colors = ['#3b82f6','#22c55e','#eab308','#ef4444','#a855f7','#14b8a6','#f97316','#ec4899','#84cc16','#06b6d4'];

let barChart=null,pieChart=null;

function draw(){{
 if(barChart) barChart.destroy();
 if(pieChart) pieChart.destroy();

 barChart = new Chart(document.getElementById("barChart"), {{
  type:'bar',
  data:{{
   labels:Object.keys(srcData),
   datasets:[{{label:'Nombre de requêtes', data:Object.values(srcData), backgroundColor:colors}}]
  }},
  options:{{responsive:true}}
 }});

 pieChart = new Chart(document.getElementById("pieChart"), {{
  type:'pie',
  data:{{
   labels:Object.keys(srcData),
   datasets:[{{data:Object.values(srcData), backgroundColor:colors}}]
  }},
  options:{{responsive:true}}
 }});
}}

let m=document.getElementById("menaces");
if(Object.keys(menaces).length===0){{
 m.innerHTML="<div class='alert'>Aucune menace détectée</div>";
}} else {{
 for(let ip in menaces){{
  let d=document.createElement("div");
  d.className="alert";
  d.textContent=ip+" → "+menaces[ip]+" requêtes";
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

# ---------------- lancement analyse
def lancer_analyse(chemin):
    trames = lire_fichier(chemin)
    if not trames:
        print("Aucune trame valide détectée")
        return

    src = analyser(trames)
    menaces = detecter_menaces(src, len(trames))

    afficher_table("IP source", src)

    generer_dashboard(src, menaces)
    webbrowser.open("dashboard.html")

# ---------------- interface fichier
def choisir():
    chemin = filedialog.askopenfilename(filetypes=[("txt","*.txt")])
    if chemin:
        root.destroy()
        lancer_analyse(chemin)

# ---------------- interface principale
root = tk.Tk()
root.title("Analyse trafic réseau")
root.geometry("400x200")
tk.Button(root,text="Choisir fichier TCPDump",command=choisir).pack(pady=60)
root.mainloop()
