import re
import json
import csv
import unicodedata
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
    champ = champ.split(":")[0]          # enlever le port
    champ = re.sub(r'\.https$', '', champ)
    champ = re.sub(r'\.http$', '', champ)
    champ = re.sub(r'\.\d+$', '', champ) # BP-Linux8.34862 → BP-Linux8
    return champ

# ---------------- normalisation texte (minuscules, sans accents ni ponctuation)
def normaliser_texte(text):
    text = text.lower()
    text = ''.join(c for c in unicodedata.normalize('NFD', text) if unicodedata.category(c) != 'Mn')
    text = ''.join(c if c.isalnum() or c.isspace() else '' for c in text)
    text = ' '.join(text.split())
    return text

# ---------------- lecture fichier
def lire_fichier(chemin):
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
                    "length": d["length"]
                })
    return trames

# ---------------- sauvegarde CSV
def sauvegarder_csv(trames, chemin_csv="trames.csv"):
    champs = ["time", "src", "dst", "length"]
    with open(chemin_csv, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=champs)
        writer.writeheader()
        for t in trames:
            writer.writerow({
                "time": t["time"],
                "src": normaliser_texte(t["src"]),
                "dst": normaliser_texte(t["dst"]),
                "length": t["length"]
            })
    print(f"CSV créé : {chemin_csv}")

# ---------------- analyse trames
def analyser(trames):
    src = Counter(t["src"] for t in trames)
    return src

# ---------------- détection menaces
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
    html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<title>Dashboard IP Source</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
:root {{
  --bg-color: #0f172a;
  --bg-section: #020617;
  --text-color: #e5e7eb;
  --alert-bg: #7f1d1d;
  --th-bg: #1e293b;
}}
body {{
 background: var(--bg-color);
 color: var(--text-color);
 font-family: Arial;
 margin:0;
}}
nav {{
 background: #1e293b;
 padding: 12px 20px;
 display: flex;
 justify-content: space-between;
 align-items: center;
}}
nav h1 {{ margin:0; font-size: 1.2em; }}
button {{
 padding:6px 12px;
 border:none;
 border-radius:6px;
 cursor:pointer;
}}
section {{
 background: var(--bg-section);
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
 background: var(--alert-bg);
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
th {{ background: var(--th-bg); }}
.grid {{
 display:grid;
 grid-template-columns:1fr 1fr;
 gap:20px;
 justify-items:center;
}}
@media (max-width: 800px) {{
 .grid {{ grid-template-columns:1fr; }}
}}
</style>
</head>
<body>

<nav>
  <h1>Dashboard</h1>
  <button id="modeBtn">Mode Clair</button>
</nav>

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
<label for="limitMenaces">Nombre de menaces à afficher: </label>
<input type="number" id="limitMenaces" min="1" max="50" value="10" style="width:60px"/>
<button onclick="updateMenaces()">Afficher</button>
<div id="menaces"></div>
</section>

<script>
let darkMode = true;
const modeBtn = document.getElementById("modeBtn");
modeBtn.onclick = function(){{
  darkMode=!darkMode;
  if(darkMode){{
    document.body.style.background='#0f172a';
    document.body.style.color='#e5e7eb';
    document.querySelectorAll('section').forEach(s=>s.style.background='#020617');
    document.querySelectorAll('.alert').forEach(a=>a.style.background='#7f1d1d');
    document.querySelectorAll('th').forEach(th=>th.style.background='#1e293b');
    modeBtn.textContent="Mode Clair";
  }} else {{
    document.body.style.background='#f8fafc';
    document.body.style.color='#1e293b';
    document.querySelectorAll('section').forEach(s=>s.style.background='#ffffff');
    document.querySelectorAll('.alert').forEach(a=>a.style.background='#f87171');
    document.querySelectorAll('th').forEach(th=>th.style.background='#e5e7eb');
    modeBtn.textContent="Mode Sombre";
  }}
}}

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

// ---------------- correction bouton pour afficher les menaces en ordre décroissant
function updateMenaces(){{
    let limit = parseInt(document.getElementById("limitMenaces").value);
    let m = document.getElementById("menaces");
    m.innerHTML = "";
    let entries = Object.entries(menaces)
                        .sort((a,b)=>b[1]-a[1])  // ordre décroissant
                        .slice(0, limit);
    if(entries.length===0){{
      m.innerHTML="<div class='alert'>Aucune menace détectée</div>";
    }} else {{
      for(let [ip, nb] of entries){{
        let d=document.createElement("div");
        d.className="alert";
        d.textContent=ip+" → "+nb+" requêtes";
        m.appendChild(d);
      }}
    }}
}}

updateMenaces();
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

    # création CSV complet
    sauvegarder_csv(trames, "trames.csv")

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
