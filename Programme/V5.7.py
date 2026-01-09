import re
import json
import tkinter as tk
from tkinter import filedialog, ttk
from collections import Counter
import webbrowser

# ---------------- pattern tcpdump
pattern = re.compile(
    r'(?P<time>\d{2}:\d{2}:\d{2})\.\d+\s+IP\s+'
    r'(?P<src>[^ ]+)\s+>\s+(?P<dst>[^:]+):'
    r'.*length\s+(?P<length>\d+)'
)

# ---------------- extraction IP robuste
def extraire_ip(champ):
    champ = champ.split(":")[0]
    parties = champ.split(".")
    if len(parties) > 4 and parties[-1].isdigit() and int(parties[-1]) > 255:
        return ".".join(parties[:-1])
    return champ

# ---------------- lecture fichier tcpdump
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
                    "length": int(d["length"])
                })
    return trames

# ---------------- analyse trames
def analyser(trames):
    src = Counter(t["src"] for t in trames)
    dst = Counter(t["dst"] for t in trames)
    return src, dst

# ---------------- détection menaces
def detecter_menaces(compteur, total):
    seuil = max(10, int(total * 0.2))
    return {ip: nb for ip, nb in compteur.items() if nb >= seuil}

# ---------------- affichage Tkinter
def afficher_table(titre, compteur):
    fen = tk.Toplevel()
    fen.title(titre)
    tree = ttk.Treeview(fen, columns=("ip", "nb"), show="headings")
    tree.heading("ip", text="Adresse IP")
    tree.heading("nb", text="Occurrences")
    tree.pack(expand=True, fill="both")

    for ip, nb in compteur.most_common(20):
        tree.insert("", "end", values=(ip, nb))

# ---------------- génération dashboard HTML
def generer_dashboard(src, dst, menaces):
    # tri des données par nombre de trames
    src_sorted = dict(sorted(src.items(), key=lambda x: x[1], reverse=True)[:10])
    dst_sorted = dict(sorted(dst.items(), key=lambda x: x[1], reverse=True)[:10])

    html = f"""
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<title>Dashboard sécurité réseau</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
body {{
 background:#0f172a;
 color:#e5e7eb;
 font-family:arial;
 margin:0;
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
canvas {{
 background:#1e293b;
 border-radius:8px;
 padding:10px;
}}
table {{
 width:100%;
 border-collapse: collapse;
 margin-top:10px;
}}
th, td {{
 border: 1px solid #334155;
 padding:8px;
 text-align:center;
}}
th {{
 background:#1e293b;
}}
</style>
</head>
<body>

<section>
<label>Type graphique:</label>
<select id="type">
<option value="bar">Barres</option>
<option value="pie">Camembert</option>
</select>
<button onclick="draw()">Appliquer</button>
</section>

<section class="grid">
<canvas id="srcChart"></canvas>
<canvas id="dstChart"></canvas>
</section>

<section>
<h3>Score des IP les plus actives</h3>
<table id="scoreTable">
<thead>
<tr><th>IP</th><th>Score</th></tr>
</thead>
<tbody>
</tbody>
</table>
</section>

<section>
<h3>Menaces potentielles</h3>
<div id="menaces"></div>
</section>

<script>
const srcData = {json.dumps(src_sorted)};
const dstData = {json.dumps(dst_sorted)};
const menaces = {json.dumps(detecter_menaces(src_sorted, sum(src_sorted.values())) )};

// graphiques
let srcChart=null, dstChart=null;

function draw(){{
 let t=document.getElementById("type").value;

 if(srcChart) srcChart.destroy();
 if(dstChart) dstChart.destroy();

 srcChart = new Chart(document.getElementById("srcChart"), {{
  type: t,
  data: {{labels:Object.keys(srcData), datasets:[{{label:'IP Source', data:Object.values(srcData), backgroundColor:'rgba(59, 130, 246,0.7)'}}]}},
  options: {{responsive:true}}
 }});

 dstChart = new Chart(document.getElementById("dstChart"), {{
  type: t,
  data: {{labels:Object.keys(dstData), datasets:[{{label:'IP Destination', data:Object.values(dstData), backgroundColor:'rgba(16, 185, 129,0.7)'}}]}},
  options: {{responsive:true}}
 }});
}}

// tableau score IP
let tbody = document.getElementById("scoreTable").querySelector("tbody");
for(let ip in srcData){{
 let tr = document.createElement("tr");
 let td1 = document.createElement("td");
 td1.textContent = ip;
 let td2 = document.createElement("td");
 td2.textContent = srcData[ip];
 tr.appendChild(td1);
 tr.appendChild(td2);
 tbody.appendChild(tr);
}}

// affichage menaces
let mdiv = document.getElementById("menaces");
if(Object.keys(menaces).length===0){{
 mdiv.innerHTML="<div class='alert'>Aucune menace détectée</div>";
}} else {{
 for(let ip in menaces){{
  let d=document.createElement("div");
  d.className="alert";
  d.textContent=ip+" : "+menaces[ip]+" occurrences";
  mdiv.appendChild(d);
 }}
}}

draw();
</script>

</body>
</html>
"""
    with open("dashboard.html", "w", encoding="utf-8") as f:
        f.write(html)

# ---------------- lancement analyse
def lancer_analyse(chemin):
    trames = lire_fichier(chemin)
    if not trames:
        print("Aucune trame valide détectée")
        return

    src, dst = analyser(trames)
    menaces = detecter_menaces(src, len(trames))

    afficher_table("IP source les plus actives", src)
    afficher_table("IP destination les plus sollicitées", dst)

    generer_dashboard(src, dst, menaces)

    webbrowser.open("dashboard.html")

# ---------------- interface fichier
def choisir_fichier():
    chemin = filedialog.askopenfilename(
        title="Sélectionner fichier TCPDump",
        filetypes=[("Fichier texte", "*.txt")]
    )
    if chemin:
        root.destroy()
        lancer_analyse(chemin)

# ---------------- interface principale
root = tk.Tk()
root.title("Analyse trafic réseau")
root.geometry("400x200")

tk.Button(root, text="Choisir fichier TCPDump", command=choisir_fichier).pack(pady=60)

root.mainloop()
