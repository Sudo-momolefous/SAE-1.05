import csv

def lire_ics_complet(chemin_fichier):
    with open(chemin_fichier, "r", encoding="utf-8") as f:
        lignes = f.readlines()

    lignes_reconstruites = []
    for ligne in lignes:
        ligne = ligne.rstrip("\n")
        if ligne.startswith(" "):
            lignes_reconstruites[-1] += ligne[1:]
        else:
            lignes_reconstruites.append(ligne)

    evenements = []
    event = {}

    for ligne in lignes_reconstruites:

        if ligne.startswith("BEGIN:VEVENT"):
            event = {}

        elif ligne.startswith("SUMMARY:"):
            event["SUMMARY"] = ligne[8:].strip()

        elif ligne.startswith("DESCRIPTION:"):
            desc = ligne[12:].strip()
            desc = desc.replace("\\n", " ").replace("\n", " ").strip()
            event["DESCRIPTION"] = desc

        elif ligne.startswith("DTSTART:"):
            event["DTSTART"] = ligne[8:].strip()

        elif ligne.startswith("DTEND:"):
            event["DTEND"] = ligne[6:].strip()

        elif ligne.startswith("LOCATION:"):
            event["LOCATION"] = ligne[9:].strip()

        elif ligne.startswith("CATEGORIES:"):
            event["CATEGORIES"] = ligne[11:].strip()

        elif ligne.startswith("UID:"):
            event["UID"] = ligne[4:].strip()

        elif ligne.startswith("END:VEVENT"):
            evenements.append(event)

    return evenements


def creer_csv_depuis_ics(chemin_ics, chemin_csv):
    evenements = lire_ics_complet(chemin_ics)

    print("Nombre d'événements lus :", len(evenements)) 

    with open(chemin_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f, delimiter=";")

        writer.writerow(["SUMMARY", "DESCRIPTION", "DTSTART", "DTEND", "LOCATION", "CATEGORIES", "UID"])

        for ev in evenements:
            writer.writerow([
                ev.get("SUMMARY", ""),
                ev.get("DESCRIPTION", ""),
                ev.get("DTSTART", ""),
                ev.get("DTEND", ""),
                ev.get("LOCATION", ""),
                ev.get("CATEGORIES", ""),
                ev.get("UID", "")
            ])

    print("❇️Normalement si les astres sont sympa LE FICHIER CSV est créé :", chemin_csv)


creer_csv_depuis_ics("ADE_RT1_Septembre2025_Decembre2025.ics", "fichier_de_merde.csv")
