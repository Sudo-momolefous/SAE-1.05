import csv

chemin_fichier = "ADE_RT1_Septembre2025_Decembre2025.ics"

def lire_fichier_ics_simple(chemin_fichier):
    evenements = []
    sommaire = ""
    description = ""
    debut = ""
    fin = ""

    with open(chemin_fichier, "r", encoding="utf-8") as f:
        for ligne in f:
            ligne = ligne.strip()

            # Début d'un événement
            if ligne.startswith("BEGIN:VEVENT"):
                sommaire = ""
                description = ""
                debut = ""
                fin = ""

            elif ligne.startswith("SUMMARY:"):
                sommaire = ligne.replace("SUMMARY:", "")

            elif ligne.startswith("DESCRIPTION:"):
                description = ligne.replace("DESCRIPTION:", "")
                description = description.replace("\\n", " ").strip()

            elif ligne.startswith("DTSTART:"):
                debut = ligne.replace("DTSTART:", "")

            elif ligne.startswith("DTEND:"):
                fin = ligne.replace("DTEND:", "")

            # Fin d'un événement → on l'ajoute à la liste
            elif ligne.startswith("END:VEVENT"):
                evenements.append([sommaire, description, debut, fin])

    return evenements


def ecrire_csv(fichier_ics, fichier_csv):
    evenements = lire_fichier_ics_simple(fichier_ics)

    with open(fichier_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f, delimiter=";")
        writer.writerow(["SUMMARY", "DESCRIPTION", "DTSTART", "DTEND"])

        for ev in evenements:
            writer.writerow(ev)

    print("❇️Normalement si les astres sont sympa LE FICHIER CSV est créé", len(evenements), "événements →", fichier_csv)


ecrire_csv(chemin_fichier, "test.csv")
