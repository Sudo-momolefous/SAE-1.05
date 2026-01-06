import os
import csv


chemin_fichier = "ADE_RT1_Septembre2025_Decembre2025.ics"

def lire_fichier_ics_simple(chemin_fichier):

    sommaire = "rien"
    description = "rien"
    début = "rien"
    fin = "rien"

    with open(chemin_fichier, "r", encoding="utf-8") as f:
        for ligne in f:
            ligne = ligne.strip()

            if ligne.startswith("SUMMARY:"):
                sommaire = ligne.replace("SUMMARY:", "")
                print("résumé :", sommaire)

            elif ligne.startswith("DESCRIPTION:"):
                description = ligne.replace("DESCRIPTION:", "")
                description = description.replace("\\n", "").strip()
                print("description :", description)

            elif ligne.startswith("DTSTART:"):
                début = ligne.replace("DTSTART:", "")
                print("début :", début)

            elif ligne.startswith("DTEND:"):
                fin = ligne.replace("DTEND:", "")
                print("fin :", fin)

                #elif ligne.startswith("NAME"):
                    #print("description :", ligne.replace("NAME:", ""))
    return sommaire, description, fin, début

def ecrire_csv(fichier_ics, fichier_csv):
    sommaire, description, debut, fin = lire_fichier_ics_simple(fichier_ics)

    with open(fichier_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f, delimiter=";")
        writer.writerow(["SUMMARY", "DESCRIPTION", "DTSTART", "DTEND"])
        writer.writerow([sommaire, description, debut, fin])

    print("❇️Normalement si les astres sont sympa LE FICHIER CSV est créé :", fichier_csv)


ecrire_csv(chemin_fichier, "test.csv")

    

lire_fichier_ics_simple(chemin_fichier)