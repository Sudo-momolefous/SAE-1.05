chemin_fichier = "evenementSAE_15_2025.ics"

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


    

lire_fichier_ics_simple(chemin_fichier)