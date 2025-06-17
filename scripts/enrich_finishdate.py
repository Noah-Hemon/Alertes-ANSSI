import pandas as pd
import requests
import time

def get_closed_at(id_anssi):
    """
    Appelle l'API CERT pour récupérer les informations de l'alerte et
    renvoie le dernier revision_date (date de clôture) ou None si non trouvé.
    """
    if id_anssi == "Non disponible" or pd.isna(id_anssi):
        return None

    url = f"https://www.cert.ssi.gouv.fr/alerte/{id_anssi}/json/"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            revisions = data.get("revisions", [])
            if revisions:
                dates = [pd.to_datetime(item.get("revision_date")) for item in revisions if item.get("revision_date")]
                if dates:
                    return max(dates)
        return None
    except Exception as e:
        print(f"Erreur lors de l'appel pour {id_anssi}: {e}")
        return None

# Lecture de l'intégralité du CSV
df = pd.read_csv("data/cve_enriched.csv")

closed_dates = []

# Pour chaque alerte, appeler l'API et récupérer la date de clôture
for idx, row in df.iterrows():
    id_anssi = str(row["id_anssi"])
    finalerte = get_closed_at(id_anssi)
    if finalerte is None:
        finalerte = "Inconnu"
    closed_dates.append(finalerte)
    print(f"{id_anssi} -> finalerte: {finalerte}")
    time.sleep(0.1)

# Ajout de la nouvelle colonne "finalerte" au DataFrame original
df["finalerte"] = closed_dates

# Sauvegarde du DataFrame enrichi avec la nouvelle colonne
df.to_csv("data/enriched_vdate.csv", index=False)

print("Fichier 'enriched_vdate.csv' créé avec succès.")