import pandas as pd

# Charger le fichier CSV
file_path = "data/cve_enriched.csv"  # Remplacez par le chemin réel si besoin
df = pd.read_csv(file_path)

# Nettoyer les colonnes cvss_score et epss_score (convertir en numérique)
df['cvss_score_clean'] = pd.to_numeric(df['cvss_score'], errors='coerce')
df['epss_score_clean'] = pd.to_numeric(df['epss_score'], errors='coerce')

# Calcul du taux de valeurs manquantes
total = len(df)
missing_cvss = df['cvss_score_clean'].isna().sum()
missing_epss = df['epss_score_clean'].isna().sum()

rate_cvss = missing_cvss / total * 100
rate_epss = missing_epss / total * 100

# Affichage des résultats
print(f"Total d'entrées : {total}")
print(f"Scores CVSS manquants : {missing_cvss} ({rate_cvss:.2f}%)")
print(f"Scores EPSS manquants : {missing_epss} ({rate_epss:.2f}%)")
