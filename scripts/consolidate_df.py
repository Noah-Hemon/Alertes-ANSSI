import pandas as pd

# Lecture du CSV enrichi
df = pd.read_csv("data/cve_enriched.csv")

# On renomme les colonnes pour correspondre aux informations attendues
df.columns = [
    "Identifiant ANSSI",    # ID du bulletin (ANSSI)
    "Titre",               # Titre du bulletin (ANSSI)
    "Publiée le",          # Date de publication
    "Lien",                # Lien du bulletin (ANSSI)
    "Type (Avis ou Alerte)",# Type de bulletin
    "ID CVE",              # Identifiant CVE
    "Description",         # Description (issue des API)
    "Score CVSS",          # Score CVSS
    "Base Severity",       # Base Severity (Criticité)
    "ID CWE",              # Type CWE
    "Description CWE",     # Description CWE
    "Vendeur",             # Éditeur/Vendor
    "Version Affectés",    # Versions affectées
    "Score EPSS"           # Score EPSS
]
print(df.isna().sum())
# Fonctions de nettoyage pour consolider les chaînes de caractères en gardant des valeurs uniques
def clean_vendor(vendor_str):
    if isinstance(vendor_str, str):
        # Séparation par la virgule, nettoyage et élimination des doublons
        vendors = [v.strip() for v in vendor_str.split(",")]
        unique_vendors = set(vendors)
        return ", ".join(unique_vendors)
    return vendor_str

def clean_versions(versions_str):
    if isinstance(versions_str, str):
        versions = [v.strip() for v in versions_str.split(",")]
        unique_versions = set(versions)
        return ", ".join(unique_versions)
    return versions_str

df["Vendeur"] = df["Vendeur"].apply(clean_vendor)
df["Version Affectés"] = df["Version Affectés"].apply(clean_versions)

# Ajout d'une colonne "Produit" avec la valeur par défaut "Non disponible"
df["Produit"] = "Non disponible"

# Réorganisation des colonnes suivant l'ordre demandé :
df = df[[
    "Identifiant ANSSI",
    "Titre",
    "Type (Avis ou Alerte)",
    "Publiée le",
    "ID CVE",
    "Score CVSS",
    "Base Severity",
    "Score EPSS",
    "ID CWE",
    "Description CWE",
    "Lien",
    "Description",
    "Vendeur",
    "Produit",
    "Version Affectés"
]]  

print(df.isna().sum())

# afficher un message d'erreur lorsque l'on a aucune info

replacement_dict = {
    "Identifiant ANSSI": "Pas d'Identifiant ANSSI",
    "Titre": "Pas de Titre",
    "Type (Avis ou Alerte)": "Pas de Type",
    "Publiée le": "Pas de Date de publication",
    "ID CVE": "Pas d'ID CVE",
    "Score CVSS": "Pas de Score CVSS",
    "Base Severity": "Pas de Base Severity",
    "ID CWE": "Pas d'ID CWE",
    "Description CWE": "Pas de Description CWE",
    "Score EPSS": "Pas de Score EPSS",
    "Lien": "Pas de Lien",
    "Description": "Pas de Description",
    "Vendeur": "Pas de Vendeur",
    "Produit": "Pas de Produit",
    "Version Affectés": "Pas de Version Affectés"
}

for col, replacement in replacement_dict.items():
    if df[col].isna().sum() > 0:
        print(f"Remplacement des valeurs manquantes pour '{col}'")
    df[col].fillna(replacement, inplace=True)

# Affichage du DataFrame consolidé
print(df)

df.to_csv("data/cve_cleaned_for_df.csv")
print(df.isna().sum())