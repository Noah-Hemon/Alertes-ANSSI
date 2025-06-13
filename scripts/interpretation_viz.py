import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Configuration de l'affichage
pd.set_option('display.width', 1000)
pd.set_option('display.max_columns', None)

# Lecture et renommage des colonnes
df = pd.read_csv("../data/cve_enriched.csv")
df.columns = ["Identifiant ANSSI", "Titre", "Publiée le", "Lien", "Type (Avis ou Alerte)", "ID CVE", "Description", "Score CVSS", "Criticité", "ID CWE", "Description CWE", "Vendeur", "Version Affectés", "Score EPSS"]

# Fonctions de nettoyage pour les colonnes sous forme de string
def clean_vendor(vendor_str):
    if isinstance(vendor_str, str):
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

# ---------------------------
# Visualisation des données
# ---------------------------

# Histogramme des scores CVSS
plt.figure(figsize=(10,6))
# On s'assure que la colonne est de type numérique :
df["Score CVSS"] = pd.to_numeric(df["Score CVSS"], errors="coerce")
sns.histplot(df["Score CVSS"].dropna(), bins=20, kde=True)
plt.title("Distribution des scores CVSS")
plt.xlabel("Score CVSS")
plt.ylabel("Fréquence")
plt.tight_layout()
plt.show()

# Diagramme circulaire pour le type (Avis ou Alerte)
plt.figure(figsize=(8,8))
df["Type (Avis ou Alerte)"].value_counts().plot.pie(autopct='%1.1f%%', startangle=90)
plt.title("Répartition des types (Avis ou Alerte)")
plt.ylabel("")
plt.tight_layout()
plt.show()

# Diagramme à barres pour les éditeurs (Vendeur)
plt.figure(figsize=(10,6))
# Si un même CVE peut contenir plusieurs vendeurs, on compte les occurences dans la chaîne :
vendor_counts = df["Vendeur"].apply(lambda x: x.split(", ") if isinstance(x, str) else []).explode().value_counts()
sns.barplot(x=vendor_counts.index, y=vendor_counts.values)
plt.title("Nombre de vulnérabilités par éditeur")
plt.xlabel("Vendeur")
plt.ylabel("Nombre de vulnérabilités")
plt.xticks(rotation=45)
plt.tight_layout()
plt.show()

# Nuage de points entre score CVSS et score EPSS
plt.figure(figsize=(10,6))
df["Score EPSS"] = pd.to_numeric(df["Score EPSS"], errors="coerce")
sns.scatterplot(data=df, x="Score CVSS", y="Score EPSS")
plt.title("Nuage de points : Score CVSS vs Score EPSS")
plt.xlabel("Score CVSS")
plt.ylabel("Score EPSS")
plt.tight_layout()
plt.show()