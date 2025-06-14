import pandas as pd

df = pd.read_csv("data/cve_enriched.csv")
df.columns = ["Identifiant ANSSI", "Titre", "Publiée le", "Lien", "Type (Avis ou Alerte)", "ID CVE", "Description", "Score CVSS", "Criticité", "ID CWE", "Description CWE", "Vendeur", "Version Affectés", "Score EPSS"]

def clean_vendor(vendor_str):
    if isinstance(vendor_str, str):
        # Séparer par la virgule, enlever les espaces en trop et prendre les valeurs uniques
        vendors = [v.strip() for v in vendor_str.split(",")]
        unique_vendors = set(vendors)
        return ", ".join(unique_vendors)
    return vendor_str

def clean_versions(versions_str):
    if isinstance(versions_str, str):
        # Séparer par la virgule, enlever les espaces en trop et prendre les valeurs uniques
        versions = [v.strip() for v in versions_str.split(",")]
        unique_versions = set(versions)
        return ", ".join(unique_versions)
    return versions_str

df["Vendeur"] = df["Vendeur"].apply(clean_vendor)
df["Version Affectés"] = df["Version Affectés"].apply(clean_versions)

#print(df["Vendeur"].to_string())
#print(df["Version Affectés"].to_string())

print(df)