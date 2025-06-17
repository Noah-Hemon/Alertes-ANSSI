import pandas as pd
import requests
import time

def extract_cvss_score(mitre_data):
    def extract_from_metrics(metrics):
        for metric in metrics:
            for key in ["cvssV3_1", "cvssV3_0", "cvssV2", "cvssV4_0"]:
                if key in metric:
                    m = metric[key]
                    score = m.get("baseScore")
                    severity = m.get("baseSeverity", "Non disponible")
                    if score is not None:
                        return score, severity
        return None, "Non disponible"

    # 1. Tenter depuis CNA
    cna_metrics = mitre_data.get("containers", {}).get("cna", {}).get("metrics", [])
    score, severity = extract_from_metrics(cna_metrics)
    if score is not None:
        return score, severity

    # 2. Tenter depuis ADP
    for adp in mitre_data.get("containers", {}).get("adp", []):
        adp_metrics = adp.get("metrics", [])
        score, severity = extract_from_metrics(adp_metrics)
        if score is not None:
            return score, severity

    return None, "Non disponible"

# Chargement des données initiales
df = pd.read_csv("data/cve_extracted.csv")
df = df[df["cve_id"].notna() & df["cve_id"].str.startswith("CVE-")]
# Vérifier si la colonne "Identifiant ANSSI" existe dans le CSV d'origine
if "Identifiant ANSSI" in df.columns:
    df_unique = df[["cve_id", "Identifiant ANSSI"]].drop_duplicates().reset_index(drop=True)
else:
    # Si non, on utilise un identifiant par défaut
    df_unique = df[["cve_id"]].drop_duplicates().reset_index(drop=True)
    df_unique["Identifiant ANSSI"] = "Non disponible"

records = []

for idx, row in df_unique.iterrows():
    cve_id = row["cve_id"]
    # Utiliser l'identifiant ANSSI fourni ou "Non disponible"
    id_anssi = row.get("Identifiant ANSSI", "Non disponible")
    mitre_url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
    epss_url = f"https://api.first.org/data/v1/epss?cve={cve_id}"

    # Valeurs par défaut
    cvss_score, base_severity = None, "Non disponible"
    cwe_id, cwe_desc, description = "Non disponible", "Non disponible", "Non disponible"
    vendor = "Non disponible"
    epss_score = None
    affected_versions = "Non disponible"

    # --- MITRE API ---
    try:
        mitre_resp = requests.get(mitre_url, timeout=10)
        if mitre_resp.status_code == 200:
            mitre_data = mitre_resp.json()

            # Vérifier si le CVE n'existe pas
            if mitre_data.get("error") == "CVE_RECORD_DNE":
                print(f"{cve_id} : Non trouvé (CVE_RECORD_DNE). Ignoré.")
                continue

            container = mitre_data.get("containers", {}).get("cna", {})

            # Description
            descs = container.get("descriptions", [])
            if descs:
                description = descs[0].get("value", "Non disponible")

            # CVSS
            cvss_score, base_severity = extract_cvss_score(mitre_data)

            # CWE extraction : vérifier d'abord dans CNA
            found_cwe = False
            probtypes = container.get("problemTypes", [])
            for entry in probtypes:
                for desc in entry.get("descriptions", []):
                    # Si une valeur explicite "cweId" est présente et valide
                    if desc.get("cweId") and desc.get("cweId").lower() != "n/a":
                        cwe_id = desc.get("cweId")
                        cwe_desc = desc.get("description", "Non disponible")
                        found_cwe = True
                        break
                    else:
                        # En absence de "cweId", vérifier si la description commence par "CWE"
                        candidate = desc.get("description", "").strip()
                        if candidate.startswith("CWE"):
                            # Par exemple, "CWE-180: Incorrect Behavior Order: Validate Before Canonicalize"
                            cwe_id = candidate.split(":")[0].strip()  # "CWE-180"
                            cwe_desc = candidate
                            found_cwe = True
                            break
                if found_cwe:
                    break

            # Fallback CWE depuis ADP si non trouvé dans CNA
            if not found_cwe:
                adps = mitre_data.get("containers", {}).get("adp", [])
                for adp in adps:
                    probtypes = adp.get("problemTypes", [])
                    for entry in probtypes:
                        for desc in entry.get("descriptions", []):
                            if desc.get("cweId") and desc.get("cweId").lower() != "n/a":
                                cwe_id = desc.get("cweId")
                                cwe_desc = desc.get("description", "Non disponible")
                                found_cwe = True
                                break
                            else:
                                candidate = desc.get("description", "").strip()
                                if candidate.startswith("CWE"):
                                    cwe_id = candidate.split(":")[0].strip()
                                    cwe_desc = candidate
                                    found_cwe = True
                                    break
                        if found_cwe:
                            break
                    if found_cwe:
                        break

            # Extraction de Vendor et Versions
            affected = container.get("affected", [])
            if affected:
                vendors_list = [aff.get("vendor", "Non disponible") for aff in affected if aff.get("vendor")]
                if vendors_list:
                    vendor = ", ".join(vendors_list)

                versions_list = []
                for aff in affected:
                    for ver in aff.get("versions", []):
                        if ver.get("version"):
                            versions_list.append(ver["version"])
                if versions_list:
                    affected_versions = ", ".join(sorted(set(versions_list)))

    except Exception as e:
        print(f"Erreur MITRE pour {cve_id} : {e}")
        continue

    # --- EPSS API ---
    try:
        epss_resp = requests.get(epss_url, timeout=10)
        if epss_resp.status_code == 200:
            epss_data = epss_resp.json().get("data", [])
            if epss_data:
                epss_score = epss_data[0].get("epss", None)
    except Exception as e:
        print(f"Erreur EPSS pour {cve_id} : {e}")

    records.append({
        "cve_id": cve_id,
        "Identifiant ANSSI": id_anssi,
        "description": description,
        "cvss_score": cvss_score,
        "base_severity": base_severity,
        "cwe_id": cwe_id,
        "cwe_description": cwe_desc,
        "vendor": vendor,
        "affected_versions": affected_versions,
        "epss_score": epss_score
    })

    print(f"OK {idx+1}/{len(df_unique)}, next")
    time.sleep(0.1)

df_enrich = pd.DataFrame(records)

def get_closed_at(id_anssi):
    """
    Appelle l'API CERT pour récupérer les informations de l'alerte et
    renvoie le dernier revision_date (date de clôture).
    """
    if id_anssi == "Non disponible" or pd.isna(id_anssi):
        return None  # Si l'identifiant est invalide, retourner None

    url = f"https://www.cert.ssi.gouv.fr/alerte/{id_anssi}/json/"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            revisions = data.get("revisions", [])
            if revisions:
                # Transformation des dates en datetime et récupération du maximum
                dates = [pd.to_datetime(item.get("revision_date")) for item in revisions if item.get("revision_date")]
                if dates:
                    return max(dates)  # Retourner la date la plus récente
        return None
    except Exception as e:
        print(f"Erreur lors de l'appel pour {id_anssi}: {e}")
        return None

closed_dates = []

# Fusion et export
df_final = df.merge(df_enrich, on="cve_id", how="left")
df_final.to_csv("data/cve_enriched.csv", index=False)

# Chargement des données enrichies
df_enrich = pd.read_csv("data/cve_enriched.csv")

# Vérifier si la colonne "Identifiant ANSSI" existe
if "Identifiant ANSSI" not in df_enrich.columns:
    print("La colonne 'Identifiant ANSSI' est absente du DataFrame.")
    df_enrich["Identifiant ANSSI"] = "Non disponible"

# Initialisation de la liste pour stocker les dates de clôture
closed_dates = []

# Pour chaque alerte dans le DataFrame enrichi, appeler l'API et récupérer la date de clôture
for idx, row in df_enrich.iterrows():
    id_anssi = str(row["id_anssi"])

    print(id_anssi)

    closed_date = get_closed_at(id_anssi)
    closed_dates.append(closed_date)
    print(f"{id_anssi} -> closed_at: {closed_date}")
    time.sleep(0.1)  # Pause pour éviter de surcharger l'API

# Ajout de la nouvelle colonne "closed_at"
df_enrich["closed_at"] = closed_dates

# Sauvegarde du DataFrame mis à jour
df_enrich.to_csv("data/cve_enriched_with_closedat.csv", index=False)

print("Mise à jour terminée, fichier data/cve_enriched_with_closedat.csv créé.")

print("Enrichissement MITRE + EPSS terminé.")
print(f"{len(df_final)} CVE enrichies dans data/cve_enriched.csv")