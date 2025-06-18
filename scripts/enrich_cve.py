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

# Fusion et export
df_final = df.merge(df_enrich, on="cve_id", how="left")
df_final.to_csv("data/cve_enriched.csv", index=False)

def get_closed_at(id_anssi):
    """
    Appelle l'API CERT pour récupérer les informations de l'alerte et
    renvoie la valeur de l'attribut "closed_at" (date de clôture) convertie en datetime,
    ou None si non trouvé.
    """
    if id_anssi == "Non disponible" or pd.isna(id_anssi):
        return None

    url = f"https://www.cert.ssi.gouv.fr/alerte/{id_anssi}/json/"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            closed_date = data.get("closed_at")
            if closed_date:
                return pd.to_datetime(closed_date)
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
df.to_csv("data/cve_enriched.csv", index=False)

print("Enrichissement MITRE + EPSS terminé.")
print(f"{len(df_final)} CVE enrichies dans data/cve_enriched.csv")