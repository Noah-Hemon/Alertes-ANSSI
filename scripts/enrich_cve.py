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

    # 1. Try from CNA
    cna_metrics = mitre_data.get("containers", {}).get("cna", {}).get("metrics", [])
    score, severity = extract_from_metrics(cna_metrics)
    if score is not None:
        return score, severity

    # 2. Try from ADP
    for adp in mitre_data.get("containers", {}).get("adp", []):
        adp_metrics = adp.get("metrics", [])
        score, severity = extract_from_metrics(adp_metrics)
        if score is not None:
            return score, severity

    return None, "Non disponible"

# Chargement des données initiales
df = pd.read_csv("data/cve_extracted.csv")
df = df[df["cve_id"].notna() & df["cve_id"].str.startswith("CVE-")]
df_unique = df[["cve_id"]].drop_duplicates().reset_index(drop=True)

records = []

for idx, row in df_unique.iterrows():
    cve_id = row["cve_id"]
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

            # Vérifier si le CVE est inexistant
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

            # CWE depuis CNA
            found_cwe = False
            probtypes = container.get("problemTypes", [])
            for entry in probtypes:
                for desc in entry.get("descriptions", []):
                    if desc.get("cweId") and desc.get("cweId") != "n/a":
                        cwe_id = desc.get("cweId")
                        cwe_desc = desc.get("description", "Non disponible")
                        found_cwe = True
                        break
                if found_cwe:
                    break

            # Fallback CWE depuis ADP
            if not found_cwe:
                adps = mitre_data.get("containers", {}).get("adp", [])
                for adp in adps:
                    probtypes = adp.get("problemTypes", [])
                    for entry in probtypes:
                        for desc in entry.get("descriptions", []):
                            if desc.get("cweId"):
                                cwe_id = desc.get("cweId")
                                cwe_desc = desc.get("description", "Non disponible")
                                found_cwe = True
                                break
                        if found_cwe:
                            break
                    if found_cwe:
                        break

            # Vendor et versions
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
        continue  # Éviter d’ajouter un CVE corrompu même en cas d’erreur

    # --- EPSS API ---
    try:
        epss_resp = requests.get(epss_url, timeout=10)
        if epss_resp.status_code == 200:
            epss_data = epss_resp.json().get("data", [])
            if epss_data:
                epss_score = epss_data[0].get("epss", None)
    except Exception as e:
        print(f"Erreur EPSS pour {cve_id} : {e}")

    # Ajout dans le résultat seulement si tout est OK
    records.append({
        "cve_id": cve_id,
        "description": description,
        "cvss_score": cvss_score,
        "base_severity": base_severity,
        "cwe_id": cwe_id,
        "cwe_description": cwe_desc,
        "vendor": vendor,
        "affected_versions": affected_versions,
        "epss_score": epss_score
    })

    print(f"OK {idx + 1}/{len(df_unique)}, next")
    time.sleep(0.1)


# Fusion et export
df_enrich = pd.DataFrame(records)
df_final = df.merge(df_enrich, on="cve_id", how="left")
df_final.to_csv("data/cve_enriched.csv", index=False)

print("Enrichissement MITRE + EPSS terminé.")
print(f"{len(df_final)} CVE enrichies dans data/cve_enriched.csv")
