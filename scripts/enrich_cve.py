import pandas as pd
import requests
import time

df = pd.read_csv("../data/cve_extracted.csv")
df = df[df["cve_id"].notna() & df["cve_id"].str.startswith("CVE-")]
df_unique = df[["cve_id"]].drop_duplicates().reset_index(drop=True)

records = []

for _, row in df_unique.iterrows():
    cve_id = row["cve_id"]
    mitre_url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
    epss_url = f"https://api.first.org/data/v1/epss?cve={cve_id}"

    # Initialisation des variables d'extraction
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
            container = mitre_data.get("containers", {}).get("cna", {})

            # Extraction de la description
            descs = container.get("descriptions", [])
            if descs:
                description = descs[0].get("value", "Non disponible")

            # Extraction du score CVSS et de la base severity
            try:
                metrics = container.get("metrics", [])
                if metrics:
                    metrics = metrics[0]
                    for key in ["cvssV3_1", "cvssV3_0", "cvssV2"]:
                        if key in metrics:
                            metric_data = metrics[key]
                            cvss_score = metric_data.get("baseScore")
                            base_severity = metric_data.get("baseSeverity", "Non disponible")
                            break
            except Exception:
                pass

            # Extraction de CWE
            probtypes = container.get("problemTypes", [])
            if probtypes and "descriptions" in probtypes[0]:
                desc = probtypes[0]["descriptions"][0]
                cwe_id = desc.get("cweId", "Non disponible")
                cwe_desc = desc.get("description", "Non disponible")

            # Extraction du vendor et des versions affectées depuis "affected"
            affected = container.get("affected", [])
            if affected and isinstance(affected, list):
                # Récupérer tous les vendors listés dans "affected"
                vendors_list = [aff.get("vendor", "Non disponible") for aff in affected if aff.get("vendor")]
                if vendors_list:
                    vendor = ", ".join(vendors_list)
                # Récupérer les versions affectées
                versions_list = []
                for aff in affected:
                    versions = aff.get("versions", [])
                    for ver in versions:
                        version = ver.get("version", None)
                        if version:
                            versions_list.append(version)
                if versions_list:
                    # Optionnel : supprimer les doublons
                    affected_versions = ", ".join(sorted(set(versions_list)))
    except Exception as e:
        print(f"Erreur MITRE pour {cve_id} : {e}")

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
        "description": description,
        "cvss_score": cvss_score,
        "base_severity": base_severity,
        "cwe_id": cwe_id,
        "cwe_description": cwe_desc,
        "vendor": vendor,
        "affected_versions": affected_versions,
        "epss_score": epss_score
    })

    print(f"OK {_}, next")
    time.sleep(0.1)

# Conversion et fusion
df_enrich = pd.DataFrame(records)
df_final = df.merge(df_enrich, on="cve_id", how="left")
df_final.to_csv("../data/cve_enriched.csv", index=False)

print("Enrichissement MITRE + EPSS terminé.")
print(f"{len(df_final)} CVE enrichies et enregistrées dans ../data/cve_enriched.csv")