import pandas as pd
import requests
import re
import time


def main():

    df_rss = pd.read_csv("data/raw_rss.csv")

    # Liste pour stocker les résultats enrichis
    cve_records = []

    for _, row in df_rss.iterrows():
        id_anssi = row["id_anssi"]
        url_json = f"https://www.cert.ssi.gouv.fr/{row['type']}/{id_anssi}/json/"

        try:
            response = requests.get(url_json, timeout=10)
            if response.status_code == 200:
                data = response.json()

                if "cves" in data and isinstance(data["cves"], list):
                    for cve_entry in data["cves"]:
                        cve_id = cve_entry.get("name", "")
                        cve_records.append({
                            "id_anssi": id_anssi,
                            "title": row["title"],
                            "published": row["published"],
                            "link": row["link"],
                            "type": row["type"],
                            "cve_id": cve_id
                        })

                # Backup avec regex en cas de champs manquant
                else:
                    cve_pattern = r"CVE-\d{4}-\d{4,7}"
                    cve_found = list(set(re.findall(cve_pattern, str(data))))
                    for cve_id in cve_found:
                        cve_records.append({
                            "id_anssi": id_anssi,
                            "title": row["title"],
                            "published": row["published"],
                            "link": row["link"],
                            "type": row["type"],
                            "cve_id": cve_id
                        })

            else:
                print(f"Erreur JSON non accessible : {url_json} [{response.status_code}]")

        except Exception as e:
            print(f"Erreur pour {id_anssi} → {e}")

        time.sleep(1)

    df_cves = pd.DataFrame(cve_records)
    df_cves.to_csv("data/cve_extracted.csv", index=False)
    print("Extraction des CVE terminée.")
    print(f"{len(df_cves)} CVE extraits et enregistrés dans data/cve_extracted.csv")



if __name__ == "__main__":
    main()