import scripts.scraper_rss as scraper_rss
import scripts.extract_cve as extract_cve
import scripts.enrich_cve as enrich_cve
import scripts.consolidate_df as consolidate_df
import scripts.model_py as model_py

import schedule
import time


print("Tâche planifiée. En attente des déclenchements...")

def job():
    print("Début de la tâche planifiée...")

    print("le scraping commence !")
    scraper_rss.main()

    print("l'extraction des CVE commence")
    extract_cve.main()

    print("l'enrichissement des CVE commence")
    enrich_cve.main()

    print("consolidation du csv et df")
    consolidate_df.main()

    print("envoi des emails")
    model_py.main()

    print("Tâche planifiée terminée.")


schedule.every().minute.do(job)


while True:
    schedule.run_pending()
    time.sleep(1)