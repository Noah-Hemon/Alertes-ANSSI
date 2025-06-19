import scripts.scraper_rss as scraper_rss
import scripts.extract_cve as extract_cve
import scripts.enrich_cve as enrich_cve
import scripts.consolidate_df as consolidate_df
import scripts.model_py as model_py

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
