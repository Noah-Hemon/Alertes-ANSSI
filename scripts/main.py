import scraper_rss
import extract_cve
import enrich_cve
import consolidate_df

print("le scraping commence !")
scraper_rss.main()

print("l'extraction des CVE commence")
extract_cve.main()

print("l'enrichissement des CVE commence")
enrich_cve.main()

print("consolidation du csv et df")
consolidate_df.main()