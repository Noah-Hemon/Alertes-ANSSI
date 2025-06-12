import requests
import pandas as pd
import xml.etree.ElementTree as ET

RSS_FEEDS = {
    "alerte": "https://www.cert.ssi.gouv.fr/alerte/feed/",
    "avis": "https://www.cert.ssi.gouv.fr/avis/feed/"
}

rss_data = []

for rss_type, url in RSS_FEEDS.items():
    response = requests.get(url)
    root = ET.fromstring(response.content)
    items = root.findall(".//item")

    for item in items:
        title = item.find("title").text.strip()
        description = item.find("description").text.strip()
        pub_date = item.find("pubDate").text.strip()
        link_tag = item.find("guid")
        link_url = link_tag.text.strip() if link_tag is not None else None
        id_anssi = link_url.rstrip("/").split("/")[-1] if link_url else None

        rss_data.append({
            "id_anssi": id_anssi,
            "title": title,
            "description": description,
            "published": pub_date,
            "link": link_url,
            "type": rss_type
        })

df_rss = pd.DataFrame(rss_data)
df_rss.to_csv("data/raw_rss.csv", index=False)
print("Données RSS des deux flux enregistrées.")
