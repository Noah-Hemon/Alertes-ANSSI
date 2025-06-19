import requests
import feedparser
import pandas as pd

def main():
    RSS_FEEDS = {
        "alerte": "https://www.cert.ssi.gouv.fr/alerte/feed/",
        "avis": "https://www.cert.ssi.gouv.fr/avis/feed/"
    }

    headers = {
        'User-Agent': 'Mozilla/5.0'
    }

    rss_data = []

    for rss_type, url in RSS_FEEDS.items():
        response = requests.get(url, headers=headers)
        feed = feedparser.parse(response.content)

        print(f"[{rss_type}] → {len(feed.entries)} entrées trouvées.")

        for entry in feed.entries:
            title = entry.get("title", "").strip()
            description = entry.get("description", "").strip()
            pub_date = entry.get("published", "").strip()
            link_url = entry.get("id", "").strip()  # équivaut à <guid>
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
    print(f"{len(df_rss)} lignes enregistrées dans data/raw_rss.csv")

if __name__ == "__main__":
    main()