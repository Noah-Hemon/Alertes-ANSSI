# Alertes-ANSSI
#### Analyse des Avis et Alertes ANSSI avec Enrichissement des CVE

## Installer les dépendances

```
pip install -r requirements.txt
```


## Structure du projet

```
Alertes-ANSSI/
├── data/
│   ├── raw_rss.csv
│   ├── cve_extracted.csv
│   └── cve_enriched.csv
├── models/
│   └── placeholder.ipynb
├── scripts/
│   ├── consolidate_df.py
│   ├── enrich_cve.py
│   ├── extract_cve.py
│   ├── interpretation_viz.py
│   └── scraper_rss.py
├── video_demo/
│   └── placeholder.mp4
├── requirements.txt
└── README.md
```

## Utilisation

1. **Récupérer les flux RSS :**
   ```
   python scripts/scraper_rss.py
   ```
   Génère `data/raw_rss.csv`

2. **Extraire les CVE :**
   ```
   python scripts/extract_cve.py
   ```
   Génère `data/cve_extracted.csv`

3. **Enrichir les CVE :**
   ```
   python scripts/enrich_cve.py
   ```
   Génère `data/cve_enriched.csv`

4. **Nettoyer les données :**
   ```
   python scripts/consolidate_df.py
   ```
   Génère le fichier `data/cve_cleaned_for_df.csv`

5. **Tracés des graphiques :**
   ```
   python scripts/interpretation_viz.py
   ```
   Génère les graphiques et les sauvegarde dans le dossier `diagrams/`

6. **Modèle de machine learning**

## Structure des données

- `data/raw_rss.csv` : Alertes et avis ANSSI bruts.
- `data/cve_extracted.csv` : CVE extraites par alerte/avis.
- `data/cve_enriched.csv` : CVE enrichies avec MITRE et EPSS.
- `data/cve_cleaned_for_df.csv` : Données nettoyés prêtes à l'emploi dans un DataFrame