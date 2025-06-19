import os
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

def main():
    # Créer le dossier si nécessaire
    os.makedirs("diagrams", exist_ok=True)

    # Configuration de l'affichage
    pd.set_option('display.width', 1000)
    pd.set_option('display.max_columns', None)

    # Lecture et renommage des colonnes
    df = pd.read_csv("data/cve_cleaned_for_df.csv")
    df = df[[
        "Identifiant ANSSI",
        "Titre",
        "Type (Avis ou Alerte)",
        "Publiée le",
        "Date de fin d'alerte",
        "ID CVE",
        "Score CVSS",
        "Base Severity",
        "Score EPSS",
        "ID CWE",
        "Description CWE",
        "Lien",
        "Description",
        "Vendeur",
        "Produit",
        "Version Affectés",
        "Différence en jours"
    ]]  

    # Fonctions de nettoyage pour les colonnes sous forme de string
    def clean_vendor(vendor_str):
        if isinstance(vendor_str, str):
            vendors = [v.strip() for v in vendor_str.split(",")]
            unique_vendors = set(vendors)
            return ", ".join(unique_vendors)
        return vendor_str

    def clean_versions(versions_str):
        if isinstance(versions_str, str):
            versions = [v.strip() for v in versions_str.split(",")]
            unique_versions = set(versions)
            return ", ".join(unique_versions)
        return versions_str

    df["Vendeur"] = df["Vendeur"].apply(clean_vendor)
    df["Version Affectés"] = df["Version Affectés"].apply(clean_versions)

    # Conversion des scores en numérique si nécessaire
    df["Score CVSS"] = pd.to_numeric(df["Score CVSS"], errors="coerce")
    df["Score EPSS"] = pd.to_numeric(df["Score EPSS"], errors="coerce")

    # Conversion de la date de publication en datetime
    df["Publiée le"] = pd.to_datetime(df["Publiée le"], errors="coerce")

    # ---------------------------
    # 1. Histogramme des Scores CVSS
    plt.figure(figsize=(14, 7))
    sns.histplot(df['Score CVSS'], bins=20, kde=True, color='skyblue')
    plt.axvline(x=4.0, color='gold', linestyle='--', label='Moyen (4.0)')
    plt.axvline(x=7.0, color='orange', linestyle='--', label='Élevé (7.0)')
    plt.axvline(x=9.0, color='red', linestyle='--', label='Critique (9.0)')
    plt.title('Distribution des Scores de Gravité CVSS', fontsize=16)
    plt.xlabel('Score CVSS')
    plt.ylabel('Nombre de Vulnérabilités')
    plt.legend()
    plt.tight_layout()
    plt.savefig("diagrams/histogram_cvss.png", dpi=300)
    plt.show()

    # ---------------------------
    # 2. Diagramme circulaire (Donut) pour le Top 10 des CWE
    top_cwe = df['ID CWE'].value_counts().nlargest(10)
    plt.figure(figsize=(12, 12))
    plt.pie(top_cwe, labels=top_cwe.index, autopct='%1.1f%%', startangle=140, pctdistance=0.85)
    centre_circle = plt.Circle((0,0),0.70,fc='white')
    fig = plt.gcf()
    fig.gca().add_artist(centre_circle)
    plt.title('Top 10 des Types de Vulnérabilités (CWE) les Plus Fréquents', fontsize=16)
    plt.axis('equal')
    plt.tight_layout()
    plt.savefig("diagrams/donut_top_cwe.png", dpi=300)
    plt.show()

    # ---------------------------
    # 3. Diagramme à barres pour le Top 15 des éditeurs (Vendeur)
    plt.figure(figsize=(12, 8))
    top_vendors = df['Vendeur'].value_counts().nlargest(15)
    sns.barplot(x=top_vendors.values, y=top_vendors.index, palette='viridis')
    plt.title('Top 15 des Éditeurs les Plus Affectés par des Vulnérabilités', fontsize=16)
    plt.xlabel('Nombre Total de Vulnérabilités')
    plt.ylabel('Éditeur')
    plt.tight_layout()
    plt.savefig("diagrams/bar_top_vendors.png", dpi=300)
    plt.show()

    # ---------------------------
    # 4. Scatter plot : Score CVSS vs Score EPSS
    plt.figure(figsize=(14, 8))
    sns.scatterplot(
        data=df,
        x='Score CVSS',
        y='Score EPSS',
        hue='Base Severity',
        palette={'Non disponible': 'grey', 'LOW': 'green', 'MEDIUM': 'orange', 'HIGH': 'red', 'CRITICAL': 'darkred'},
        alpha=0.7,
        s=80
    )
    plt.title('Relation entre Gravité (CVSS) et Probabilité d\'Exploitation (EPSS)', fontsize=16)
    plt.xlabel('Score CVSS (Gravité)')
    plt.ylabel('Score EPSS (Probabilité d\'exploitation)')
    plt.legend(title='Sévérité')
    plt.tight_layout()
    plt.savefig("diagrams/scatter_cvss_epss.png", dpi=300)
    plt.show()

    # ---------------------------
    # 5. Courbe cumulative des Vulnérabilités au fil du Temps
    df_sorted_by_date = df.sort_values(by='Publiée le')
    cumulative_vulns = df_sorted_by_date.groupby('Publiée le').size().cumsum()
    plt.figure(figsize=(14, 7))
    cumulative_vulns.plot(kind='line', color='navy')
    plt.title('Évolution Cumulative des Vulnérabilités Détectées', fontsize=16)
    plt.xlabel('Date de Publication')
    plt.ylabel('Nombre Cumulatif de Vulnérabilités')
    plt.tight_layout()
    plt.savefig("diagrams/cumulative_vulns.png", dpi=300)
    plt.show()

    # ---------------------------
    # 6. Boxplot des Scores CVSS pour les 10 Éditeurs les Plus Affectés
    top_10_vendors_names = df['Vendeur'].value_counts().nlargest(10).index
    df_top_vendors = df[df['Vendeur'].isin(top_10_vendors_names)]
    plt.figure(figsize=(15, 8))
    sns.boxplot(
        data=df_top_vendors,
        x='Score CVSS',
        y='Vendeur',
        order=top_10_vendors_names,
        palette='coolwarm'
    )
    plt.title('Dispersion des Scores CVSS pour les 10 Éditeurs les Plus Affectés', fontsize=16)
    plt.xlabel('Score CVSS')
    plt.ylabel('Éditeur')
    plt.tight_layout()
    plt.savefig("diagrams/boxplot_top_vendors_cvss.png", dpi=300)
    plt.show()

    # ---------------------------
    # 7. Countplot du nombre de Bulletins par Éditeur et par Type (Avis vs. Alerte)
    top_10_vendors_names = df['Vendeur'].value_counts().nlargest(10).index
    df_top_vendors_types = df[df['Vendeur'].isin(top_10_vendors_names)]
    plt.figure(figsize=(14, 8))
    sns.countplot(
        data=df_top_vendors_types,
        y='Vendeur',
        hue='Type (Avis ou Alerte)',
        order=top_10_vendors_names,
        palette={'avis': 'steelblue', 'alerte': 'orangered'}
    )
    plt.title('Nombre de Bulletins par Éditeur et par Type (Avis vs. Alerte)', fontsize=16)
    plt.xlabel('Nombre de Bulletins')
    plt.ylabel('Éditeur')
    plt.legend(title='Type de Bulletin')
    plt.tight_layout()
    plt.savefig("diagrams/countplot_vendors_bulletins.png", dpi=300)
    plt.show()

    # ---------------------------
    # 8. Histogramme des Scores EPSS
    plt.figure(figsize=(14, 7))
    sns.histplot(df['Score EPSS'].dropna(), kde=True, color='mediumseagreen', bins=30)
    plt.title("Distribution de la Probabilité d'Exploitation (Score EPSS)", fontsize=16)
    plt.xlabel("Score EPSS")
    plt.ylabel("Nombre de Vulnérabilités")
    plt.tight_layout()
    plt.savefig("diagrams/histogram_epss.png", dpi=300)
    plt.show()

    # ---------------------------
    # 9. Heatmap de Corrélation entre Score CVSS et Score EPSS
    correlation_matrix = df[['Score CVSS', 'Score EPSS']].corr()
    plt.figure(figsize=(8, 6))
    sns.heatmap(
        correlation_matrix,
        annot=True,
        cmap='coolwarm',
        vmin=-1, vmax=1
    )
    plt.title('Heatmap de Corrélation entre les Scores CVSS et EPSS', fontsize=16)
    plt.tight_layout()
    plt.savefig("diagrams/heatmap_cvss_epss_corr.png", dpi=300)
    plt.show()

    # ---------------------------
    # 9.1 analyse de la triple corrélation

    # S'assurer que la colonne "Différence en jours" est bien en numérique
    df["Différence en jours"] = pd.to_numeric(df["Différence en jours"], errors='coerce')

    # Sélectionner les colonnes d'intérêt
    cols = ["Score CVSS", "Score EPSS", "Différence en jours"]
    corr_matrix = df[cols].corr()

    # Afficher la heatmap
    plt.figure(figsize=(8,6))
    sns.heatmap(corr_matrix, annot=True, cmap='coolwarm', vmin=-1, vmax=1)
    plt.title("Heatmap de Corrélation entre Différence en jours, Score CVSS et Score EPSS", fontsize=16)
    plt.tight_layout()
    plt.savefig("diagrams/heatmap_corr_diff_jours_cvss_epss.png", dpi=300)
    plt.show()

    # ---------------------------
    # 10. Barplot des Top Éditeurs Affectés (pour analyse CWE)
    top_vendors_for_cwe = df['Vendeur'].value_counts().nlargest(10)
    plt.figure(figsize=(12, 8))
    sns.barplot(x=top_vendors_for_cwe.values, y=top_vendors_for_cwe.index, palette='magma')
    plt.title("Top Éditeurs Affectés par les Vulnérabilités", fontsize=16)
    plt.xlabel("Nombre de Vulnérabilités de ce Type")
    plt.ylabel("Éditeur")
    plt.tight_layout()
    plt.savefig("diagrams/bar_top_vendors_for_cwe.png", dpi=300)
    plt.show()

    # ---------------------------
    # 11. Barplot des Top 20 Versions les Plus Fréquemment Affectées
    top_versions = df['Version Affectés'].value_counts().nlargest(20)
    plt.figure(figsize=(12, 10))
    sns.barplot(x=top_versions.values, y=top_versions.index, palette='plasma')
    plt.title('Top 20 des Versions de Produits les Plus Fréquemment Affectées', fontsize=16)
    plt.xlabel('Nombre de Bulletins de Vulnérabilité Associés')
    plt.ylabel('Version du Produit')
    plt.tight_layout()
    plt.savefig("diagrams/bar_top_product_versions.png", dpi=300)
    plt.show()

    # ---------------------------
    # 12. Stacked Bar (Horizontal) : Composition de la Sévérité des Vulnérabilités par Éditeur
    top_vendors_names = df['Vendeur'].value_counts().nlargest(10).index
    df_top_vendors = df[df['Vendeur'].isin(top_vendors_names)]
    severity_by_vendor = pd.crosstab(df_top_vendors['Vendeur'], df_top_vendors['Base Severity'])
    severity_by_vendor.plot(kind='barh', stacked=True, figsize=(14, 8), colormap='coolwarm_r', title='Composition de la Sévérité des Vulnérabilités par Éditeur')
    plt.tight_layout()
    plt.savefig("diagrams/stacked_bar_severity_vendor.png", dpi=300)
    plt.show()

    # ---------------------------
    # 13. Heatmap des Types de Faiblesses (CWE) par Éditeur
    top_vendors = df['Vendeur'].value_counts().nlargest(10).index
    top_cwes = df['ID CWE'].value_counts().nlargest(10).index
    df_filtered = df[df['Vendeur'].isin(top_vendors) & df['ID CWE'].isin(top_cwes)]
    cwe_vendor_matrix = pd.crosstab(df_filtered['Vendeur'], df_filtered['ID CWE'])
    plt.figure(figsize=(15, 10))
    sns.heatmap(cwe_vendor_matrix, annot=True, cmap='YlGnBu', fmt='d')
    plt.title('Heatmap des Types de Faiblesses (CWE) par Éditeur', fontsize=16)
    plt.tight_layout()
    plt.savefig("diagrams/heatmap_cwe_vendor_matrix.png", dpi=300)
    plt.show()


if __name__ == "__main__":
    main()