import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import os

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.ensemble import RandomForestRegressor
from sklearn.metrics import mean_squared_error, r2_score, silhouette_score
from sklearn.cluster import KMeans
from sklearn.decomposition import PCA

import datetime

import smtplib
from email.mime.text import MIMEText

import warnings
warnings.filterwarnings('ignore')

# Variables globales pour stocker les résultats
_prediction_results = {}
_clustering_results = {}
_critical_alerts = []

def load_and_prepare_data():
    """Charger et préparer les données"""
    try:
        # Charger les données enrichies
        df = pd.read_csv('../data/cve_cleaned_for_df.csv')
        
        # Conversion des dates
        df['Publiée le'] = pd.to_datetime(df['Publiée le'], errors='coerce')
        df["Date de fin d'alerte"] = pd.to_datetime(df["Date de fin d'alerte"], errors='coerce')
        
        # Encodage des variables catégorielles principales
        cat_cols = ['Base Severity', 'ID CWE', 'Vendeur', 'Type (Avis ou Alerte)']
        for col in cat_cols:
            if col in df.columns:
                df[col] = df[col].fillna('Unknown').astype(str)
        
        # Encodage label pour les variables catégorielles (pour ML)
        label_encoders = {}
        for col in cat_cols:
            if col in df.columns:
                le = LabelEncoder()
                df[col+'_enc'] = le.fit_transform(df[col])
                label_encoders[col] = le
        
        # Conversion des scores en numérique
        df['Score CVSS'] = df['Score CVSS'].replace(['Pas de Score CVSS', 'Non disponible', ''], np.nan)
        df['Score CVSS'] = pd.to_numeric(df['Score CVSS'], errors='coerce')
        
        df['Score EPSS'] = df['Score EPSS'].replace(['Pas de Score EPSS', 'Non disponible', ''], np.nan)
        df['Score EPSS'] = pd.to_numeric(df['Score EPSS'], errors='coerce')
        
        return df, label_encoders
    except Exception as e:
        print(f"Erreur lors du chargement des données: {e}")
        return None, None

def run_predictions():
    """Fonction pour exécuter les prédictions et retourner les résultats"""
    global _prediction_results
    
    try:
        df, label_encoders = load_and_prepare_data()
        if df is None:
            return {'success': False, 'error': 'Impossible de charger les données'}
        
        # Filtrer uniquement les alertes
        col_type = 'Type (Avis ou Alerte)'
        col_id_anssi = 'Identifiant ANSSI'
        col_datefin = "Date de fin d'alerte"
        
        df_alertes = df[df[col_type].str.lower() == 'alerte'].copy()
        
        if len(df_alertes) == 0:
            return {'success': False, 'error': 'Aucune alerte trouvée dans le dataset'}
        
        # Conversion et nettoyage des scores numériques
        df_alertes['Score CVSS'] = df_alertes['Score CVSS'].replace(['Pas de Score CVSS', 'Non disponible', ''], np.nan)
        df_alertes['Score CVSS'] = pd.to_numeric(df_alertes['Score CVSS'], errors='coerce')
        
        df_alertes['Score EPSS'] = df_alertes['Score EPSS'].replace(['Pas de Score EPSS', 'Non disponible', ''], np.nan)
        df_alertes['Score EPSS'] = pd.to_numeric(df_alertes['Score EPSS'], errors='coerce')
        
        # Encodage des variables catégorielles
        for col in ['Base Severity', 'ID CWE', 'Vendeur', 'Type (Avis ou Alerte)']:
            enc_col = f"{col}_enc"
            if enc_col not in df_alertes.columns:
                le = LabelEncoder()
                df_alertes[enc_col] = le.fit_transform(df_alertes[col].astype(str))
        
        # Standardiser les timezones
        df_alertes['Publiée le'] = pd.to_datetime(df_alertes['Publiée le']).dt.tz_localize(None)
        df_alertes[col_datefin] = pd.to_datetime(df_alertes[col_datefin]).dt.tz_localize(None)
        
        # Calculer la durée en jours entre publication et fin d'alerte
        valid_dates = df_alertes[col_datefin].notnull() & df_alertes['Publiée le'].notnull()
        
        df_alertes['duree_alerte_jours'] = np.nan
        df_alertes.loc[valid_dates, 'duree_alerte_jours'] = (
            df_alertes.loc[valid_dates, col_datefin] - df_alertes.loc[valid_dates, 'Publiée le']
        ).dt.days
        
        # S'assurer que la durée est positive
        df_alertes.loc[df_alertes['duree_alerte_jours'] <= 0, 'duree_alerte_jours'] = 7
        
        # Sélection des features explicatives
        features = [
            'Score CVSS', 'Score EPSS', 'Base Severity_enc', 'ID CWE_enc', 'Vendeur_enc', 'Type (Avis ou Alerte)_enc'
        ]
        
        # Gestion des valeurs manquantes dans les features
        for col in features:
            if col in df_alertes.columns and df_alertes[col].isnull().any():
                if df_alertes[col].dtype.kind in 'biufc':
                    df_alertes[col].fillna(df_alertes[col].median(), inplace=True)
                else:
                    df_alertes[col].fillna(-1, inplace=True)
        
        # Séparer train/pred basé sur la durée calculée
        df_train = df_alertes[df_alertes['duree_alerte_jours'].notnull()]
        df_pred = df_alertes[df_alertes['duree_alerte_jours'].isnull()]
        
        predictions_count = 0
        avg_duration = 0
        durations_predicted = []
        
        if len(df_train) >= 1 and not df_pred.empty:
            X_train = df_train[features]
            y_train = df_train['duree_alerte_jours']
            X_pred = df_pred[features]
            
            # Stratégie de règles métier pour la durée
            def create_duration_based_predictions(df_pred):
                durations = []
                for idx, row in df_pred.iterrows():
                    severity = row['Base Severity']
                    cvss_score = row['Score CVSS']
                    
                    if pd.isna(cvss_score):
                        cvss_score = 5.0
                    
                    if severity == 'CRITICAL' or cvss_score >= 9.0:
                        duration_days = 30
                    elif severity == 'HIGH' or cvss_score >= 7.0:
                        duration_days = 60
                    elif severity == 'MEDIUM' or cvss_score >= 4.0:
                        duration_days = 90
                    else:
                        duration_days = 120
                    
                    # Ajuster selon le type de CWE
                    cwe_id = str(row['ID CWE'])
                    if 'CWE-79' in cwe_id or 'CWE-89' in cwe_id:
                        duration_days = max(30, duration_days - 15)
                    elif 'CWE-200' in cwe_id:
                        duration_days += 30
                    
                    duration_days = max(7, min(365, duration_days))
                    durations.append(duration_days)
                
                return pd.Series(durations, index=df_pred.index)
            
            # Modèle ML pour prédire la durée
            if len(df_train) >= 3:
                try:
                    from sklearn.linear_model import Ridge
                    
                    scaler = StandardScaler()
                    X_train_scaled = scaler.fit_transform(X_train)
                    X_pred_scaled = scaler.transform(X_pred)
                    
                    if len(df_train) < 10:
                        model = Ridge(alpha=1.0)
                    else:
                        model = RandomForestRegressor(n_estimators=50, max_depth=3, random_state=42)
                    
                    model.fit(X_train_scaled, y_train)
                    y_pred_duration_ml = model.predict(X_pred_scaled)
                    y_pred_duration_ml = np.clip(y_pred_duration_ml, 7, 365)
                    
                    y_pred_duration_rules = create_duration_based_predictions(df_pred)
                    
                    weight_ml = min(len(df_train) / 10, 0.7)
                    weight_rules = 1 - weight_ml
                    
                    y_pred_duration_combined = (weight_ml * y_pred_duration_ml + 
                                               weight_rules * y_pred_duration_rules.values)
                    
                except Exception as e:
                    y_pred_duration_combined = create_duration_based_predictions(df_pred).values
            else:
                y_pred_duration_combined = create_duration_based_predictions(df_pred).values
            
            # Calculer les dates de fin prédites
            predicted_dates = []
            for i, idx in enumerate(df_pred.index):
                pub_date = pd.to_datetime(df_pred.loc[idx, 'Publiée le']).tz_localize(None)
                predicted_duration = int(round(y_pred_duration_combined[i]))
                predicted_duration = max(7, predicted_duration)
                pred_date = pub_date + pd.Timedelta(days=predicted_duration)
                predicted_dates.append(pred_date)
            
            y_pred_dates = pd.Series(predicted_dates, index=df_pred.index)
            durations_predicted = [int(round(y_pred_duration_combined[i])) for i in range(len(df_pred))]
            
            predictions_count = len(y_pred_dates)
            avg_duration = np.mean(durations_predicted) if durations_predicted else 0
        
        # Stocker les résultats globalement
        _prediction_results = {
            'predictions_count': predictions_count,
            'avg_duration': float(avg_duration),
            'durations': durations_predicted,
            'train_size': len(df_train) if 'df_train' in locals() else 0,
            'pred_size': len(df_pred) if 'df_pred' in locals() else 0,
            'success': True
        }
        
        return _prediction_results
        
    except Exception as e:
        error_result = {'success': False, 'error': str(e)}
        _prediction_results = error_result
        return error_result

def run_clustering():
    """Fonction pour exécuter le clustering et retourner les résultats"""
    global _clustering_results
    
    try:
        df, label_encoders = load_and_prepare_data()
        if df is None:
            return {'success': False, 'error': 'Impossible de charger les données'}
        
        # Préparation des données pour clustering
        df_work = df.copy()
        
        # Encodage des variables catégorielles pour clustering
        for col in ['Base Severity', 'ID CWE', 'Vendeur', 'Type (Avis ou Alerte)']:
            enc_col = f"{col}_cluster_enc"
            if col in df_work.columns:
                le = LabelEncoder()
                df_work[enc_col] = le.fit_transform(df_work[col].astype(str))
        
        # Conversion des scores numériques
        df_work['Score CVSS'] = df_work['Score CVSS'].replace(['Pas de Score CVSS', 'Non disponible', ''], np.nan)
        df_work['Score CVSS'] = pd.to_numeric(df_work['Score CVSS'], errors='coerce')
        df_work['Score EPSS'] = df_work['Score EPSS'].replace(['Pas de Score EPSS', 'Non disponible', ''], np.nan)
        df_work['Score EPSS'] = pd.to_numeric(df_work['Score EPSS'], errors='coerce')
        
        # Ajout de features temporelles
        df_work['Publiée le'] = pd.to_datetime(df_work['Publiée le'], errors='coerce')
        df_work['Année'] = df_work['Publiée le'].dt.year
        df_work['Mois'] = df_work['Publiée le'].dt.month
        
        # Sélection des features pour le clustering
        features_cluster = [
            'Score CVSS', 'Score EPSS', 'Base Severity_cluster_enc', 'ID CWE_cluster_enc', 
            'Vendeur_cluster_enc', 'Type (Avis ou Alerte)_cluster_enc', 'Année', 'Mois'
        ]
        
        # Filtrer les lignes avec toutes les features disponibles
        df_cluster = df_work[features_cluster].dropna()
        
        if len(df_cluster) <= 10:
            return {'success': False, 'error': 'Pas assez de données pour le clustering'}
        
        # Test de différents nombres de clusters
        max_clusters = min(8, len(df_cluster) // 10)
        if max_clusters < 2:
            max_clusters = 2
        
        inertias = []
        silhouette_scores = []
        k_range = range(2, max_clusters + 1)
        
        # Standardisation
        scaler_cluster = StandardScaler()
        X_cluster = scaler_cluster.fit_transform(df_cluster)
        
        for k in k_range:
            kmeans_test = KMeans(n_clusters=k, random_state=42, n_init=10)
            labels_test = kmeans_test.fit_predict(X_cluster)
            inertias.append(kmeans_test.inertia_)
            sil_score = silhouette_score(X_cluster, labels_test)
            silhouette_scores.append(sil_score)
        
        # Choisir le k optimal
        optimal_k = k_range[np.argmax(silhouette_scores)]
        best_silhouette = max(silhouette_scores)
        
        # Clustering final avec le k optimal
        kmeans = KMeans(n_clusters=optimal_k, random_state=42, n_init=10)
        labels = kmeans.fit_predict(X_cluster)
        
        # Analyse des clusters
        df_cluster['cluster'] = labels
        df_work_indexed = df_work.loc[df_cluster.index].copy()
        df_work_indexed['cluster'] = labels
        
        cluster_summaries = []
        for i in range(optimal_k):
            cluster_data = df_work_indexed[df_work_indexed['cluster'] == i]
            
            if len(cluster_data) > 0:
                avg_cvss = cluster_data['Score CVSS'].mean()
                avg_epss = cluster_data['Score EPSS'].mean()
                
                # Top vendeurs et CWE
                top_vendors = cluster_data['Vendeur'].value_counts().head(3)
                top_cwes = cluster_data['ID CWE'].value_counts().head(3)
                
                # Calcul du score de criticité
                criticality_score = 0
                if avg_cvss >= 9.0:
                    criticality_score += 40
                elif avg_cvss >= 7.0:
                    criticality_score += 25
                elif avg_cvss >= 4.0:
                    criticality_score += 10
                
                if avg_epss > 0.5:
                    criticality_score += 30
                elif avg_epss > 0.1:
                    criticality_score += 15
                
                critical_count = len(cluster_data[cluster_data['Base Severity'] == 'CRITICAL'])
                criticality_score += (critical_count / len(cluster_data)) * 30
                
                cluster_summaries.append({
                    'cluster_id': i + 1,
                    'size': len(cluster_data),
                    'avg_cvss': float(avg_cvss) if not pd.isna(avg_cvss) else 0,
                    'avg_epss': float(avg_epss) if not pd.isna(avg_epss) else 0,
                    'criticality_score': float(criticality_score),
                    'top_vendor': top_vendors.index[0] if len(top_vendors) > 0 else 'N/A',
                    'top_cwe': top_cwes.index[0] if len(top_cwes) > 0 else 'N/A',
                    'critical_count': int(critical_count)
                })
        
        # Stocker les résultats globalement
        _clustering_results = {
            'clusters_count': int(optimal_k),
            'silhouette_score': float(best_silhouette),
            'data_size': len(df_cluster),
            'cluster_summaries': cluster_summaries,
            'success': True
        }
        
        return _clustering_results
        
    except Exception as e:
        error_result = {'success': False, 'error': str(e)}
        _clustering_results = error_result
        return error_result

def detect_critical_alerts():
    """Détecter les vulnérabilités critiques"""
    global _critical_alerts
    
    try:
        df, _ = load_and_prepare_data()
        if df is None:
            return {'success': False, 'error': 'Impossible de charger les données'}
        
        # Définition des critères de criticité
        critical_cvss = 9.0
        critical_severity = 'CRITICAL'
        now = pd.Timestamp.now()
        
        # Standardiser les timezones
        df['Publiée le'] = pd.to_datetime(df['Publiée le']).dt.tz_localize(None)
        df["Date de fin d'alerte"] = pd.to_datetime(df["Date de fin d'alerte"]).dt.tz_localize(None)
        
        # Calculer les jours restants
        df['base_severity_upper'] = df['Base Severity'].str.upper()
        df['days_to_end'] = (df["Date de fin d'alerte"] - now).dt.days
        
        # Critères de criticité
        crit_mask = (
            (pd.notna(df['Score CVSS']) & (df['Score CVSS'] >= critical_cvss)) |
            (df['base_severity_upper'] == critical_severity)
        ) & (
            (pd.isna(df["Date de fin d'alerte"])) |
            (df['days_to_end'] <= 7)
        )
        
        df_crit = df[crit_mask].copy()
        
        # Convertir en liste de dictionnaires pour JSON
        critical_alerts = []
        for idx, row in df_crit.iterrows():
            alert = {
                'cve_id': row.get('ID CVE', 'N/A'),
                'title': str(row.get('Titre', 'N/A'))[:100],
                'cvss_score': float(row.get('Score CVSS', 0)) if pd.notna(row.get('Score CVSS')) else None,
                'severity': row.get('Base Severity', 'N/A'),
                'vendor': str(row.get('Vendeur', 'N/A'))[:50],
                'end_date': row.get("Date de fin d'alerte").strftime('%Y-%m-%d') if pd.notna(row.get("Date de fin d'alerte")) else None,
                'days_remaining': int(row.get('days_to_end', 0)) if pd.notna(row.get('days_to_end')) else None,
                'link': row.get('Lien', 'N/A')
            }
            critical_alerts.append(alert)
        
        _critical_alerts = critical_alerts
        
        return {
            'success': True,
            'critical_count': len(critical_alerts),
            'alerts': critical_alerts
        }
        
    except Exception as e:
        return {'success': False, 'error': str(e)}

def get_dashboard_stats():
    """Obtenir les statistiques pour le dashboard"""
    try:
        df, _ = load_and_prepare_data()
        if df is None:
            return {'success': False, 'error': 'Impossible de charger les données'}
        
        stats = {
            'total_vulns': len(df),
            'critical_vulns': len(df[df['Base Severity'] == 'CRITICAL']),
            'avg_cvss': float(df['Score CVSS'].mean()) if not df['Score CVSS'].isna().all() else 0,
            'top_vendors': df['Vendeur'].value_counts().head(10).to_dict(),
            'severity_counts': df['Base Severity'].value_counts().to_dict(),
            'recent_vulns': len(df[df['Publiée le'] >= (pd.Timestamp.now() - pd.Timedelta(days=30))]),
            'success': True
        }
        
        return stats
        
    except Exception as e:
        return {'success': False, 'error': str(e)}

# Fonctions utilitaires pour l'intégration Django
def get_prediction_results():
    """Récupérer les résultats de prédiction stockés"""
    global _prediction_results
    return _prediction_results if _prediction_results else {'success': False, 'error': 'Aucun résultat de prédiction disponible'}

def get_clustering_results():
    """Récupérer les résultats de clustering stockés"""
    global _clustering_results
    return _clustering_results if _clustering_results else {'success': False, 'error': 'Aucun résultat de clustering disponible'}

def get_critical_alerts():
    """Récupérer les alertes critiques stockées"""
    global _critical_alerts
    return _critical_alerts if _critical_alerts else []

# Si le script est exécuté directement, lancez le code existant
if __name__ == "__main__":
    print("=== EXÉCUTION DU PIPELINE ML COMPLET ===")
    
    # Chargement et préparation des données
    print("\n1. Chargement des données...")
    df, label_encoders = load_and_prepare_data()
    
    if df is not None:
        print(f"✅ Données chargées : {len(df)} vulnérabilités")
        
        # Sélection des colonnes pour l'affichage
        display_columns = [
            "Identifiant ANSSI", "Titre", "Type (Avis ou Alerte)", "Publiée le",
            "Date de fin d'alerte", "ID CVE", "Score CVSS", "Base Severity",
            "Score EPSS", "ID CWE", "Description CWE", "Lien", "Description",
            "Vendeur", "Produit", "Version Affectés", "Différence en jours"
        ]
        
        # Filtrer les colonnes existantes
        existing_columns = [col for col in display_columns if col in df.columns]
        df_display = df[existing_columns]
        
        # Fonctions de nettoyage
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
        
        if "Vendeur" in df_display.columns:
            df_display["Vendeur"] = df_display["Vendeur"].apply(clean_vendor)
        if "Version Affectés" in df_display.columns:
            df_display["Version Affectés"] = df_display["Version Affectés"].apply(clean_versions)
        
        # Visualisations
        print("\n2. Génération des visualisations...")
        os.makedirs("diagrams", exist_ok=True)
        
        # 1. Histogramme des Scores CVSS
        plt.figure(figsize=(14, 7))
        sns.histplot(df_display['Score CVSS'], bins=20, kde=True, color='skyblue')
        plt.axvline(x=4.0, color='gold', linestyle='--', label='Moyen (4.0)')
        plt.axvline(x=7.0, color='orange', linestyle='--', label='Élevé (7.0)')
        plt.axvline(x=9.0, color='red', linestyle='--', label='Critique (9.0)')
        plt.title('Distribution des Scores de Gravité CVSS', fontsize=16)
        plt.xlabel('Score CVSS')
        plt.ylabel('Nombre de Vulnérabilités')
        plt.legend()
        plt.tight_layout()
        plt.savefig("diagrams/histogram_cvss.png", dpi=300)
        plt.close()
        
        # 2. Top des vendeurs
        if "Vendeur" in df_display.columns:
            plt.figure(figsize=(12, 8))
            top_vendors = df_display['Vendeur'].value_counts().nlargest(15)
            sns.barplot(x=top_vendors.values, y=top_vendors.index, palette='viridis')
            plt.title('Top 15 des Éditeurs les Plus Affectés par des Vulnérabilités', fontsize=16)
            plt.xlabel('Nombre Total de Vulnérabilités')
            plt.ylabel('Éditeur')
            plt.tight_layout()
            plt.savefig("diagrams/bar_top_vendors.png", dpi=300)
            plt.close()
        
        print("✅ Visualisations générées dans le dossier 'diagrams/'")
        
        # Exécution des prédictions
        print("\n3. Exécution des prédictions...")
        pred_results = run_predictions()
        if pred_results['success']:
            print(f"✅ Prédictions terminées : {pred_results['predictions_count']} prédictions")
            print(f"   Durée moyenne prédite : {pred_results['avg_duration']:.1f} jours")
        else:
            print(f"❌ Erreur prédictions : {pred_results['error']}")
        
        # Exécution du clustering
        print("\n4. Exécution du clustering...")
        cluster_results = run_clustering()
        if cluster_results['success']:
            print(f"✅ Clustering terminé : {cluster_results['clusters_count']} clusters")
            print(f"   Score de silhouette : {cluster_results['silhouette_score']:.3f}")
            print(f"   {cluster_results['data_size']} vulnérabilités analysées")
        else:
            print(f"❌ Erreur clustering : {cluster_results['error']}")
        
        # Détection des alertes critiques
        print("\n5. Détection des vulnérabilités critiques...")
        critical_results = detect_critical_alerts()
        if critical_results['success']:
            print(f"✅ {critical_results['critical_count']} vulnérabilités critiques détectées")
        else:
            print(f"❌ Erreur détection critique : {critical_results['error']}")
        
        # Statistiques du dashboard
        print("\n6. Génération des statistiques...")
        stats = get_dashboard_stats()
        if stats['success']:
            print(f"✅ Statistiques générées :")
            print(f"   Total vulnérabilités : {stats['total_vulns']}")
            print(f"   Vulnérabilités critiques : {stats['critical_vulns']}")
            print(f"   Score CVSS moyen : {stats['avg_cvss']:.2f}")
        
        print("\n🎉 PIPELINE ML TERMINÉ AVEC SUCCÈS")
        print("📊 Les résultats sont maintenant disponibles pour Django via les fonctions :")
        print("   - get_dashboard_stats()")
        print("   - get_prediction_results()")
        print("   - get_clustering_results()")
        print("   - get_critical_alerts()")
        
    else:
        print("❌ Impossible de charger les données")