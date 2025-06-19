from django.shortcuts import render
from django.http import JsonResponse
import pandas as pd
import numpy as np
import os
import sys
from pathlib import Path

# Ajouter le chemin vers votre script ML
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.append(str(BASE_DIR / 'models'))

# Dans ml_dashboard/views.py, modifier la fonction dashboard :

def dashboard(request):
    """Vue principale du dashboard"""
    try:
        # Charger les données via votre fonction ML
        from models.model_py import get_dashboard_stats
        
        stats = get_dashboard_stats()
        
        if stats['success']:
            # Préparer les données pour les graphiques
            top_vendors_items = list(stats['top_vendors'].items())[:10]
            severity_items = list(stats['severity_counts'].items())
            
            # Calculer les valeurs maximales pour les pourcentages
            max_vendor_count = max([count for _, count in top_vendors_items]) if top_vendors_items else 1
            max_severity_count = max([count for _, count in severity_items]) if severity_items else 1
            
            context = {
                'total_vulns': stats['total_vulns'],
                'critical_vulns': stats['critical_vulns'],
                'avg_cvss': round(stats['avg_cvss'], 2) if stats['avg_cvss'] else 'N/A',
                'top_vendors_items': top_vendors_items,
                'severity_items': severity_items,
                'max_vendor_count': max_vendor_count,
                'max_severity_count': max_severity_count,
            }
            
            return render(request, 'ml_dashboard/index.html', context)
        else:
            return render(request, 'ml_dashboard/error.html', {'error': stats['error']})
        
    except Exception as e:
        return render(request, 'ml_dashboard/error.html', {'error': str(e)})

def predictions(request):
    """Vue pour les prédictions ML"""
    try:
        # Importer et exécuter votre code ML
        from models.model_py import run_predictions
        
        predictions_data = run_predictions()
        
        context = {
            'predictions': predictions_data,
        }
        
        return render(request, 'ml_dashboard/predictions.html', context)
        
    except Exception as e:
        return render(request, 'ml_dashboard/error.html', {'error': str(e)})

def clustering(request):
    """Vue pour l'analyse de clustering"""
    try:
        # Importer et exécuter votre code de clustering
        from models.model_py import run_clustering
        
        clustering_data = run_clustering()
        
        context = {
            'clusters': clustering_data,
        }
        
        return render(request, 'ml_dashboard/clustering.html', context)
        
    except Exception as e:
        return render(request, 'ml_dashboard/error.html', {'error': str(e)})

def api_data(request):
    """API pour récupérer les données en JSON"""
    try:
        df = pd.read_csv(BASE_DIR / 'data' / 'cve_cleaned_for_df.csv')
        
        # Convertir en JSON
        data = df.head(100).to_dict('records')  # Limiter à 100 pour la performance
        
        return JsonResponse({
            'status': 'success',
            'data': data,
            'count': len(data)
        })
        
    except Exception as e:
        return JsonResponse({
            'status': 'error',
            'message': str(e)
        })