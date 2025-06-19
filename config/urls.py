from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('ml_dashboard.urls')),  # Inclut les URLs de l'app ml_dashboard
]