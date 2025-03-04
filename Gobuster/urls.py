from django.urls import path
from .views import scan_vulnerability

urlpatterns = [
    path('scan/', scan_vulnerability, name='scan_vulnerability'),
]
