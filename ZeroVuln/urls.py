from django.urls import path
from .views import scan_ports

urlpatterns = [
    path('scan/', scan_ports, name='scan_ports'),
]