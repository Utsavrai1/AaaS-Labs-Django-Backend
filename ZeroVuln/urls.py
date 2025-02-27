from django.urls import path
from .views import scan_ports, get_nmap_arguments

urlpatterns = [
    path('scan/', scan_ports, name='scan_ports'),
    path('arguments/', get_nmap_arguments, name='get_nmap_arguments'),
]