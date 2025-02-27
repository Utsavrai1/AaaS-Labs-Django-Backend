import nmap
from django.http import JsonResponse

def scan_ports(request):
    target = request.GET.get('target', 'prosign.prostructproposal.com')
    scanner = nmap.PortScanner()
    
    scanner.scan(target, arguments="-F")  # Fast scan
    
    result = {"target": target, "state": "unknown", "open_ports": []}
    
    for host in scanner.all_hosts():
        result["state"] = scanner[host].state()
        if 'tcp' in scanner[host]:
            for port, details in scanner[host]['tcp'].items():
                result["open_ports"].append({"port": port, "state": details['state']})
    
    return JsonResponse(result)