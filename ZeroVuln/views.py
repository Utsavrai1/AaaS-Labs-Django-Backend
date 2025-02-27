import json
import nmap
import logging
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

# Configure logging
logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("nmap_scan.log"),
        logging.StreamHandler()
    ],
)

# Nmap scanner instance
scanner = nmap.PortScanner()

@csrf_exempt
def scan_ports(request):
    if request.method != "POST":
        logger.warning("Invalid request method for /scan_ports/")
        return JsonResponse({"error": "Only POST method is allowed"}, status=405)

    try:
        data = json.loads(request.body)
        target = data.get("target")
        arguments = data.get("arguments", "-F")  # Default to Fast Scan if no arguments provided

        if not target:
            logger.error("Missing target parameter in request body")
            return JsonResponse({"error": "Target URL is required"}, status=400)

        logger.info(f"Starting Nmap scan: target={target}, arguments={arguments}")
        scanner.scan(target, arguments=arguments)

        result = {"target": target, "state": "unknown", "open_ports": []}

        for host in scanner.all_hosts():
            result["state"] = scanner[host].state()
            if "tcp" in scanner[host]:
                for port, details in scanner[host]["tcp"].items():
                    result["open_ports"].append({"port": port, "state": details["state"]})

        logger.info(f"Scan completed for {target}: {result}")
        return JsonResponse(result)

    except json.JSONDecodeError:
        logger.error("Invalid JSON data received in request body")
        return JsonResponse({"error": "Invalid JSON data"}, status=400)
    except nmap.PortScannerError as e:
        logger.error(f"Nmap scan failed: {str(e)}")
        return JsonResponse({"error": f"Nmap scan failed: {str(e)}"}, status=500)
    except Exception as e:
        logger.exception(f"Unexpected error during scan: {str(e)}")
        return JsonResponse({"error": f"Unexpected error: {str(e)}"}, status=500)
