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

@csrf_exempt
def get_nmap_arguments(request):
    """
    Returns all available Nmap arguments from the `nmap` command.
    """
    if request.method != "GET":
        logger.warning("Invalid request method for /get_nmap_arguments/")
        return JsonResponse({"error": "Only GET method is allowed"}, status=405)

    try:
        help_output = scanner.nmap_version()
        arguments = [
            "-sS", "-sT", "-sU", "-sN", "-sF", "-sX", "-sA", "-sW", "-sM",
            "-Pn", "-PS", "-PA", "-PU", "-PY", "-PE", "-PP", "-PM",
            "-sn", "-O", "-F", "-p", "-T0", "-T1", "-T2", "-T3", "-T4", "-T5"
        ]  # A subset of common arguments

        logger.info("Fetched available Nmap arguments")
        return JsonResponse({"nmap_version": help_output, "supported_arguments": arguments})

    except Exception as e:
        logger.exception(f"Failed to fetch Nmap arguments: {str(e)}")
        return JsonResponse({"error": f"Failed to fetch Nmap arguments: {str(e)}"}, status=500)