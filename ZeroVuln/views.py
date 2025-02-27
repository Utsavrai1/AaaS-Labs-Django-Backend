import json
import nmap
import logging
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("nmap_scan.log"),
        logging.StreamHandler()
    ],
)

scanner = nmap.PortScanner()

@csrf_exempt
def scan_ports(request):
    if request.method != "POST":
        logger.warning("Invalid request method for /scan_ports/")
        return JsonResponse({"error": "Only POST method is allowed"}, status=405)

    try:
        # Parse JSON request body
        data = json.loads(request.body)
        target = data.get("target")
        arguments = data.get("arguments", "-F")  # Default: Fast Scan

        if not target:
            logger.error("Missing target parameter in request body")
            return JsonResponse({"error": "Target URL is required"}, status=400)

        # Log the scan details
        logger.info(f"Starting Nmap scan: target={target}, arguments={arguments}")
        scanner.scan(target, arguments=arguments)

        # Return the full scan result
        full_result = scanner._scan_result

        logger.info(f"Scan completed for {target}")
        return JsonResponse(full_result, safe=False)

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
    Returns all available Nmap arguments, categorized by type with descriptions.
    """
    if request.method != "GET":
        logger.warning("Invalid request method for /get_nmap_arguments/")
        return JsonResponse({"error": "Only GET method is allowed"}, status=405)

    try:
        scanner = nmap.PortScanner()
        nmap_version = scanner.nmap_version()

        # Categorized Nmap Arguments with Descriptions
        nmap_arguments = {
            "scan_types": {
                "-sS": "TCP SYN scan (Stealth Scan)",
                "-sT": "TCP Connect scan",
                "-sU": "UDP scan",
                "-sN": "TCP NULL scan (No flags set)",
                "-sF": "TCP FIN scan",
                "-sX": "TCP Xmas scan (FIN, PSH, URG set)",
                "-sA": "TCP ACK scan",
                "-sW": "TCP Window scan",
                "-sM": "TCP Maimon scan"
            },
            "host_discovery": {
                "-Pn": "Disable host discovery, scan all given targets",
                "-PS": "TCP SYN Ping",
                "-PA": "TCP ACK Ping",
                "-PU": "UDP Ping",
                "-PY": "SCTP INIT Ping",
                "-PE": "ICMP Echo Request Ping",
                "-PP": "ICMP Timestamp Request Ping",
                "-PM": "ICMP Netmask Request Ping",
                "-sn": "Ping Scan - Only discover hosts without port scan"
            },
            "timing_options": {
                "-T0": "Paranoid (slowest, avoids detection)",
                "-T1": "Sneaky (very slow, evades detection)",
                "-T2": "Polite (reduces bandwidth, slow)",
                "-T3": "Normal (default timing)",
                "-T4": "Aggressive (faster, might alert firewalls)",
                "-T5": "Insane (fastest, high network load)"
            },
            "port_options": {
                "-F": "Fast scan (only scans 100 most common ports)",
                "-p": "Specify port range (e.g., -p 80,443,8080)"
            },
            "OS_detection": {
                "-O": "Enable OS detection"
            },
            "version_detection": {
                "-sV": "Service version detection"
            },
            "script_scan": {
                "-sC": "Run default Nmap scripts"
            },
            "traceroute": {
                "--traceroute": "Trace network path to target"
            },
            "aggressive_scan": {
                "-A": "Aggressive scan (OS, version detection, scripts, traceroute)"
            }
        }

        logger.info("Fetched available Nmap arguments successfully")
        return JsonResponse({"nmap_version": nmap_version, "supported_arguments": nmap_arguments})

    except Exception as e:
        logger.exception(f"Failed to fetch Nmap arguments: {str(e)}")
        return JsonResponse({"error": f"Failed to fetch Nmap arguments: {str(e)}"}, status=500)