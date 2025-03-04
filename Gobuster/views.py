import json
import subprocess
import os
import re
import logging
from datetime import datetime
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
import tempfile
from urllib.parse import urlparse

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@csrf_exempt
@require_http_methods(["POST"])
def scan_vulnerability(request):
    try:
        data = json.loads(request.body)
        target_url = data.get('url')
        
        # Validate URL
        if not target_url:
            return JsonResponse({'error': 'URL is required'}, status=400)
        
        # Ensure URL has a scheme
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'http://' + target_url
        
        parsed_url = urlparse(target_url)
        domain = parsed_url.netloc
        
        logger.info(f"Starting vulnerability scan for {target_url}")
        
        # Run Gobuster
        gobuster_results = run_gobuster(target_url)
        
        # Structure the data
        structured_data = {
            'target_url': target_url,
            'scan_date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'directories_found': gobuster_results['directories'],
            'files_found': gobuster_results['files'],
            'total_findings': len(gobuster_results['directories']) + len(gobuster_results['files']),
        }
        
        # Add additional scan results if requested and available
        try:
            if data.get('run_nikto', False):
                logger.info("Running Nikto scan")
                structured_data['nikto_scan'] = run_nikto(target_url)
            
            if data.get('run_nmap', False):
                logger.info("Running Nmap scan")
                structured_data['nmap_scan'] = run_nmap(domain)
            
            if data.get('run_sqlmap', False) and data.get('test_url'):
                logger.info("Running SQLMap scan")
                structured_data['sqlmap_scan'] = run_sqlmap(data.get('test_url'))
            
            if data.get('run_wpscan', False) and is_wordpress_site(target_url):
                logger.info("Running WPScan")
                structured_data['wpscan_results'] = run_wpscan(target_url)
        
        except Exception as scan_error:
            logger.error(f"Error in additional scans: {str(scan_error)}")
            structured_data['scan_errors'] = str(scan_error)
        
        logger.info("Vulnerability scan completed successfully")
        return JsonResponse(structured_data)
    
    except Exception as e:
        logger.error(f"Vulnerability scan failed: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)

def run_gobuster(url):
    """Run Gobuster against the target URL and parse results"""
    logger.info(f"Running Gobuster for {url}")
    
    # Create a temporary file to store the results
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_file_path = temp_file.name
    
    # Define the wordlist path with a smaller, faster list
    wordlist = "/usr/share/wordlists/dirb/common.txt"
    
    # Run Gobuster command with optimizations
    try:
        cmd = [
            "gobuster", "dir",
            "--url", url,
            "--wordlist", wordlist,
            "--quiet",
            "-k",  # Skip SSL verification
            "-t", "50",  # Increase threads for speed
            "-r",  # Follow redirects
            "--output", temp_file_path
        ]
        
        process = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=600,  # 10-minute timeout
            check=True
        )
        
        # Read the results from the temporary file
        with open(temp_file_path, 'r') as f:
            results = f.read()
        
        # Clean up the temporary file
        os.unlink(temp_file_path)
        
        # Parse the results
        return parse_gobuster_results(results)
    
    except subprocess.CalledProcessError as e:
        logger.error(f"Gobuster scan failed: {e.stderr}")
        # Clean up the temporary file if it exists
        if os.path.exists(temp_file_path):
            os.unlink(temp_file_path)
        
        # Return empty results if Gobuster fails
        return {
            "directories": [],
            "files": []
        }
    except Exception as e:
        logger.error(f"Unexpected error in Gobuster: {str(e)}")
        return {
            "directories": [],
            "files": []
        }

def parse_gobuster_results(results):
    """Parse Gobuster output and separate directories from files"""
    directories = []
    files = []
    
    # More robust regex to handle various Gobuster output formats
    pattern = re.compile(r'^/([\w\-\.]+)(?:/\s*)?.*\(Status:\s*(\d+)\)', re.MULTILINE)
    
    for match in pattern.finditer(results):
        path = match.group(1)
        status = int(match.group(2))
        
        # Determine if it's a file or directory
        if '.' in path.split('/')[-1]:
            files.append({
                'path': f"/{path}",
                'status': status
            })
        else:
            directories.append({
                'path': f"/{path}",
                'status': status
            })
    
    return {
        "directories": directories,
        "files": files
    }

def run_nikto(url):
    """Run Nikto against the target URL and return results"""
    try:
        logger.info(f"Running Nikto scan on {url}")
        # Updated Nikto command to include output file
        with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='.json') as temp_output:
            cmd = [
                "nikto", 
                "-h", url, 
                "-Format", "json", 
                "-o", temp_output.name,  # Specify output file
                "-timeout", "300"  # 5-minute timeout
            ]
        
            process = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=600  # 10 minute total timeout
            )
        
        # Read the output file
        try:
            with open(temp_output.name, 'r') as f:
                nikto_results = json.load(f)
            os.unlink(temp_output.name)  # Delete temp file
            return nikto_results
        except Exception as file_error:
            logger.warning(f"Failed to read Nikto output: {file_error}")
            return {
                "raw_output": process.stdout,
                "error": str(file_error)
            }
    
    except Exception as e:
        logger.error(f"Nikto scan failed: {str(e)}")
        return {
            "error": str(e),
            "raw_output": None
        }

def run_nmap(domain):
    """Run basic Nmap scan against the domain and return results"""
    try:
        cmd = ["nmap", "-sV", "-F", "--open", domain]
        process = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=300  # 5 minute timeout
        )
        
        # Parse Nmap output
        open_ports = []
        current_port = None
        
        for line in process.stdout.splitlines():
            port_match = re.search(r'^(\d+)/(\w+)\s+(\w+)\s+(.*)$', line.strip())
            if port_match:
                port_number, protocol, state, service = port_match.groups()
                current_port = {
                    "port": int(port_number),
                    "protocol": protocol,
                    "state": state,
                    "service": service
                }
                open_ports.append(current_port)
        
        return {
            "open_ports": open_ports,
            "raw_output": process.stdout
        }
    
    except Exception as e:
        return {
            "error": str(e),
            "raw_output": None
        }

def run_sqlmap(url):
    """Run SQLMap against the target URL and return results"""
    try:
        cmd = [
            "sqlmap", 
            "-u", url, 
            "--batch", 
            "--level=1", 
            "--risk=1",
            "--output-dir=/tmp/sqlmap",
            "--forms"
        ]
        
        process = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=600  # 10 minute timeout
        )
        
        # Parse SQLMap output looking for vulnerabilities
        vulnerabilities = []
        
        # Look for SQLi detection in output
        if "is vulnerable" in process.stdout:
            for line in process.stdout.splitlines():
                if "is vulnerable" in line:
                    vulnerabilities.append(line.strip())
        
        return {
            "vulnerabilities": vulnerabilities,
            "raw_output": process.stdout
        }
    
    except Exception as e:
        return {
            "error": str(e),
            "raw_output": None
        }

def is_wordpress_site(url):
    """Check if the site is running WordPress"""
    try:
        cmd = ["curl", "-s", "-L", f"{url}/wp-login.php"]
        process = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30
        )
        
        return "WordPress" in process.stdout
    except:
        return False

def run_wpscan(url):
    """Run WPScan against the WordPress site with improved error handling"""
    try:
        cmd = [
            "wpscan",
            "--url", url,
            "--format", "json",
            "--no-banner",
            "--random-user-agent",  # Added to bypass WAF
            "--disable-tls-checks"  # Added to handle SSL issues
        ]
        
        process = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=600  # 10 minute timeout
        )
        
        # Improved error handling and logging
        if process.returncode != 0:
            logger.warning(f"WPScan returned non-zero exit code: {process.stderr}")
        
        # Try to parse JSON output
        try:
            return json.loads(process.stdout) if process.stdout else {"error": "No output"}
        except json.JSONDecodeError:
            return {
                "raw_output": process.stdout,
                "error": process.stderr
            }
    
    except Exception as e:
        logger.error(f"WPScan failed: {str(e)}")
        return {
            "error": str(e),
            "raw_output": None
        }