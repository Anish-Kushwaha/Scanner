"""
ANISH SECURITY SCANNER v3.2
"""
import json
import socket
import dns.resolver
import requests
from datetime import datetime
from urllib.parse import urlparse

# ==================== SECURITY SCANNER ====================
def scan_target(target_url):
    """Main scanning function"""
    try:
        # Parse URL
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'http://' + target_url
        
        parsed = urlparse(target_url)
        domain = parsed.netloc.split(':')[0]
        
        # Resolve IP
        ip = socket.gethostbyname(domain)
        
        # Scan ports
        open_ports = []
        ports_to_scan = [21, 22, 23, 25, 53, 80, 110, 443, 3306, 3389, 8080, 8443]
        
        for port in ports_to_scan:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            except:
                pass
        
        # DNS lookup
        dns_info = {}
        try:
            answers = dns.resolver.resolve(domain, 'A')
            dns_info['A'] = [str(r) for r in answers]
        except:
            dns_info['A'] = []
        
        # Geolocation
        geolocation = {}
        try:
            resp = requests.get(f'http://ip-api.com/json/{ip}', timeout=3)
            geolocation = resp.json()
        except:
            geolocation = {'error': 'Geolocation failed'}
        
        # Build response
        return {
            "success": True,
            "timestamp": datetime.now().isoformat(),
            "target_info": {
                "original": target_url,
                "domain": domain,
                "ip": ip,
                "parsed_url": target_url
            },
            "scan_results": {
                "open_ports": open_ports,
                "dns_records": dns_info,
                "geolocation": geolocation,
                "total_ports_scanned": len(ports_to_scan),
                "open_ports_count": len(open_ports)
            },
            "risk_assessment": {
                "level": "HIGH" if len(open_ports) > 5 else "MEDIUM" if len(open_ports) > 2 else "LOW",
                "message": f"Found {len(open_ports)} open ports on {domain}"
            }
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }

# ==================== VERCEL SERVERLESS HANDLER ====================
def handler(request, response):
    """
    Vercel Serverless Function Handler
    IMPORTANT: This is the CORRECT signature for Vercel
    """
    
    # Handle CORS preflight
    if request.method == 'OPTIONS':
        response.status_code = 200
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
        return
    
    # Handle GET request (health check)
    if request.method == 'GET':
        response.status_code = 200
        response.headers['Content-Type'] = 'application/json'
        response.headers['Access-Control-Allow-Origin'] = '*'
        
        health_data = {
            "status": "online",
            "service": "Vulnerability Scanner v3.2",
            "version": "3.2.0",
            "endpoints": {
                "scan": "POST /api with JSON: {\"target\": \"example.com\"}",
                "health": "GET /api"
            },
            "creator": "Anish Kushwaha",
            "website": "Anish-kushwaha.b12sites.com",
            "warning": "⚠️ FOR AUTHORIZED SECURITY TESTING ONLY"
        }
        
        response.body = json.dumps(health_data, indent=2)
        return
    
    # Handle POST request (scan)
    if request.method == 'POST':
        try:
            # Parse JSON body
            body = request.body
            if isinstance(body, bytes):
                body = body.decode('utf-8')
            
            data = json.loads(body)
            target = data.get('target', '').strip()
            
            if not target:
                response.status_code = 400
                response.headers['Content-Type'] = 'application/json'
                response.headers['Access-Control-Allow-Origin'] = '*'
                response.body = json.dumps({
                    "error": "Target URL is required",
                    "example": {"target": "example.com"}
                })
                return
            
            # Run the scan
            scan_results = scan_target(target)
            
            # Send response
            response.status_code = 200
            response.headers['Content-Type'] = 'application/json'
            response.headers['Access-Control-Allow-Origin'] = '*'
            response.body = json.dumps(scan_results, indent=2)
            
        except json.JSONDecodeError:
            response.status_code = 400
            response.headers['Content-Type'] = 'application/json'
            response.body = json.dumps({"error": "Invalid JSON format"})
            
        except Exception as e:
            response.status_code = 500
            response.headers['Content-Type'] = 'application/json'
            response.body = json.dumps({"error": f"Scan failed: {str(e)}"})
        
        return
    
    # Handle other methods
    response.status_code = 405
    response.headers['Content-Type'] = 'application/json'
    response.body = json.dumps({"error": "Method not allowed"})

# ==================== FOR LOCAL TESTING ====================
if __name__ == "__main__":
    # This allows testing locally
    print("🔐 Vulnerability Scanner v3.2")
    print("🔧 Local testing mode")
    print("=" * 50)
    
    # Test the scanner
    test_result = scan_target("example.com")
    print(json.dumps(test_result, indent=2))
