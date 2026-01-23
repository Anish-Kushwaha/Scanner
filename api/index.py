import json

def handler(request, response):
    response.status_code = 200
    response.headers['Content-Type'] = 'application/json'
    
    result = {
        "status": "online",
        "service": "Anish Security Scanner v3.2",
        "message": "Scanner is working!",
        "creator": "Anish Kushwaha",
        "website": "Anish-kushwaha.b12sites.com"
    }
    
    response.body = json.dumps(result)
