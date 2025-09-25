import requests as r
import pandas as pd
import glob
import os
import csv

vulns = [
    # Injection
    'sql injection', 'sqli',
    'nosql injection', 'nosqli',
    'ldap injection',
    'xpath injection',
    'command injection', 'os command injection',
    'expression language injection', 'el injection',
    'template injection', 'ssti', 'server-side template injection',
    'server side template injection', 'template injection',
    'xpathi', 'xpath injection',
    
    # SSRF & related
    'ssrf', 'server side request forgery',
    'blind ssrf',

    # Race conditions
    'race condition', 'race conditions',
    'toctou', 'time of check time of use',

    # CSRF
    'csrf', 'cross site request forgery',
    'xsrf', 'cross site request forgery attack',

    # XSS
    'xss', 'cross site scripting', 'cross-site scripting',
    'stored xss', 'reflected xss', 'dom xss',

    # Deserialization
    'object deserialization',
    'insecure deserialization',
    'object injection',
    'serialization attack',

    # Prototype Pollution
    'prototype pollution',
    'prototype',
    '__proto__',

    # XXE
    'xxe', 'xml external entities', 'xml external entity',
    'xml injection',

    # IDOR / BOLA
    'idor', 'insecure direct object reference',
    'bola', 'broken object level authorization',
    'bfla', 'broken function level authorization',

    # Authentication / AuthZ
    'broken authentication',
    'weak authentication',
    'credential stuffing',
    'session fixation',
    'session hijacking',
    'jwt attack', 'jwt none algorithm', 'jwt vulnerabilities','jwt'
    'brute force',

    # RCE
    'rce', 'remote code execution', 'remote command execution',
    'command execution', 'arbitrary code execution', 'javascript execution', 'eval'

    # Injection variants
    'html injection',
    'http header injection',
    'host header injection',
    'crlf injection', 'crlfi',

    # Hijacking / takeover
    'hijacking',
    'subdomain takeover',
    'dns rebinding',

    # Weak secrets
    'weak password',
    'weak secret',
    'hardcoded credentials',
    'default credentials',

    # File/path issues
    'path traversal',
    'directory traversal',
    'lfi', 'local file inclusion',
    'rfi', 'remote file inclusion',
    'zip slip',
    'symlink attack',

    # Type/system-level issues
    'type juggling',
    'insecure type casting',

    # HTTP request issues
    'request smuggling',
    'request splitting',
    'http desync attack',

    # Injections (other)
    'object injection',
    'xpath injection',
    'graphql injection',
    'graphql abuse',

    # Clickjacking
    'clickjacking', 'ui redressing',

    # DoS
    'dos', 'denial of service', 'denial-of-service',
    'redos', 're-dos', 'regular expression denial of service',
    'application-level dos',
    'algorithmic complexity attack',

    # Input validation
    'improper input validation',
    'improper input sanitization',
    'improper sanitization',
    'insufficient input validation',
    'insufficient validation',
    'insufficient sanitization',
    'sanitization',

    # Misc
    'insecure randomness',
    'insecure file upload',
    'open redirect',
    'open redirection',
    'unvalidated redirect',
    'business logic flaw',
    'logic bugs',
    'information disclosure',
    'insecure configuration',
    'sensitive data exposure',
    'directory indexing',
    'directory listing',
    'privilege escalation',
    'mass assignment',
    
    'clear-text private key',
    'mitm','man in the middle',
    'buffer overflow',
    'heap overflow',
    'overflow',
    'oauth bypass',
    'oauth',
    'backdoor',
    'malicious code',
    'malware',
    'crash',
    'arbitrary file write',
    'arbitrary file read',
    'arbitrary commands',
    'access control',
    'missing encryption',
    'unencrypted authentication data',
    'unencrypted data',
]

mitre_url = 'https://cveawg.mitre.org/api/cve/{cve}'
output_dir = '../output'
out_file_name = 'cve_parser.csv'

def mitre_request(cve):
    response = r.get(url=mitre_url.format(cve=cve))
    
    if response.status_code != 200:
        return {}
    
    response = response.json()
        
    title = (response['containers']['cna']['title']).lower() if 'title' in response['containers']['cna'] else 'NO TITLE'
    descs = response['containers']['cna']['descriptions'] if 'descriptions' in response['containers']['cna'] else []
    
    category = next((x for x in vulns if x in title.lower() or any(x in y.lower() for y in [z['value'] for z in descs])),
        'UNKNOWN'
    )    
    
    score = ', '.join(
        str(v['baseScore'])
        for m in response.get('containers', {}).get('cna', {}).get('metrics', [])
        for v in m.values()
        if isinstance(v, dict) and 'baseScore' in v
    )

    cwes = ', '.join(
        y.get('cweId', '')
        for pt in response.get('containers', {}).get('cna', {}).get('problemTypes', [])
        for z in pt.get('descriptions', [])
        for y in [z] if 'cweId' in z
    )
    
    result = {
        'cve' : cve ,
        'category': category,
        'scores': score, 
        'cwes': cwes
    }
        
    return result

def process_csv(df) -> set:
    cves = set()
    if "cve_strings" not in df.columns:
        return cves  # return empty if column missing
    
    for val in df["cve_strings"].dropna():
        # Split by comma, strip whitespace
        for cve in str(val).split(","):
            cve = cve.strip()
            if cve:  # ensure non-empty
                if cve.startswith("CVE"): # other junk format may be present in the csv
                    cves.add(cve)
                    
    return cves


if __name__ == '__main__':
    cves = set()
    
    for file in glob.glob(os.path.join(output_dir,'*.csv')):
        path = os.path.join(output_dir,file)
        print(f"Parsing file: {file}:{path}")
        df = pd.read_csv(path)
        cves.update(process_csv(df))
    
    print(f"Total unique CVEs found: {len(cves)}")
    
    keys = [
        'cve',
        'category',
        'scores',
        'cwes'
    ]
    
    with open(os.path.join(os.path.join(output_dir,out_file_name)), "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=keys)
        writer.writeheader()

    count = 0
    
    for cve in cves:
        count+=1 
        print(f"Reached {count} over {len(cves)}")
        result = mitre_request(cve)
        with open(os.path.join(os.path.join(output_dir,out_file_name)), "a", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=keys)
            writer.writerow(result)
        