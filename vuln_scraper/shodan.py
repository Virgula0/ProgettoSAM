import requests as r
import sys

url = "https://cvedb.shodan.io/cpes?product={product}"
cpe = "https://cvedb.shodan.io/cves?cpe23={cpe}"
cpe_key = "cpes"
cve_key ="cves"

def shodan_search(product, version) -> list:
    print(f"Searching for product... {product}")
    cpes_response = (r.get(url=url.format(product = product))).json()[cpe_key]
    print(f"Collected {len(cpes_response)} elements")
    collected = []
        
    for x in cpes_response:
        if x.split(":")[-1] == version:
            collected.append(x)

    return collected , len(collected)

def __shodan_cpe_search(product, version, collected) -> dict:
    vuln_collected = {}
    
    for x in collected:
        vuln_response = ((r.get(url=cpe.format(cpe=x))).json())[cve_key]
        vuln_collected[product+":"+version] = vuln_response
    
    return vuln_collected

def shodan_engine(product: str, version:str) -> dict:
    collected , _ = shodan_search(product=sys.argv[1], version=sys.argv[2])
    return __shodan_cpe_search(product=product, version=version , collected=collected)

# Tests from command line, not the prupose of this script
# Usage: python3 shodan.py xz 5.1.0
if __name__ == "__main__":
    
    if len(sys.argv)<1 or sys.argv[1] is None or sys.argv[1] == "":
        exit("Not a valid product input", -1)
        
    if len(sys.argv)<2 or sys.argv[2] is None or sys.argv[2] == "":
        exit("Not a valid version", -1)

    collected , length = shodan_search(product:=sys.argv[1], version:=sys.argv[2])
    print("Found -> " + str((collected,length)))

    if length > 0:
        print("CVE info -> " + str(__shodan_cpe_search(product=product, version=version , collected=collected)))