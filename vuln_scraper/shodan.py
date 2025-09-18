import requests as r
import sys

url = "https://cvedb.shodan.io/cpes?product={product}"
cpe = "https://cvedb.shodan.io/cves?cpe23={cpe}"
cpe_key = "cpes"

def shodan_search(product, version):
    print(f"Searching for product... {product}")
    cpes_response = (r.get(url=url.format(product = product))).json()[cpe_key]
    print(f"Collected {len(cpes_response)} elements")
    collected = []
        
    for x in cpes_response:
        if x.split(":")[-1] == version:
            collected.append(x)
            
    return collected , len(collected)

if sys.argv[1] is None or sys.argv[1] == "":
    exit("Not a valid product input", -1)
    
if sys.argv[2] is None or sys.argv[2] == "":
    exit("Not a valid version", -1)

print("Found -> " + str(shodan_search(product=sys.argv[1], version=sys.argv[2])))
