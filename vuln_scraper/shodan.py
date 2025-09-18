import requests as r
import urllib
import sys

class Shodan:
    def __init__(self):
        self.url = "https://cvedb.shodan.io/cpes?product={product}"
        self.cpe =  "https://cvedb.shodan.io/cves?cpe23={cpe}"
        self.cpe_key = "cpes"
        self.cve_key = "cves"
    
    def shodan_engine(self, product: str, version:str) -> list:
        collected , length = self.__shodan_search(product=product, version=version)
        
        if length > 0:
            return self.__shodan_cpe_search(product=product, version=version , collected=collected)
            
        return None

    def __shodan_search(self, product, version) -> list:
        print(f"Searching for product... {product}")
        product = urllib.parse.quote(product)
        cpes_response = (r.get(url=self.url.format(product=product))).json()[self.cpe_key]
        print(f"Collected {len(cpes_response)} elements")
        collected = []
            
        for x in cpes_response:
            if x.split(":")[-1] == version:
                collected.append(x)

        return collected , len(collected)

    def __shodan_cpe_search(self, product, version, collected) -> dict:
        vuln_collected = {}  
        for x in collected:
            vuln_response = ((r.get(url=self.cpe.format(cpe=x))).json())[self.cve_key]
            for el in vuln_response:
                vuln_collected[product+":"+version+":"+el['cve_id']] = vuln_response
        
        return vuln_collected


# Tests from command line, not the prupose of this script
# Usage: python3 shodan.py xz 5.1.0
if __name__ == "__main__":
    
    if len(sys.argv)<1 or sys.argv[1] is None or sys.argv[1] == "":
        exit("Not a valid product input")
        
    if len(sys.argv)<2 or sys.argv[2] is None or sys.argv[2] == "":
        exit("Not a valid version")

    s = Shodan()
    
    collected = s.shodan_engine(product:=sys.argv[1], version:=sys.argv[2])
    print("Found -> " + str((collected)))