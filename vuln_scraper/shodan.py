import requests as r
import urllib
import re
import sys

class Shodan:
    def __init__(self):
        self.url = "https://cvedb.shodan.io/cpes?product={product}"
        self.cpe =  "https://cvedb.shodan.io/cves?cpe23={cpe}"
        self.__product_regex = r'^(?:@([a-z0-9][a-z0-9._-]*)/)?([a-z0-9][a-z0-9._-]*)$'
        self.__version_regex = r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-(?:0|[1-9]\d*|[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|[a-zA-Z-][0-9a-zA-Z-]*))*)?(?:\+[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*)?$"
        self.cpe_key = "cpes"
        self.cve_key = "cves"
        self.__product_error = "Regex does not match the format of npm package"
        self.__version_error = "Version format of npm package not valid"

    def __extract_simple_product(self, product):
        match = re.compile(self.__product_regex).fullmatch(product.strip())

        if not match:
            raise ValueError(f"Invalid npm package name: {product}")
        
        scope, name = match.groups()
        return scope if scope else name

    def shodan_engine(self, product: str, version:str) -> list:

        if re.match(self.__product_regex, product) is None:
            raise ValueError(self.__product_error)

        if re.match(self.__version_regex, version) is None:
            raise ValueError(self.__version_error)
        
        product = self.__extract_simple_product(product=product)

        collected = self.__shodan_search(product=product, version=version)
        
        if len(collected) > 0:
            return self.__shodan_cpe_search(product=product, version=version , collected=collected)
            
        return None

    def __shodan_search(self, product, version) -> list:
        product = urllib.parse.quote_plus(product)
        
        response = r.get(url=self.url.format(product=product))

        if response.status_code == 404:
            return []

        cpes_response = response.json()[self.cpe_key]
        collected = []
            
        for x in cpes_response:
            if x.split(":")[-1] == version:
                collected.append(x)

        return collected

    def __shodan_cpe_search(self, product, version, collected) -> dict:
        vuln_collected = {}  
        for x in collected:
            vuln_response = ((r.get(url=self.cpe.format(cpe=x))).json())[self.cve_key]
            for el in vuln_response:
                vuln_collected[product+":"+version+":"+el['cve_id']] = vuln_response
        
        return vuln_collected


# Tests from command line, not the prupose of this script
# Usage: python3 shodan.py '@babel/cli' 7.10.5
# python3 shodan.py 'xz' 5.1.0
if __name__ == "__main__":
    
    if len(sys.argv)<1 or sys.argv[1] is None or sys.argv[1] == "":
        exit("Not a valid product input")
        
    if len(sys.argv)<2 or sys.argv[2] is None or sys.argv[2] == "":
        exit("Not a valid version")

    s = Shodan()
    
    collected = s.shodan_engine(product:=sys.argv[1], version:=sys.argv[2])
    print("Found -> " + str((collected)))