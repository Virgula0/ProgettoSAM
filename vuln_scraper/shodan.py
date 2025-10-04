import requests as r
import urllib
import re
import sys

class Shodan:
    def __init__(self):
        self.url = "https://cvedb.shodan.io/cpes?product={product}"
        self.cpe =  "https://cvedb.shodan.io/cves?cpe23={cpe}"
        self.cve_url = "https://cvedb.shodan.io/cve/{cve}"
        self.__cve_regex = r'CVE-\d{4}-\d{4,7}'
        self.__product_regex = r'^(?:@([a-z0-9][a-z0-9._-]*)/)?([a-z0-9][a-z0-9._-]*)$'
        self.__version_regex = r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-(?:0|[1-9]\d*|[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|[a-zA-Z-][0-9a-zA-Z-]*))*)?(?:\+[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*)?$"
        self.cpe_key = "cpes"
        self.cve_key = "cves"
        self.__product_error = "Regex does not match the format of npm package"
        self.__version_error = "Version format of npm package not valid"
        self.__cve_error_regex="Passed argument does not match cve format for {cve}"

    def __extract_simple_product(self, product):
        match = re.compile(self.__product_regex).fullmatch(product.strip())

        if not match:
            raise ValueError(f"Invalid npm package name: {product}")
        
        scope, name = match.groups()
        return scope if scope else name

    def shodan_engine(self, product: str, version:str) -> list|None:

        if re.match(self.__product_regex, product) is None:
            raise ValueError(self.__product_error)

        if re.match(self.__version_regex, version) is None:
            raise ValueError(self.__version_error)
        
        product = self.__extract_simple_product(product=product)

        collected = self.__shodan_search(product=product, version=version)
        
        if len(collected) > 0:
            return self.__shodan_cpe_search(collected=collected)
            
        return None

    def __shodan_search(self, product, version) -> list:
        product = urllib.parse.quote_plus(product)
        
        response = r.get(url=self.url.format(product=product),timeout=10)

        if response.status_code == 404:
            return []

        cpes_response = response.json()[self.cpe_key]
        collected = []
            
        for x in cpes_response:
            if x.split(":")[-1] == version:
                collected.append(x)

        return collected

    def __shodan_cpe_search(self, collected) -> list:
        vuln_collected = []  
        for x in collected:
            vuln_response = ((r.get(url=self.cpe.format(cpe=x),timeout=10)).json())[self.cve_key]
            vuln_collected.append(vuln_response[0] if type(vuln_response) is list else vuln_response) # don't know why sometimes is a list and sometimes a dict
        
        return vuln_collected
    
    def shodan_search_by_cve(self, cve) -> dict:

        if re.match(self.__cve_regex , cve) is None:
            raise ValueError(self.__cve_error_regex.format(cve=cve))
        
        built_url = self.cve_url.format(cve=cve)              
        response = r.get(url=built_url,timeout=10)
        
        if response.status_code != 200:
            return {}
        
        jsoned = response.json()
        
        return {
            'epss' : jsoned['epss'] if 'epss' in jsoned else '',
            'ranking_epss': jsoned['ranking_epss'] if 'ranking_epss' in jsoned else ''
        }
        

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