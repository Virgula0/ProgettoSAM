from typing import Dict, Tuple
import httpx # needed instead of requests because HTTP/1.1 are blocked
import re
import sys

class Sploitus:
    def __init__(self):
        self.__url = "https://sploitus.com/search"
        self.__CVE_REGEX =  r'CVE-\d{4}-\d{4,7}'
    
    def get_regex(self):
        return self.__CVE_REGEX

    def search_sploitus_by_cve(self, cve: str) -> Tuple[Dict, int]:
        
        payload = {
            "type": "exploits",
            "sort": "default",
            "query": f"{cve}",
            "title": False,
            "offset": 0
        }    
        
        with httpx.Client(http2=True, timeout=15) as client:
            jj = (client.post(self.__url, json=payload)).json() # Uses http2 by default
            return jj, jj['exploits_total']
            

# Tests from command line, not the prupose of this script
# Usage: python3 sploitus.py CVE-2022-1271
if __name__ == "__main__":
    
    s = Sploitus()
    
    if len(sys.argv)<1 or sys.argv[1] is None or sys.argv[1] == "" or re.match(s.get_regex(),sys.argv[1]) is None:
        exit("Not a valid CVE identifier")

    collected , length= s.search_sploitus_by_cve(cve=sys.argv[1])
    print("Found -> " , (collected,length))