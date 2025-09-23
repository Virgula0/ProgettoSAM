import requests as r
import sys
import urllib
import re

class DepsDev:
    def __init__(self):
        self.__url = "https://api.deps.dev/v3alpha/systems/npm/packages/{product}/versions/{version}"
        self.__product_regex = r"^(?:@[a-z0-9][a-z0-9-_.]*\/)?[a-z0-9][a-z0-9-_.]*$"
        self.__version_regex = r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-(?:0|[1-9]\d*|[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|[a-zA-Z-][0-9a-zA-Z-]*))*)?(?:\+[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*)?$"
        self.__product_error = "Regex does not match the format of npm package"
        self.__version_error = "Version format of npm package not valid"

    def depsdev_engine(self, product: str, version:str):
        
        if re.match(self.__product_regex, product) is None:
            raise ValueError(self.__product_error)
        
        if re.match(self.__version_regex, version) is None:
            raise ValueError(self.__version_error)
        
        response = r.get(url=self.__url.format(product=urllib.parse.quote_plus(product),version=urllib.parse.quote_plus(version)),timeout=10)

        if response.status_code == 404:
            return None
        
        return response.json()
        

# Tests from command line, not the prupose of this script
# Usage: python3 deps_dev.py '@artilleryio/int-commons' 2.16.0
if __name__ == "__main__":
    
    if len(sys.argv)<1 or sys.argv[1] is None or sys.argv[1] == "":
        exit("Not a valid product input")
        
    if len(sys.argv)<2 or sys.argv[2] is None or sys.argv[2] == "":
        exit("Not a valid version")

    s = DepsDev()
    
    collected = s.depsdev_engine(product:=sys.argv[1], version:=sys.argv[2])
    print("Found -> " + str((collected)))