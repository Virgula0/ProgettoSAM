from vuln_scraper.shodan import Shodan
from vuln_scraper.sploitus import Sploitus

if __name__ == "__main__":
    # Test
    shodan = Shodan()
    sploitus = Sploitus()
    
    # search given a vuln
    shodan_results = shodan.shodan_engine("xz","5.1.0")
    
    for result in shodan_results: # result is in the format product:version:cve of vulnerables found
        cve = result.split(":")[-1] # get cve only
        print(sploitus.search_sploitus_by_cve(cve=cve))
    