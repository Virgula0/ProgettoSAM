from vuln_scraper.shodan import Shodan
from vuln_scraper.sploitus import Sploitus

if __name__ == "__main__":
    # Test
    shodan = Shodan()
    sploitus = Sploitus()

    """
        DEPS_DEV -> return a json always for any existing version, then advisoryKeys array must be checked for the presence of vulnerabilities
        OSV_DEV -> returns an empty json if no vulnerabilities have been found
        SHODAN -> returns None if no vulnerabilities have been found
        SPLOITUS -> returns a json in the first argument and the second argument represents the number of findings
    """
    
    # search given a vuln
    shodan_results = shodan.shodan_engine("xz","5.1.0")
    
    if shodan_results is not None:
        for result in shodan_results: # result is in the format product:version:cve of vulnerables found
            cve = result.split(":")[-1] # get cve only
            print(sploitus.search_sploitus_by_cve(cve=cve))
    