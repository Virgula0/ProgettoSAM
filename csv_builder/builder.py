from typing import Mapping, List

from github_scraper.dependency_file import DependencyFile
from github_scraper.github import Github

from vuln_scraper.shodan import Shodan
from vuln_scraper.sploitus import Sploitus
from vuln_scraper.deps_dev import DepsDev
from vuln_scraper.osv_dev import OSDev

import math
import os 
import csv
import threading

from time import sleep

class Builder:
    def __init__(self, 
                 language_dict: Mapping[str, Mapping[str, DependencyFile]],
                 github: Github,
                 star_ranges: List[str] = [">1800"], #["19..22", "50..65", "150..240", "450..999", ">1800"],
                 output_folder: str = "./output"):
        self.language_dict = language_dict
        self.github = github
        self.output_folder = output_folder
        self.star_ranges = star_ranges
        self.shodan = Shodan()
        self.sploitus = Sploitus()
        self.deps_dev = DepsDev()
        self.os_dev = OSDev()
        self.threads_number = 0
        self.mutex = threading.Lock()
        
    def flatten_dict(self, d, parent_key='', sep='_'):
        """
        Recursively flattens a dictionary, joining nested keys with `sep`.
        """
        items = {}
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                items.update(self.flatten_dict(v, new_key, sep=sep))
            elif isinstance(v, (list, set)):
                # Convert lists/sets to comma-separated strings
                items[new_key] = ",".join(map(str, v))
            else:
                items[new_key] = v
        return items
    
    
    def parse_vuln_and_save(self, repo, star_range, file_searched, dependency_set):   
        ghsa = set()
        cve_strings = set()
        severity = []
        cvss = []
        sploitus_pocs = 0
        
        # this loop should run in a separate thread
        for el in dependency_set:
            product = el[0]
            version = el[1]
            
            try:
                deps_response = self.deps_dev.depsdev_engine(product=product, version=version)

                if deps_response is not None and 'advisoryKeys' in deps_response and len(deps_response['advisoryKeys']) > 0:
                    ghsa.update(set([x['id'] for x in deps_response['advisoryKeys']]))

                os_dev_engine_response = self.os_dev.osdev_engine(product=product, version=version)

                if len(os_dev_engine_response) > 0:
                    for vuln in os_dev_engine_response['vulns']:
                        alieases = vuln['aliases'] if 'aliases' in vuln else []
                        ss = (
                            vuln['database_specific']['severity']
                            if 'database_specific' in vuln and 'severity' in vuln['database_specific']
                            else 'UNKNOWN'
                        )
                        cve_strings.update(set(alieases))
                        severity.append(ss)

                s_r = self.shodan.shodan_engine(product=product, version=version)

                if s_r is not None:
                    for result in s_r:
                        cve_strings.add(result['cve_id'])
                        cvss.append(result['cvss'])

            except Exception:
                pass
            
        try:
            for cve in cve_strings:
                if cve.startswith("CVE"):  # let's consider cve only
                    _, ll = self.sploitus.search_sploitus_by_cve(cve=cve)
                    sploitus_pocs = sploitus_pocs + ll

            # export in csv
            csv_output = {
                "repository": repo['full_name'],
                "star_range": star_range,
                "star": repo['stargazers_count'],
                "latest_push": repo['updated_at'],
                "files": file_searched,
                "total_dependencies": len(dependency_set),
                "number_of_vulnerabilities": max(len(cve_strings), len(ghsa), 0),
                "ghsa": ghsa,
                "cve_strings": cve_strings,
                "cvss": cvss,
                "severity": severity,
                "sploitus_number_of_pocs": sploitus_pocs,
            }

            # Flatten the dictionary
            flat_output = self.flatten_dict(csv_output)

            # Write to CSV
            with open(os.path.join(self.output_folder, star_range + ".csv"), "a", newline="", encoding="utf-8") as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=flat_output.keys())
                writer.writerow(flat_output)
        except Exception:
            pass
            
        with self.mutex:
            self.threads_number-=1
                
    def build_all_csv(self, results_per_page:int=100, verbose:bool=False):
        if verbose: print("Starting CSV build loop")
        
        for language in self.language_dict.keys():
            if verbose: print(f"\nStarting with language {language}")
            
            for star_range in self.star_ranges:
                with open(os.path.join(self.output_folder,star_range+".csv"), "w", newline="", encoding="utf-8") as csvfile:
                    keys = [
                            "repository",
                            "star_range",
                            "star",
                            "latest_push",
                            "files",
                            "total_dependencies",
                            "number_of_vulnerabilities",
                            "ghsa",
                            "cve_strings",
                            "cvss",
                            "severity",
                            "sploitus_number_of_pocs",
                    ]
                    writer = csv.DictWriter(csvfile, fieldnames=keys)
                    writer.writeheader()

                if verbose: print(f"Star range {star_range}")
                total_repositories_found = self.github.call_repository_api(language=language, stars=star_range, per_page=1)["total_count"]
                total_github_repo_rounds = min(math.ceil(total_repositories_found/results_per_page), 10)
                
                if verbose: print(f"Found {total_repositories_found} repositories. Total rounds to do is {total_github_repo_rounds}")
                
                for github_repo_index in range(1, total_github_repo_rounds+1):
                    if verbose: print(f"Now GITHUB_REPO_INDEX={github_repo_index}")
                    repositories = self.github.call_repository_api(language=language, stars=star_range, page=github_repo_index)['items']
                    
                    for repo in repositories:                   
                        try:
                            if verbose: print(f"Repo {repo['full_name']}")
                            
                            files_to_search = [v.filename for v in self.language_dict[language].values()]
                            
                            files_found = self.github.get_files_from_repo(repo['full_name'], files_to_search=files_to_search)
                            
                            for file_searched in files_found.keys():
                                dependency_set = set()
                                
                                for url_to_download in files_found[file_searched]:
                                    content = self.language_dict[language][file_searched].download_file(url_to_download)
                                    dependency_set.update(self.language_dict[language][file_searched].extract_dependencies(content))
                                    
                                if verbose: print("Analyzing dependencies... ")
                                
                                while self.threads_number >= 10:
                                    if verbose: print("Waiting for threads...")
                                    sleep(3)
                                    
                                thread = threading.Thread(target=self.parse_vuln_and_save, args=(repo,star_range,file_searched,dependency_set.copy()), daemon=True)
                                with self.mutex:
                                    self.threads_number+=1
                                thread.start()
                                
                        except Exception as ex:
                            print("Exception occurred " + str(ex))
                            continue
                        

                        
                        


                                
