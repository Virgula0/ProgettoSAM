import os,sys
import pandas as pd
import csv

sys.path.append(os.path.dirname(os.path.dirname(__file__))) # not the most elegant way to avoid manual module importing

from vuln_scraper.shodan import Shodan

output_dir = './output'
out_file_name = 'epss.csv'
cve_file = 'cve_parser.csv'


def process(p) -> set:
    found = set()
    
    if "cve" not in df.columns:
        return cves  # return empty if column missing
    
    for val in df["cve"].dropna():
        if val and val.startswith("CVE"): 
            found.add(val)
            
    return found

if __name__ == '__main__':
    cves = set()
    output_file = os.path.join(output_dir,out_file_name)
    path_input_file = os.path.join(output_dir,cve_file)
    
    df = pd.read_csv(path_input_file)
    cves.update(process(df))
    
    print(f"Total to process {len(cves)}")
    
    s = Shodan()
    
    columns = [
        'cve',
        'epss',
        'ranking_epss'
    ]
    
    with open(output_file, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=columns)
        writer.writeheader()

    count = 0
    with open(output_file, 'a') as file:
        writer = csv.DictWriter(file, fieldnames=columns)
        for x in cves:
            count+=1
            print(f"[{count}] Trying {x}")
            result = s.shodan_search_by_cve(cve=x)
            if result:
                writer.writerow({'cve': x , 'epss' : result['epss'], 'ranking_epss': result['ranking_epss']}) 
                file.flush() 


