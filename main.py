from csv_builder.builder import Builder
from github_scraper.dependency_file import PackageJson
from github_scraper.github import Github
import os
import pandas as pd

if __name__ == "__main__":

    """
        DEPS_DEV -> return a json always for any existing version, then advisoryKeys array must be checked for the presence of vulnerabilities
        OSV_DEV -> returns an empty json if no vulnerabilities have been found
        SHODAN -> returns None if no vulnerabilities have been found
        SPLOITUS -> returns a json in the first argument and the second argument represents the number of findings
    """
    
    if (token := os.environ.get("GITHUB_ACCESS_TOKEN")) is None:
        exit("Please set environment variable GITHUB_ACCESS_TOKEN")
    
    b = Builder({"js": {"package.json": PackageJson()}}, Github(token))
    ''' 
    # Build Base CSV
    b.build_all_csv(verbose=True)
    '''
    
    # Build Demographics CSV
    folder_path = "./output/"

    files = os.listdir(folder_path)

    files_to_exclude = ['cve_parser.csv', 'epss.csv']

    csv_files_to_merge = [f for f in files if f.endswith('.csv') and f not in files_to_exclude]

    dataframes_to_merge = {}

    for csv_file in csv_files_to_merge:
        file_path = os.path.join(folder_path, csv_file)
        df_name = os.path.splitext(csv_file)[0]
        try:
            dataframes_to_merge[df_name] = pd.read_csv(file_path)
            print(f"Caricato con successo il file per l'unione: {csv_file}")
        except Exception as e:
            print(f"Errore durante il caricamento del file {csv_file} per l'unione: {e}")
    
    merged_df = pd.concat(dataframes_to_merge.values(), ignore_index=True)
    filtered_df = merged_df[merged_df['total_dependencies'] > 0].copy()
    
    b.build_demographics(repositories=list(filtered_df["repository"]), language="JavaScript")
    