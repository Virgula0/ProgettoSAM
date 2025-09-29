from csv_builder.builder import Builder
from github_scraper.dependency_file import PackageJson
from github_scraper.github import Github
import os

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
    
    b.build_all_csv(verbose=True)
    