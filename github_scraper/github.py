from datetime import datetime
from typing import List, Mapping
import requests as r
import os
import urllib
import re

from time import sleep

class Github:
    def __init__(self, github_access_token: str):
        self.github_access_token = github_access_token
        self.repository_url = "https://api.github.com/search/repositories?q=language:{language}+size:<{size_up_limit}+stars:{stars}+archived:=false+pushed:{last_commit_pushed_after}..{today}&per_page={per_page}&page={page}"
        self.contents_url = "https://api.github.com/repos/{repo_full_name}/contents/{path}"
        self.number_of_commits_url = "https://api.github.com/repos/{repo_full_name}/commits?per_page=1&page=1&anon=true"
        self.number_of_contributors_url = "https://api.github.com/repos/{repo_full_name}/contributors?per_page=1&page=1&anon=true"
        self.bytes_of_code_url = "https://api.github.com/repos/{repo_full_name}/languages"
        self.blocked = "API rate limit exceeded for user ID"
        self.blocked_sleep = 120

    def __check_blocked(self, jsoned):
        return 'message' in jsoned and self.blocked in jsoned['message']
        

    def call_repository_api(self, 
                language: str, 
                size_up_limit : str = "100000", # 100 MB
                stars: str = ">20", 
                last_commit_pushed_after: str = "2025-08-18",
                per_page: int = 100,
                page: int = 1) -> dict:
        
        headers = {"Authorization": f"Bearer {self.github_access_token}"}

        response = (r.get(url=self.repository_url.format(language=language, 
                                  size_up_limit=size_up_limit,
                                  stars=stars, 
                                  last_commit_pushed_after=last_commit_pushed_after,
                                  today=datetime.today().strftime('%Y-%m-%d'),
                                  per_page=per_page,
                                  page=page),
                        headers=headers)).json()
             
        while self.__check_blocked(response):
            print(f"Github API Rate limit reached, sleeping for {self.blocked_sleep/60} minutes... ")
            sleep(self.blocked_sleep)
            response = (r.get(url=self.repository_url.format(language=language, 
                          size_up_limit=size_up_limit,
                          stars=stars, 
                          last_commit_pushed_after=last_commit_pushed_after,
                          today=datetime.today().strftime('%Y-%m-%d'),
                          per_page=per_page,
                          page=page),
                headers=headers)).json()
        
        return response
    
    def get_number_of_commits(self,
                              repo_full_name: str) -> int:    
        number_of_commits = 1
        
        try:
            headers = {"Authorization": f"Bearer {self.github_access_token}"}

            response = (r.get(url=self.number_of_commits_url.format(repo_full_name=repo_full_name),headers=headers)).headers
                
            while self.__check_blocked(response):
                print(f"Github API Rate limit reached, sleeping for {self.blocked_sleep/60} minutes... ")
                sleep(self.blocked_sleep)
                response = (r.get(url=self.number_of_commits_url.format(repo_full_name=repo_full_name),headers=headers)).headers

            s = response["Link"]
            match = re.search(r'page=(\d+)&anon=true>; rel="last"', s)
            if match:
                number_of_commits = match.group(1)
                
            number_of_commits = int(number_of_commits)
        except Exception as ex:
            print("Exception occurred " + str(ex))
        
        return number_of_commits
        
    
    def get_number_of_contributors(self,
                                   repo_full_name: str) -> int:
        number_of_contributors = 1
        
        try:
            headers = {"Authorization": f"Bearer {self.github_access_token}"}

            response = (r.get(url=self.number_of_contributors_url.format(repo_full_name=repo_full_name),headers=headers)).headers
                
            while self.__check_blocked(response):
                print(f"Github API Rate limit reached, sleeping for {self.blocked_sleep/60} minutes... ")
                sleep(self.blocked_sleep)
                response = (r.get(url=self.number_of_contributors_url.format(repo_full_name=repo_full_name),headers=headers)).headers

            s = response["Link"]
            match = re.search(r'page=(\d+)&anon=true>; rel="last"', s)
            if match:
                number_of_contributors = match.group(1)
                
            number_of_contributors = int(number_of_contributors)
        except Exception as ex:
            print("Exception occurred " + str(ex))
        
        return number_of_contributors
    
    def get_bytes_of_language(self,
                               repo_full_name: str,
                               language: str) -> int:
        bytes_of_language = 0
        
        try:
            headers = {"Authorization": f"Bearer {self.github_access_token}"}

            response = (r.get(url=self.bytes_of_code_url.format(repo_full_name=repo_full_name),headers=headers)).json()
            
            while self.__check_blocked(response):
                print(f"Github API Rate limit reached, sleeping for {self.blocked_sleep/60} minutes... ")
                sleep(self.blocked_sleep)
                response = (r.get(url=self.bytes_of_code_url.format(repo_full_name=repo_full_name),headers=headers)).json()
            
            bytes_of_language = int(response[language])
        except Exception as ex:
            print("Exception occurred " + str(ex))
        
        return bytes_of_language
    
    def get_files_from_repo(self,
                            repo_full_name: str,
                            files_to_search: List[str]) -> Mapping[str, List[str]]:
        raw_download_urls = {filename:[] for filename in files_to_search}
        
        headers = {"Authorization": f"Bearer {self.github_access_token}"}
        contents = (r.get(url=self.contents_url.format(repo_full_name=repo_full_name, path=""),
                        headers=headers)).json()
        
        while self.__check_blocked(contents):
            print(f"Github API Rate limit reached, sleeping for {self.blocked_sleep/60} minutes... ")
            sleep(self.blocked_sleep)
            contents = (r.get(url=self.contents_url.format(repo_full_name=repo_full_name, path=""),
                headers=headers)).json()
        
        while contents:
            file_content = contents.pop(0)
            if file_content["type"] == "dir":
                rr = (r.get(url=self.contents_url.format(repo_full_name=repo_full_name, path=urllib.parse.quote(file_content["path"])),headers=headers)).json()
                            
                while self.__check_blocked(rr):
                    print(f"Github API Rate limit reached, sleeping for {self.blocked_sleep/60} minutes... ")
                    sleep(self.blocked_sleep)
                    rr = (r.get(url=self.contents_url.format(repo_full_name=repo_full_name, path=urllib.parse.quote(file_content["path"])),headers=headers)).json()
                
                contents.extend(rr)
            else:
                if file_content["name"] in files_to_search:
                    raw_download_urls[file_content["name"]].append(file_content["download_url"])
            
        return raw_download_urls

# Tests from command line, not the purpose of this script
if __name__ == "__main__":
    if (token := os.environ.get("GITHUB_ACCESS_TOKEN")) is None:
        exit("Please set environment variable GITHUB_ACCESS_TOKEN")

    g = Github(token)
    
    #print(g.call_repository_api(language="js", page=10))

    print(g.get_files_from_repo("LBartolini/ProgettoSAM", ["__init__.py"]))