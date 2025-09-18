from datetime import datetime
import requests as r
import os

class Github:
    def __init__(self, github_access_token: str):
        self.github_access_token = github_access_token
        self.repository_url = "https://api.github.com/search/repositories?q=language:{language}+stars:>{min_stars}+archived:=false+pushed:{last_commit_pushed_after}..{today}&per_page={per_page}&page={page}"
        self.code_url = "https://api.github.com/search/code?q=repo:{repository}+filename:{filename}+extension:{extension}&per_page={per_page}&page={page}"

    def call_repository_api(self, 
                language: str, 
                 min_stars: int = 20, 
                 last_commit_pushed_after: str = "2025-08-18",
                 per_page: int = 100,
                 page: int = 1) -> dict:
        
        headers = {"Authorization": f"Bearer {self.github_access_token}"}

        response = (r.get(url=self.repository_url.format(language=language, 
                                  min_stars=min_stars, 
                                  last_commit_pushed_after=last_commit_pushed_after,
                                  today=datetime.today().strftime('%Y-%m-%d'),
                                  per_page=per_page,
                                  page=page),
                        headers=headers)).json()
        
        return response  
    
    def call_code_api(self, 
                repo: str, 
                filename: str, 
                extension: str,
                per_page: int = 100,
                page: int = 1) -> dict:

        headers = {"Authorization": f"Bearer {self.github_access_token}"}

        response = (r.get(url=self.code_url.format(
                        repository=repo,
                        filename=filename,
                        extension=extension,
                        per_page=per_page,
                        page=page),
                        headers=headers)).json()
        
        return response 

# Tests from command line, not the prupose of this script
if __name__ == "__main__":
    if (token := os.environ.get("GITHUB_ACCESS_TOKEN")) is None:
        exit("Please set environment variable GITHUB_ACCESS_TOKEN")

    g = Github(token)
    
    #print(g.call_repository_api(language="js", per_page=1))

    print(g.call_code_api("facebook/react", "package", "json"))