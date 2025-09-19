import requests as r
import json
from abc import ABC, abstractmethod

class DependencyFile(ABC):
    def __init__(self, url: str):
        self.url = url
    
    @abstractmethod
    def download_file(self) -> str:
        pass
    
    @abstractmethod
    def extract_dependencies(self, content: str) -> set:
        pass

class PackageJson(DependencyFile):
    def __init__(self, url: str):
        super().__init__(url)
        
    def download_file(self) -> str:
        download_url = r.get(url=self.url).json()['download_url']
        return r.get(url=download_url).text
    
    def extract_dependencies(self, content: str) -> set:
        json_content = json.loads(content)
        
        return set(json_content['devDependencies'].items())
        
        
        
# Tests from command line, not the purpose of this script
if __name__=="__main__":
    p = PackageJson("https://api.github.com/repositories/10270250/contents/package.json?ref=6eda534718d09a26d58d65c0a376e05d7e2a3358")
    
    #print(p.download_file())
    
    print(p.extract_dependencies(p.download_file()))