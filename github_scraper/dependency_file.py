import requests as r
import json
from abc import ABC, abstractmethod

class DependencyFile(ABC):
    @abstractmethod
    def download_file(self) -> str:
        pass
    
    @abstractmethod
    def extract_dependencies(self, content: str) -> set:
        pass
    
    def get_github_download_url(self, url: str):
        return r.get(url=url).json()['download_url']

class PackageJson(DependencyFile):
    filename = "package"
    extension = "json"
        
    def download_file(self, url: str) -> str:
        download_url = self.get_github_download_url(url)
        return r.get(url=download_url).text
    
    def extract_dependencies(self, content: str) -> set:
        json_content = json.loads(content)
        
        output_set = set()
        
        if 'devDependencies' in json_content:
            output_set.update(set(json_content['devDependencies'].items()))
            
        if 'bundleDependencies' in json_content:
            output_set.update(set(json_content['bundleDependencies'].items()))
        
        if 'dependencies' in json_content:
            output_set.update(set(json_content['dependencies'].items()))
    
        return output_set
        
        
        
# Tests from command line, not the purpose of this script
if __name__=="__main__":
    p = PackageJson()
    
    #print(p.download_file("https://api.github.com/repositories/10270250/contents/package.json?ref=6eda534718d09a26d58d65c0a376e05d7e2a3358"))
    
    print(p.extract_dependencies(p.download_file("https://api.github.com/repositories/10270250/contents/package.json?ref=6eda534718d09a26d58d65c0a376e05d7e2a3358")))
    
    #print(p.filename)
    #print(p.extension)