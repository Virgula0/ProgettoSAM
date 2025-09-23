import requests as r
import json
import re
from abc import ABC, abstractmethod

class DependencyFile(ABC):
    @abstractmethod
    def download_file(self) -> str:
        pass
    
    @abstractmethod
    def extract_dependencies(self, content: str) -> set:
        pass
    
    @property
    @abstractmethod
    def filename(self):
        pass

class PackageJson(DependencyFile):
    filename = "package.json"
    
    def __init__(self):
        #self.version_regex = r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-(?:0|[1-9]\d*|[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|[a-zA-Z-][0-9a-zA-Z-]*))*)?(?:\+[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*)?$"
        self.version_regex = r"^[~^]?(\d+\.\d+\.\d+)$"
        
    def download_file(self, raw_url: str) -> str:
        return r.get(url=raw_url).text
    
    def extract_dependencies(self, content: str) -> set:
        json_content = json.loads(content)
        
        output_set = set()
        
        if 'devDependencies' in json_content:
            output_set.update(set([(dep[0], self.__extract_version(dep[1])) for dep in json_content['devDependencies'].items()]))
            
        if 'bundleDependencies' in json_content:
            output_set.update(set([(dep[0], self.__extract_version(dep[1])) for dep in json_content['bundleDependencies'].items()]))
        
        if 'dependencies' in json_content:
            output_set.update(set([(dep[0], self.__extract_version(dep[1])) for dep in json_content['dependencies'].items()]))
    
        return output_set
    
    def __extract_version(self, version: str) -> str:
        match = re.compile(self.version_regex).match(version)
        if match:
            version = match.group(1)
            
        return version
        
# Tests from command line, not the purpose of this script
if __name__=="__main__":
    p: DependencyFile = PackageJson()
    
    #print(p.download_file("https://api.github.com/repositories/10270250/contents/package.json?ref=6eda534718d09a26d58d65c0a376e05d7e2a3358"))
    
    print(p.extract_dependencies(p.download_file("https://api.github.com/repositories/10270250/contents/package.json?ref=6eda534718d09a26d58d65c0a376e05d7e2a3358")))
    
    #print(p.filename)
    #print(p.extension)