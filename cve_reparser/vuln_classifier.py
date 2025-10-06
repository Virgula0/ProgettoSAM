import requests as r
import pandas as pd
import os
import csv
import re

macrogroups = {
    "Injection": [
        r'\bsql\s*injection\b', r'\bsqli\b',
        r'\bnosql\s*injection\b', r'\bnosqli\b',
        r'\bldap\s*injection\b',
        r'\bxpath\s*injection\b',
        r'\bcommand\s*injection\b', r'\bargument\s*injection\b', r'\bos\s*command\s*injection\b',
        r'\bexpression\s*language\s*injection\b', r'\bel\s*injection\b',
        r'\btemplate\s*injection\b', r'\bssti\b', r'\bserver[-\s]*side\s*template\s*injection\b',
        r'\bxpathi\b', r'\bgraphql\s*injection\b', r'\bgraphql\s*abuse\b',
        r'\barbitrary\s*commands?\b', r'\bhtml\s*injection\b',
        r'\bhttp\s*header\s*injection\b', r'\bhost\s*header\s*injection\b',
        r'\bcrlf\s*injection\b', r'\bcrlfi\b',
        r'\bcontent\s*injection\b|\binject(?:s|ed|ing)?\s+(?:arbitrary\s+|untrusted\s+|malicious\s+)?content\b|\binjection\s+of\s+(?:arbitrary\s+|untrusted\s+|malicious\s+)?content\b|\bhtml\s*content\s*injection\b|\bcontent\s*spoofing\b',
        r'\b(?:boolean[-\s]*based|blind)\s+sql(?:\s|-)?injection\b|\bblind\s*sqli\b',

    ],
    
    "XSS":[
        r'\bxss\b', r'\bcross[-\s]*site\s*scripting\b',
        r'\bstored\s*xss\b', r'\breflected\s*xss\b', r'\bdom\s*xss\b',
        r'\b(?:csp|content[-\s]*security[-\s]*policy)\s*(?:bypass|bypass(?:es)?)\b|\bcontent[-\s]*security[-\s]*policy\b',
        r'\b(dom[-\s]?based|client[-\s]?side)\s+(xss|cross\s*site\s*scripting|cross[-\s]?site\s*scripting)\b',
        r'\bjavascript[-\s]?xss\b',
        r'\b(unescaped|unsanitized|unfiltered)\s+(javascript|html|dom)\s+(input|output|content|injection)\b',
        r'\bscript\s+(injection|inclusion|execution)\b',
    ],
    
    "SupplyChain": [
        r'\b(?:dependency\s*confusion|dependency\s*hijack|dependency\s*hijacking|typo[-\s]*squatt(?:ing|er)|supply[-\s]*chain\s*attack)\b',
        r'\bmalicious\s+(npm|node|javascript)\s+(package|dependency|module)\b',
        r'\btyposquatting\s+(package|dependency)\s+on\s+(npm|node)\b',
        r'\bcompromised\s+(npm|node|javascript)\s+(library|module|dependency)\b',
        r'\bdependency\s+(confusion|hijacking)\s+(?:attack)?\b',
        r'\bbackdoor\b', r'\bmalicious\s*code\b', r'\bmalware\b',
        
    ],

    "SSRF & related": [r'\bssrf\b', r'\bserver\s*side\s*request\s*forgery\b', r'\bblind\s*ssrf\b'],
    
    "Race conditions": [r'\brace\s*condition(s)?\b', r'\btoctou\b', r'\btime\s*of\s*check\s*time\s*of\s*use\b'],

    "CSRF": [r'\bcsrf\b', r'\bcross\s*site\s*request\s*forgery\b', r'\bxsrf\b'],

    "Deserialization": [
        r'\bobject\s*deserialization\b', r'\binsecure\s*deserialization\b',
        r'\bobject\s*injection\b', r'\bserialization\s*attack\b',
        r'\binsecure\s*deserializ(?:e|ation|ing)\b|\bunsafe\s*deserializ(?:e|ation)\b',
        r'\b(insecure|unsafe|improper)\s+(deserialization|parsing)\s+in\s+(javascript|js|node|react|vue|angular)\b',
        r'\bobject\s+injection\s+in\s+(?:javascript|node\.js|express|angular|react)\b',
        r'\b(unsafe|insecure)\s+use\s+of\s+(?:json\.parse|eval\s*\(|vm\.runinnewcontext)\b',
        r'\bgraphql\s+(injection|abuse|introspection|expos(?:e|ed)|misconfiguration)\b',
        r'\bjson\s+(injection|injections?|parsing\s+error|deserialization)\b',
        r'\bjavascript\s+api\s+(expos(?:e|ed)|leak|vulnerability)\b',
    ],

    "Prototype Pollution": [r'\bprototype\s*pollution\b', r'\b__proto__\b', r'\bproto\b',
                            r'\bconstructor\.prototype\b',
                            r'\bobject\s+pollution\b',
                            r'\bproperty\s+injection\s+in\s+(?:javascript|js|node)\b',
                            r'\b(merge|extend|assign|set)\s*(?:function|method)?\s*(?:vulnerability|flaw)\b.*prototype',
                            ],

    "Memory Corruption": [r'\bbuffer\s*overflow\b', r'\bheap\s*overflow\b', r'\boverflow\b',
                          r'\binteger\s*(?:overflow|underflow|wrap(?:around)?)\b|\bint(?:eger)?\s*overflow\b',
                          r'\bformat(?:\s*string)?\s*(?:vulnerabilit(?:y|ies)|bug|issue)?\b|\bprintf[-_\s]*format\b',
                          r'\buse[-\s]*after[-\s]*free\b|\buaf\b|\bdouble[-\s]*free\b',
                          r'\bnull\s*pointer\s*deref(?:erence|erences)?\b|\bnull[-_\s]*deref\b',
                          r'\binteger\s*(?:truncation|trunc(?:ation)?)\b|\btruncation\s*error\b|\bprecision\s*loss\b',
                          r'\bprintf(?:\s*)injection\b|\bformat[-\s]*string\s*injection\b',
                          r'\bheap\s*(?:spray|spraying)\b',
                          ],

    "XXE": [r'\bxxe\b', r'\bxml\s*external\s*entit(y|ies)\b', r'\bxml\s*injection\b'],

    "IDOR / BOLA": [
        r'\bidor\b', r'\binsecure\s*direct\s*object\s*reference\b',
        r'\bbola\b', r'\bbroken\s*object\s*level\s*authorization\b',
        r'\bbfla\b', r'\bbroken\s*function\s*level\s*authorization\b',
        r'\bmass\s*assignment\b', r'\binformation\s*disclosure\b',
        r'\bsensitive\s*data\s*exposure\b',
        r'\bapi\s*abuse\b|\bapi\s*misuse\b|\bbroken\s*object\s*model\b',
    ],
    
    'Information Disclosure':[
        r'\bsensitive\s+(?:information|data)\s+(?:expos(?:e|ed)|leak(?:s|ed)?|disclos(?:e|ed)|leakage|is\s+exposed)\b',
        r'\b(?:information\s+disclosure|data\s+disclosure|info(?:rmation)?\s+leak|info\s+leakage|data\s+leak)\b',
        r'\b(?:pii|personal\s+data|personally[-\s]?identifiable\s+information|ssn|social\s*security\s*number|date\s*of\s*birth|dob)\b',
        r'\b(?:credentials?|passwords?|secrets?|api[-_\s]?keys?|api[_-]?key|tokens?|private[-\s]?key|private\s+key)\s+(?:expos(?:e|ed)|leak(?:s|ed)?|committed|found\s+in|in\s+repo|exposed\s+in)\b',
        r'\b(?:jwt|json\s*web\s*token|token|access[-_\s]?token|refresh[-_\s]?token|api[_-]?token)\b.*\b(expos(?:e|ed)|leak(?:s|ed)?|found|committed|embedded)\b',
        r'\b(?:source\s+code|repo|repository|repository\s+history|git\s+history|git)\b.*\b(?:expos(?:e|ed)|leak(?:s|ed)?|committed|contains|includes)\b',
        r'\b(?:backup|dump|db\s*dump|database\s*dump|database\s+export|sql\s+dump)\b.*\b(?:expos(?:e|ed)|leak(?:s|ed)?|public|accessible|downloadable)\b',
        r'\b(?:public|exposed|open)\s+(?:s3|bucket|storage|bucket\s+object|cloud\s+storage|blob)\b',
        r'\b(?:logs?|log\s+files|stack\s*trace|stacktrace|debug\s+info|debug\s+output)\b.*\b(?:expos(?:e|ed)|leak(?:s|ed)|contains|disclos(?:e|ed))\b',
        r'\b(?:error\s+message|detailed\s+error|verbose\s+error|stack\s+trace)\b.*\b(?:disclos(?:e|ed)|leaks?|contains)\b',
        r'\b(?:directory\s+listing|directory\s+indexing|indexing\s+enabled|listing\s+of\s+files|file\s+listing)\b',
        r'\b(?:config(?:uration)?\s+file|\.env|env\s+file|config\s+file|settings\.json|application\.properties)\b.*\b(?:expos(?:e|ed)|contains\s+(?:credentials|secrets|passwords)|leak(?:s|ed)?)\b',
        r'\b(?:set-cookie|session\s+id|sessionid|cookie|authorization\s+header|auth\s+header)\b.*\b(?:leak(?:s|ed)?|expos(?:e|ed)|sent\s+to\s+external|exfiltrat(?:e|ed))\b',
        r'\b(?:name|email|address|phone|phone\s*number|credit\s*card|ccv|cvv|iban|account\s+number)\b(?:[^\S\r\n]{0,8}|\W){0,60}\b(?:expos(?:e|ed)|leak(?:s|ed)?|disclos(?:e|ed)|public)\b',
        r'\b(?:secret|credentials|password|token|key|ssn|pii|personal\s+data|sensitive\s+data|private\s+key|api[-_\s]?key|database|dump|backup|logs?)\b(?:[^\S\r\n]{0,8}|\W){0,80}\b(?:expos(?:e|ed)|leak(?:s|ed)?|disclos(?:e|ed)|public|accessible|downloadable)\b',
    ],

    "Authentication / AuthZ": [
        r'\bbroken\s*authentication\b', r'\bweak\s*authentication\b',
        r'\bcredential\s*stuffing\b', r'\bsession\s*fixation\b',
        r'\bsession\s*hijacking\b', r'\bjwt(\s|[-_])*attack\b',
        r'\bjwt(\s|[-_])*(none\s*algorithm|vulnerabilit(y|ies))\b',
        r'\bjwt\b', r'\bbrute\s*force\b', r'\boauth\s*bypass\b',
        r'\boauth\b', r'\baccess\s*control\b',
        r'\bauth(?:entication)?\s*bypass\b|\blogic\s*bypass\b|\bbypass\s*authentication\b',
        r'\b(business\s+logic|authorization|authz|authn)\s+bypass\s+(?:via\s+)?(?:javascript|client[-\s]?side)\b',
        r'\bclient[-\s]?side\s+(validation|check|filter)\s+(bypass|disabled)\b',
        r'\bauthoriz(?:ation|e)\s*(?:bypass|bypassed|bypass(es)?)\b',
        r'\b(?:authz|auth(?:orization|entication)?)\s*(?:bypass|bypassed|circumvented)\b',
        r'\b(bypass|bypassed|circumvent|circumvented)\b(?:[^\S\r\n]{0,8}|\W){0,40}\b(auth|authorization|authorisation|authz|authenticate|authentication|role|roles|permission|permissions|access|privilege|privileges)\b',
        r'\b(?:endpoint|api|route|url|parameter|param|query)\b.*\b(bypass|bypassed|circumvent|circumvented|unauthorized\s*access)\b' ,
         
    ],
    
    'Improper Privilege Management':[
      r'\bimproper\s+(?:privilege|permission|authorization|access\s+control)\s+(?:management|handling|control|enforcement)\b',
      r'\bimproper\s+(?:privilege|permission|authorization|access\s+control)\s+(?:management|handling|control|enforcement)\b',
      r'\b(?:allows?|permits?|enables?|results\s+in|leads\s+to|causes?)\s+(?:local\s+)?(?:user|attacker|authenticated\s+user|remote\s+user)\b[^.]{0,40}\b(?:gain|obtain|escalate|elevate|acquire)\b[^.]{0,40}\b(?:privilege|permissions?|access|admin|root)\b',
      r'\b(?:improper|missing|inadequate|insufficient|broken)\s+(?:authorization|authz|access\s+control|permission\s+checks?)\b',
      r'\b(?:bypass(?:es|ing)?|circumvent(?:s|ing)?|avoid(?:s|ing)?)\s+(?:authorization|authentication|access\s+control|permission|privilege)\b',
      r'\bgain(?:s|ed|ing)?\s+(?:unauthorized\s+)?(?:root|admin(?:istrator)?|system)\s+(?:access|privilege|permissions?)\b',
      r'\b(?:incorrect|improper|misconfigured|misapplied|overly\s+permissive)\s+(?:privileges?|permissions?|roles?|access\s+rights?)\b',
      r'\b(?:improper\s+(?:privilege|permission|authorization|access\s+control)\s+(?:management|handling|control|enforcement)|(?:privilege|permission|access)\s+(?:escalation|elevation|increase|gain|bypass|abuse)|(?:allows?|permits?|enables?|leads\s+to|results\s+in)\s+(?:local\s+)?(?:user|attacker|authenticated\s+user|remote\s+user)\b[^.]{0,40}\b(?:gain|obtain|escalate|elevate|acquire)\b[^.]{0,40}\b(?:privilege|permissions?|access|admin|root)|(?:improper|missing|inadequate|insufficient|broken)\s+(?:authorization|authz|access\s+control|permission\s+checks?)|(?:bypass(?:es|ing)?|circumvent(?:s|ing)?|avoid(?:s|ing)?)\s+(?:authorization|authentication|access\s+control|permission|privilege)|gain(?:s|ed|ing)?\s+(?:unauthorized\s+)?(?:root|admin(?:istrator)?|system)\s+(?:access|privilege|permissions?)|(?:incorrect|improper|misconfigured|misapplied|overly\s+permissive)\s+(?:privileges?|permissions?|roles?|access\s+rights?))\b'  
    ],

    "Encryption/MITM": [
        r'\bmitm\b', r'\bman\s*in\s*the\s*middle\b', r'\bmissing\s*encryption\b',
        r'\bunencrypted\s*(authentication\s*data|data)\b',
        r'\bpadding\s*oracle\b|\bcbc\s*padding\s*oracle\b',
        r'\b(cipher|ssl|tls|protocol)\s*(?:downgrade|fallback)\b|\bdowngrade\s*attack\b',
        r'\bpadding\s*(?:oracle|error)\b|\bcbc\s*(?:oracle|vulnerability)\b',
        r'\bcertificate\s*(?:validation|pinning)\s*(?:bypass|failure|error)?\b|\bpinning\s*bypass\b'
    ],

    "RCE": [
        r'\b(?:remote|local|arbitrary|privileged|unauthenticated)?(?:[-\s]+arbitrary)?[-\s]*code\s+execution\b',
        r'\brce\b', r'\bremote\s*code\s*execution\b',
        r'\bremote\s*command\s*execution\b', r'\bcommand\s*execution\b',
        r'\barbitrary\s*code\s*execution\b', r'\bjavascript\s*execution\b', r'\beval\b',
        r'\b(arbitrary|remote|unauthorized|malicious)?\s*javascript\s+(execution|code\s+execution|injection|injections?)\b',
        r'\bjavascript\s+(eval|eval\(\)|execution|code\s+injection|expression|injection\s+attack)\b',
        r'\b(js|javascript)\s*(injection|execution|code\s+execution|eval|evaluation)\b',
        r'\bexecution\s+of\s+(arbitrary|untrusted|user[-\s]?supplied)\s+(javascript|js)\b',
        r'\b(eval|function\s*\(|settimeout|setinterval)\s*\(\s*(user|attacker|external|untrusted)\s*(input|data|content)\s*\)\b',
        r'\bimproper\s+use\s+of\s+(eval|new\s+function|settimeout|setinterval)\b',
        r'\bjavascript\s+(eval|new\s+function)\s+(injection|execution)\b',
    ],

    "Hijacking / takeover": [r'\bhijacking\b', r'\bsubdomain\s*takeover\b', r'\bdns\s*rebinding\b'],

    "Weak secrets": [
        r'\bweak\s*password\b', r'\bweak\s*secret\b',
        r'\bhardcoded\s*credentials\b', r'\bdefault\s*credentials\b',
        r'\b(?:credentials|secrets?)\s*(?:in|within|found\s*in)\s*(?:repository|repo|git|git[-_\s]*history)\b|\bleaked\s*(?:credentials|secrets)\b',
        r'\bhard[-\s]?cod(?:e|ed)\s+(?:credential|credentials|passwords?|secrets?|api[-_\s]?keys?|tokens?)\b',
        r'\b(?:credential|credentials|passwords?|secrets?|api[-_\s]?keys?|tokens?)\s+(?:hard[-\s]?cod(?:e|ed)|embedded|baked[-\s]?in|stori?ed|committed|checked[-\s]?in|exposed|leaked)\b',
        r'\b(?:embedded|baked[-\s]?in|bundled|included)\s+(?:api[-_\s]?key|token|credential|credentials|password|secret|private[-\s]?key)s?\b',
        r'\b(?:credentials?|passwords?|secrets?|api[-_\s]?keys?|tokens?)\s+(?:in|within|inside|found\s+in)\s+(?:source|source\s*code|repo(?:sitory)?|repository|repository\s+history|binary|image|container|docker\s+image|config|build|artifact)\b',
        r'\b(?:clear[-\s]?text|plain(?:-| )?text|plaintext)\s+(?:passwords?|secrets?|credentials?)\b',
        r'\b(?:committed|checked[-\s]?in|exposed|leaked|published|pushed)\s+(?:credentials?|passwords?|secrets?|api[-_\s]?keys?|tokens?)\b',
        r'\b(?:private[-\s]?key|pem[-\s]?key)\s+(?:embedded|in\s+source|committed|checked[-\s]?in|exposed|leaked)\b',
        r'\b(?:api[-_\s]?key|apikey|access[-_\s]?token|auth[-_\s]?token|token)\s+(?:found\s+in|present\s+in|in\s+source|in\s+repo|committed|exposed)\b',
        r'\b(?:baked[-\s]?into|embedded\s+in)\s+(?:container\s+image|docker\s+image|vm\s+image|image)\b.*\b(?:credential|credentials|password|secret|api[-_\s]?key|token)s?\b',
        r'\b(?:credential|credentials|password|secret|api[-_\s]?key|token)s?\b(?:[^\S\r\n]{0,10}|\W){0,20}(?:hard[-\s]?cod(?:e|ed)|embedded|expos(?:e|ed)|leak(?:ed|s)|committed|checked[-\s]?in)\b'
    ],

    "File/path issues": [
        r'\bpath\s*traversal\b', r'\bdirectory\s*traversal\b',
        r'\blfi\b', r'\blocal\s*file\s*inclusion\b',
        r'\brfi\b', r'\bremote\s*file\s*inclusion\b',
        r'\bzip\s*slip\b', r'\bsymlink\s*attack\b',
        r'\binsecure\s*file\s*upload\b', r'\bdirectory\s*(indexing|listing)\b',
        r'\barbitrary\s*file\s*(read|write)\b'
    ],

    "Type/system-level issues": [r'\btype\s*juggling\b', r'\binsecure\s*type\s*casting\b'],

    "HTTP request issues": [
        r'\brequest\s*smuggling\b', r'\brequest\s*splitting\b', r'\bhttp\s*desync\s*attack\b'
    ],

    "Clickjacking": [r'\bclickjacking\b', r'\bui\s*redressing\b'],

    "DoS": [
        r'\bdos\b', r'\bdenial[-\s]*of[-\s]*service\b', r'\bredos\b',
        r'\bre[-\s]*dos\b', r'\bregular\s*expression\s*denial\s*of\s*service\b',
        r'\bapplication[-\s]*level\s*dos\b', r'\balgorithmic\s*complexity\s*attack\b'
    ],

    "Input validation": [
        r'\bimproper\s*input\s*validation\b', r'\bimproper\s*(input\s*)?sanitization\b',
        r'\binsufficient\s*(input\s*)?validation\b', r'\binsufficient\s*(input\s*)?sanitization\b',
        r'\bsanitization\b',
        r'\bimproper\s*(?:output|input)\s*encoding\b|\bmissing\s*output\s*encoding\b|\binsecure\s*encoding\b'
    ],
    
    "Open Redirect":[
      r'\bopen[-\s]?redirect(?:ion)?s?\b',
      r'\b(?:unvalidated|untrusted|unsanitized|improper(?:ly)?\s*validated|unchecked|unsafe)\s+(?:redirect(?:ion)?s?|forward(?:ing)?|destination|url(?:\s*redirect)?)\b',
      r'\b(?:allows|permits|enables|leads\s+to|results\s+in)\s+(?:an\s+)?(?:open[-\s]?redirect|unvalidated\s+redirect|external\s+redirect)\b',
    ],

    "Misc": [
        r'\binsecure\s*randomness\b', r'\bopen\s*redirect(ion)?\b',
        r'\bunvalidated\s*redirect\b', r'\bbusiness\s*logic\s*flaw\b',
        r'\blogic\s*bugs?\b', r'\binsecure\s*configuration\b',
        r'\bprivilege\s*escalation\b', r'\bclear[-\s]*text\s*private\s*key\b',
        r'\bcrash\b',
        r'\boff[-\s]*by[-\s]*one\b',
        r'\bside[-\s]*channel\b|\btiming\s*attack\b|\bcache[-\s]*timing\b',
        r'\bcontainer\s*(?:escape|breakout|breakout|escape)\b|\bdocker\s*(?:escape|breakout)\b|\bcontainer[-\s]*escape\b',
        r'\b(?:public|exposed)\s+(?:s3|bucket|storage|blob)\b|\bexposed\s+bucket\b',
        r'\bldap\s*(?:injection|expos(?:e|ure))\b|\bldap[-_\s]*injection\b',
        r'\bbusiness\s*logic\s*(?:abuse|flaw|vulnerability)\b|\blogic\s*flaw\b',
        r'\b(insecure|improper|weak)\s+(csp|content\s+security\s+policy)\b',
        r'\bmissing\s+(csp|content\s+security\s+policy)\b',
        r'\bjavascript\s+(source\s+map|debug|console)\s+(leak|expos(?:e|ed))\b',
        r'\bdebug\s+build\s+of\s+(?:javascript|react|vue|angular)\s+(exposed|published)\b',
        r'\baccess\s+(?:granted|allowed|obtained|possible)\s+(?:without|despite|bypassing?)\s+(?:authentication|authorization|auth|authz|credentials|login)\b',
        r'\b(privilege\s*escalation|role\s*escalation|missing\s*(?:access|authorization|authz)\s*check|missing\s*authorization|missing\s*authz\s*check)\b',
        r'\b(?:authoriz(?:ation|e)\s*(?:bypass|bypassed)|(?:authz|auth(?:entication|orization)?)\s*(?:bypass|circumvent(?:ed)?)|access\s+(?:granted|allowed|obtained|possible)\s+(?:without|despite|bypassing?)\s+(?:authentication|authorization|auth|authz|credentials|login)|privilege\s*escalation|role\s*escalation|missing\s*(?:access|authorization|authz)\s*check|(?:endpoint|api|route|url|parameter|param|query).*?(?:bypass|bypassed|unauthorized\s*access))\b'
    ]
}

mitre_url = 'https://cveawg.mitre.org/api/cve/{cve}'
output_dir = '../output'
out_file_name = 'cve_parser.csv'

def match_category(title: str, descs: list) -> str:
    text = title.lower() + " " + " ".join(d['value'].lower() for d in descs if 'value' in d)
    for group, patterns in macrogroups.items():
        for pattern in patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return group
    return "UNKNOWN"

def mitre_request(cve):
    response = r.get(url=mitre_url.format(cve=cve))
    
    if response.status_code != 200:
        return {}

    response = response.json()
    title = (response['containers']['cna'].get('title', 'NO TITLE')).lower()
    descs = response['containers']['cna'].get('descriptions', [])

    category = match_category(title, descs)

    score = ', '.join(
        str(v['baseScore'])
        for m in response.get('containers', {}).get('cna', {}).get('metrics', [])
        for v in m.values()
        if isinstance(v, dict) and 'baseScore' in v
    )

    cwes = ', '.join(
        y.get('cweId', '')
        for pt in response.get('containers', {}).get('cna', {}).get('problemTypes', [])
        for z in pt.get('descriptions', [])
        for y in [z] if 'cweId' in z
    )
    
    return {'cve': cve, 'category': category, 'scores': score, 'cwes': cwes}

def process_csv(df) -> set:
    cves = set()
    
    if "cve_strings" not in df.columns:
        return cves
    
    for val in df["cve_strings"].dropna():
        for cve in str(val).split(","):
            cve = cve.strip()
            if cve and cve.startswith("CVE"):
                cves.add(cve)
                
    return cves

if __name__ == '__main__':
    cves = set()
    for file in ['>1800.csv', '19..22.csv', '50..65.csv','150..240.csv','240..450.csv','450..999.csv']:
        path = os.path.join(output_dir, file)
        print(f"Parsing file: {file}:{path}")
        df = pd.read_csv(path)
        cves.update(process_csv(df))

    print(f"Total unique CVEs found: {len(cves)}")

    keys = ['cve', 'category', 'scores', 'cwes']
    out_path = os.path.join(output_dir, out_file_name)

    with open(out_path, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=keys)
        writer.writeheader()

    for count, cve in enumerate(cves, 1):
        print(f"Reached {count} over {len(cves)}")
        result = mitre_request(cve)
        if result:
            with open(out_path, "a", newline="", encoding="utf-8") as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=keys)
                writer.writerow(result)
