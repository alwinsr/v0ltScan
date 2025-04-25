import requests
from src.cve_mapper import get_cves_for_version
from bs4 import BeautifulSoup

    

def detect_version_disclosure(url):
    result = {
        "target": url,
        "vulnerability": "Version Disclosure",
        "detected": False,
        "disclosed_version": None,
        "cves": []
    }

    try:
        response = requests.get(url, timeout=10)
        

        # 1. Check HTTP Headers
        headers_to_check = ["Server", "X-Powered-By"]
        for header in headers_to_check:
            if header in response.headers:
                result["detected"] = True
                result["disclosed_version"] = response.headers[header]
                result["cves"] = get_cves_for_version(response.headers[header])
                return result

        # 2. Check HTML Content
        soup = BeautifulSoup(response.text, 'html.parser')
        comments = soup.find_all(string=lambda text: isinstance(text, Comment))
        meta_generator = soup.find("meta", {"name": "generator"})
        
        if meta_generator and meta_generator.get("content"):
            result["detected"] = True
            result["disclosed_version"] = meta_generator["content"]
            result["cves"] = get_cves_for_version(meta_generator["content"])
        else:
            for comment in comments:
                if "version" in comment.lower():
                    result["detected"] = True
                    result["disclosed_version"] = comment.strip()
                    result["cves"] = get_cves_for_version(comment.strip())
                    break
            

    except requests.exceptions.RequestException as e:
        result["error"] = str(e)
    return result


