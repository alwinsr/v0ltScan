import requests
import argparse
import json
from bs4 import BeautifulSoup, Comment
from src.cve_mapper import get_cves_for_version
from src.cve_mapper import search_mitre


class VersionDisclosureScanner:
    def __init__(self, url):
        self.url = url
        self.result = {
            "target": url,
            "vulnerability": "Version Disclosure",
            "detected": False,
            "disclosed_version": None,
            "cves": [],
        }

    def scan(self):
        try:
            response = requests.get(self.url, timeout=10)
            self._check_headers(response.headers)
            self._check_html_content(response.text)

        except requests.exceptions.RequestException as e:
            self.result["error"] = str(e)

        return self.result

    def _check_headers(self, headers):
        for header, value in headers.items():
            if any(keyword in header.lower() for keyword in ["server", "x-powered-by"]):
                self.result["detected"] = True
                self.result["disclosed_version"] = value
                self.result["cves"] = get_cves_for_version(value) or search_mitre(value)
                return

    def _check_html_content(self, html):
        soup = BeautifulSoup(html, 'html.parser')

        # Meta tag check
        meta_generator = soup.find("meta", {"name": "generator"})
        if meta_generator and meta_generator.get("content"):
            version_info = meta_generator["content"]
            self.result["detected"] = True
            self.result["disclosed_version"] = version_info
            self.result["cves"] = get_cves_for_version(version_info) or search_mitre(version_info)
            return

    # def _calculate_confidence(self, cve_id, version_info):
    #     # Example logic to calculate confidence score based on various factors
    #     # For demonstration, we return a static confidence score for the sake of simplicity.
        
    #     # In a real implementation, you'd use more complex logic (e.g., matching CVE to version history)
    #     if "high" in cve_id.lower():
    #         return "High"
    #     elif "medium" in cve_id.lower():
    #         return "Medium"
    #     else:
    #         return "Low"


def main():
    banner = r"""
 _    __     ___      _   _____                                      
| |  / /__  / _ \__ _| |_| ____|_ __ ___  ___  ___ _ ____   _____ _ __ 
| | / / _ \| | | / _` | __|  _| | '__/ _ \/ __|/ _ \ '__\ \ / / _ \ '__|
| |/ / (_) | |_| | (_| | |_| |___| | |  __/\__ \  __/ |   \ V /  __/ |   
|___/\___/ \___/ \__,_|\__|_____|_|  \___||___/\___|_|    \_/ \___|_|   

                        version disclosure scanner
                            [ powered by ⚡ v0lt ]
    """
    print(banner)
    print("\U0001F527 Version: 1.0.0 | github.com/alwinsr/v0ltScan\n")
    print("\U0001F6E1️  v0ltScan - Version Disclosure & CVE Mapper")

    parser = argparse.ArgumentParser(description="Version Disclosure and CVE Mapper")
    parser.add_argument("--url", help="Target URL to scan", required=False)
    args = parser.parse_args()

    target = args.url or input("\U0001F50D Enter the target website URL (e.g. http://demo.testfire.net): ").strip()

    print(f"\nScanning: {target}\n")
    scanner = VersionDisclosureScanner(target)
    result = scanner.scan()
    

    print(json.dumps(result, indent=4))


if __name__ == "__main__":
    main()