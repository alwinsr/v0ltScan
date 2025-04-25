import os
import json
import requests
from bs4 import BeautifulSoup

def get_api_credentials(config_file_path=None):
    """
    Fetch API credentials from a config file.
    
    :param config_file_path: The path to the configuration file.
    :return: Tuple of (api_key, api_url) or None if errors occur.
    """
    if config_file_path is None:
        config_file_path = os.path.join(os.path.dirname(__file__), '..', 'config', 'config.json')
    
    try:
        with open(config_file_path, 'r') as f:
            config = json.load(f)
            api_key = config.get("ndv_api_key")
            api_url = config.get("ndv_api_url")
            if api_key and api_url:
                return api_key, api_url
            else:
                raise ValueError("API key or API URL missing in config.")
    except FileNotFoundError:
        print(f"Error: Configuration file '{config_file_path}' not found.")
        return None, None
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON format in '{config_file_path}'.")
        return None, None
    except ValueError as ve:
        print(str(ve))
        return None, None

def convert_to_cpe(version_string):
    """
    Converts a version string to CPE (Common Platform Enumeration) format.
    
    :param version_string: Version string to convert.
    :return: CPE string (e.g., cpe:2.3:a:apache:tomcat:6.0.20).
    """
    try:
        product_version = version_string.split('/')
        vendor_product = product_version[0].split('-')
        version = product_version[1]
        
        vendor, product = vendor_product[0].lower(), vendor_product[1].lower() if len(vendor_product) == 2 else vendor_product[0].lower()
        
        cpe_name = f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
        return cpe_name
    except Exception as e:
        print(f"Error while converting version string to CPE: {e}")
        return None

def get_cves_for_version(version_string):
    """
    Fetch CVEs for a given version string using NVD API.
    
    :param version_string: Version string for which to find CVEs.
    :return: List of CVEs or an empty list if no CVEs are found.
    """
    cpe_name = convert_to_cpe(version_string)
    if not cpe_name:
        return []
    
    api_key, api_url = get_api_credentials()
    if not api_key or not api_url:
        return []
    
    params = {"cpeName": cpe_name, "resultsPerPage": 5}
    headers = {"apiKey": api_key}

    try:
        response = requests.get(api_url, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        data = response.json()

        vulnerabilities = data.get("vulnerabilities", [])
        if vulnerabilities:
            return [{"id": cve.get("cve", {}).get("id"),
                     "summary": cve.get("cve", {}).get("descriptions", [{}])[0].get("value", "No summary available"),
                     "cvss": cve.get("cve", {}).get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseScore")}
                    for cve in vulnerabilities]
        else:
            print("✅ No CVEs found for the given CPE/version in NVD Database.")
            return []
    except requests.exceptions.RequestException as e:
        print(f"Error fetching CVEs from NVD: {e}")
        return []

#Extract product name from version string.
def extract_product_name(version_string):
    
    #param version_string: Version string (e.g., 'Apache-Coyote/1.1')
    #:return: Product name (e.g., 'Apache-Coyote')
    try:
        # Example version string: 'Apache-Coyote/1.1'
        product_version = version_string.split('-')

        if len(product_version) > 0:
            product_name = product_version[1].strip()
            return product_name
        else:
            return None
    except Exception as e:
        print(f"Error while extracting product name from version string: {e}")
        return None
    
#Search MITRE CVE database for a keyword and return the top 10 CVEs.
def search_mitre(version_string):

    keyword = extract_product_name(version_string)
    try:
        url = f"https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword={keyword}"
        response = requests.get(url)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.text, 'html.parser')
        cve_table = soup.find('div', {'id': 'TableWithRules'})
        
        if not cve_table:
            print("No CVEs found in MITRE for the given keyword.")
            return []
        
        cves = []
        for row in cve_table.find_all('tr')[1:]:  # Skip header row
            cols = row.find_all('td')
            if len(cols) < 2:
                continue
            cve_id = cols[0].text.strip()
            description = cols[1].text.strip()
            cves.append({'cve_id': cve_id, 'description': description})
        
        # Return top 10 CVEs or all available if fewer than 10
        return cves[:10]

    except requests.exceptions.RequestException as e:
        print(f"Error fetching CVEs from MITRE: {e}")
        return []