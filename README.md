# Version Disclosure & CVE Mapper

This project is a **Version Disclosure & CVE Mapper** that detects potential version disclosure vulnerabilities and maps them to related CVEs from the MITRE CVE database. It takes a target URL, detects any version disclosures in the HTML source, and maps them to associated CVEs.

## Setup and Run Instructions

### Prerequisites
Ensure that you have the following installed:
- Python 3.6+
- pip (Python's package installer)

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/v0ltScan.git
   cd v0ltScan

2. Install the required Python packages:
    ```bash
    pip install -r requirements.txt

3.Ensure that requirements.txt contains the necessary dependencies, such as:

beautifulsoup4 for HTML parsing

requests for making HTTP requests

Configuration
Ensure that you have a config.json file in the config directory with the following format:

```
{
    "ndv_api_key": "your_api_key",
    "ndv_api_url": "https://api.ndv.com"
}


Running the Tool
To start the tool and begin scanning a website:
python voltscan.py


 _    __     ___      _   _____
| |  / /__  / _ \__ _| |_| ____|_ __ ___  ___  ___ _ ____   _____ _ __ 
| | / / _ \| | | / _` | __|  _| | '__/ _ \/ __|/ _ \ '__\ \ / / _ \ '__|
| |/ / (_) | |_| | (_| | |_| |___| | |  __/\__ \  __/ |   \ V /  __/ |   
|___/\___/ \___/ \__,_|\__|_____|_|  \___||___/\___|_|    \_/ \___|_|

                        version disclosure scanner
                            [ powered by ⚡ v0lt ]

🔧 Version: 1.0.0 | github.com/alwinsr/v0ltScan

🛡️  v0ltScan - Version Disclosure & CVE Mapper
🔍 Enter the target website URL (e.g. http://demo.testfire.net): http://demo.testfire.net

Scanning: http://demo.testfire.net

✅ No CVEs found for the given CPE/version in NVD Database.
{
    "target": "http://demo.testfire.net",
    "vulnerability": "Version Disclosure",
    "detected": true,
    "disclosed_version": "Apache-Coyote/1.1",
    "cves": [
        {
            "cve_id": "CVE-2005-2090",
            "description": "Jakarta Tomcat 5.0.19 (Coyote/1.1) and Tomcat 4.1.24 (Coyote/1.0) allows remote attackers to poison the web cache, bypass web application firewall protection, and conduct XSS attacks via an HTTP request with both a \"Transfer-Encoding: chunked\" header and a Content-Length header, which causes Tomcat to incorrectly handle and forward the body of the request in a way that causes the receiving server to process it as a separate HTTP request, aka \"HTTP Request Smuggling.\""
        }
    ]
}
## Authors

- [@alwinsr](https://github.com/alwinsr)

