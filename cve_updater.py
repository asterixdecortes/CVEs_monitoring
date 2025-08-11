import os
import json
import requests
import datetime

CACHE_FILE = "cache.json"
CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.getenv("NVD_API_KEY") 

# Loads data from a JSON file or returns an empty dictionary

def load_cache():
    if not os.path.exists(CACHE_FILE):
        print("Cache file not found. Exiting.")
        return {}
    with open(CACHE_FILE, "r") as f:
        return json.load(f)

# Saves data inside a cache file (JSON)
def save_cache(cache):
    with open(CACHE_FILE, "w") as f:
        json.dump(cache, f, indent=2)

# Gets the vulnerabilities (CVEs) from a CPE using NVD API
def fetch_cves_for_cpe(cpe_name):
    # Parameters for the request, the max entries per page are 1000 if we wanted more we would have to check more pages
    params = {
        "cpeName": cpe_name,
        "resultsPerPage": 1000,
        "startIndex": 0
    }
    # Headers for the HTTP request
    headers = {"User-Agent": "cve-updater"}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    # Makes the petition and transform it in a json format, if the fetch fails, throws exception with the HTTP error code
    response = requests.get(CVE_API_URL, params=params, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(f"Failed to fetch for {cpe_name}: {response.status_code} - {response.text}")

# Updates the vulnerabilities for each CPE found in cache
def update_all_cpes():
    # Loads the file, if it does not exist or is empty, the script will end as there is nothing to update
    cache = load_cache()
    if not cache:
        print("Cache file is empty")
        return 

    # Shows how many CPE per file
    print(f"Starting update for {len(cache)} CPEs...")
    updated = False

    # This will go through every entry in our dictionary. CPE is the identifier and data the info about it
    for cpe, data in cache.items():
        print(f"Checking: {cpe}")
        try:
            # store the newest info from the API and gets the vulnerabilities
            latest_data = fetch_cves_for_cpe(cpe)
            new_vulns = latest_data.get("vulnerabilities", [])
            # get the vulnerabilities from our existing file
            old_vulns = data.get("vulnerabilities", [])
            # set of CVE IDs to not get them doubled
            old_ids = {v.get("cve", {}).get("id") for v in old_vulns}

            # go through all the entries in the API call we just made then compare the vulnerabilitie ID with the ones already in our file.
            # if it does not exist, it will get added to old_vulns and will add one to our new_found counter
            new_found = 0
            # List to store new CVEs IDs
            new_ids_list = []
            for vuln in new_vulns:
                cve_id = vuln.get("cve", {}).get("id")
                if cve_id not in old_ids:
                    old_vulns.append(vuln)
                    new_found += 1
                    new_ids_list.append(cve_id)
            
            # if we found any new vulnerability, it shows how many and each of them, updates the cache file and updates the last modification datetime
            if new_found > 0:
                print(f"Found {new_found} new CVEs. Updating...")
                for cve_id in new_ids_list:
                    print(f"   - {cve_id}")
                data["vulnerabilities"] = old_vulns
                data["last_updated"] = datetime.utcnow().isoformat() + "Z"
                updated = True
            else:
                print("No new CVEs found.")

        except Exception as e:
            print(f"Error checking {cpe}: {e}")

    if updated:
        save_cache(cache)
        print("Cache file updated.")
    else:
        print("No updates were needed.")

if __name__ == "__main__":
    update_all_cpes()