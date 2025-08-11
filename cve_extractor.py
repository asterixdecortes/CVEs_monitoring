# el cliente dice CPE, si no tenemos la base de datosm vamos al nist y buscamos vulnerabilidades, despuess checks periodicos 

# despues preguntar por un cve concreto

import requests
import json
import os

CACHE_FILE = "cache.json"
CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.getenv("NVD_API_KEY")  # API KEY, optional

# Loads data from a JSON file or returns an empty dictionary
def load_cache():
    if not os.path.exists(CACHE_FILE):
        print("Cache file not found, creating...")
        with open(CACHE_FILE, "w") as f:
            json.dump({}, f)
        return {}

    with open(CACHE_FILE, "r") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            print("Cache file was corrupt, starting from scratch.")
            return {}

# Saves data inside a cache file (JSON)
def save_cache(cache_data):
    with open(CACHE_FILE, "w") as f:
        json.dump(cache_data, f, indent=2)

# Gets the vulnerabilities (CVEs) from a CPE using NVD API
def fetch_cves_for_cpe(cpe_name):
    print(f"Searching CVEs for: {cpe_name}")
    # Parameters for the request, the max entries per page are 1000 if we wanted more we would have to check more pages
    params = {
        "cpeName": cpe_name,
        "resultsPerPage": 1000,
        "startIndex": 0
    }
    # Headers for the HTTP request
    headers = {"User-Agent": "python-script"}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    # Makes the petition and transform it in a json format, if the fetch fails, throws exception with the HTTP error code
    response = requests.get(CVE_API_URL, params=params, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(f"CVE fetch failed: {response.status_code} - {response.text}")

# Looks for the vulnerabilities in our cache filem if not found there, it calls the function to make the API requests
def search_cves_by_cpe(cpe):
    cache = load_cache()
    
    try:
        new_data = fetch_cves_for_cpe(cpe)
        # In case there are no vulnerabilities
        if "vulnerabilities" not in new_data:
            print("No CVEs found in NVD")
            return None
        
        new_vulns = new_data["vulnerabilities"]
        # First time we see the CPE, we store all CVEs
        if cpe not in cache:
            cache[cpe] = new_data
            save_cache(cache)
            print(f"Added {len(new_vulns)} vulnerabilities to cache")
            return new_data
        # We already had it, we have to check if there are new CVEs
        else:
            old_vulns = cache[cpe].get("vulnerabilities", [])
            old_ids = {v.get("cve", {}).get("id") for v in old_vulns}
            combined_vulns = list(old_vulns)

            new_count = 0
            for v in new_vulns:
                cve_id = v.get("cve", {}).get("id")
                if cve_id not in old_ids:
                    combined_vulns.append(v)
                    new_count += 1

            if new_count > 0:
                print(f"{new_count} new vulnerabilities found! Updating cache.")
                cache[cpe]["vulnerabilities"] = combined_vulns
                save_cache(cache)
            else:
                print("No new vulnerabilities found. Cache is up to date.")

            return {"vulnerabilities": combined_vulns}
    except Exception as e:
        print(f"Error: {e}")
        return None

def main():
    # Asks the user for a CPE and uses strip to cleanse spacing at the beginning and the end
    cpe_input = input("Insert a CPE (ex: cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*): ").strip()
    # Calls the function to look for CVEs and stores the result
    result = search_cves_by_cpe(cpe_input)

    # Checks that there is vulnerabilities in result, if there are none, everything is cool and your script ends
    if result and "vulnerabilities" in result:
        # Extracts all the vulnerabilities and shows how many there are
        vulns = result["vulnerabilities"]
        print(f"\nFound {len(vulns)} vulnerabilities:\n")
        # For each vulnerabilitie found, extracts and shows CVE id and short description
        for v in vulns:
            cve_id = v.get("cve", {}).get("id", "Unknown")
            desc = v.get("cve", {}).get("descriptions", [{}])[0].get("value", "No description")
            print(f"- {cve_id}: {desc[:150]}...")
    # No vulnerabilities found
    else:
        print("No CVE data returned.")

if __name__ == "__main__":
    main()
