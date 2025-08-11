# CVEs_monitoring
The scripts in this repository are meant to find CVEs (Common Vulnerabilities and Exposures) from given CPEs (Common Platform Enumeration) according to NIST database (NVD)

This will use the NIST API for CVEs
[API](https://services.nvd.nist.gov/rest/json/cves/2.0)

# How to use
First, you should run the cve_extractor.py to get the vulnerabilities affecting the CPEs you want to monitor then use the cve_updater.py with a service, a while(true) loop or add them to cron to monitor them.
## cve_extractor.py
Run the command in your linux terminal
```bash
python3 cve_extractor.py
```
This will ask you for a CPE, if you dont know what they are you can check them here:
[NIST CPE](https://nvd.nist.gov/products/cpe)

After the script runs, you will have a new file if it did not exist before called cache.json containing all the info of the vulnerabilities of the given CPE.

## cpe_updater.py
When all the CPEs you want to monitor are already in your cache.json file just run this script using
```bash
python3 cve_updater.py
```
This will check your file and the API and if there is any new vulnerability, it will be added to your file.
The recommended use for this script is to run it using a cron job.
An example to run the program every day at 00:00
```bash
crontab -e
```
Then we add a line like this to our file
```cron
0 0 * * * /usr/bin/python3 /COMPLETE/PATH/TO/cve_updater.py >> /path/to/a/log_file.txt 2>&1
```
This way, you will even have a logfile to check if something breaks.