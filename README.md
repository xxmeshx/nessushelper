# Nessushelper
Install dependencies

```bash
pip install -r requirements.txt
```
Examples
Vulnerabilities by host
```
python nessus.py nessus_file.csv --host
```
Vulnerabilities by risk
```
python nessus.py nessus_file.csv --risk
```
Vulnerabilities by vulns
```
python nessus.py nessus_file.csv --vulns
```
Vulnerabilities & fixes
```
python nessus.py nessus_file.csv --fix --exportfix my_file
python nessus.py nessus_file.csv --fix --exportvulns my_file
```
