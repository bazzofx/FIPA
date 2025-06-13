# FIPA
First Impact Phishing Analysis


# Requirements
This script is for Trend Micro customers only, (sorry) because it fetches data from the Vision One console using the API, you will need to have a valid account and be a customer of Trend Micro.
**PowerShell Version 7.0 or higher**

## API Keys Requirement
- Trend Vision One API Key
You will first need a Trend Micro Vision One API Key (You will need at least Auditor Priviledges so you can search the logs)
- AbuseIPDB API Key

Save the API Keys on your User Environment variable to match the name.
## **User Environment Variable**
### Trend API
```
Name : auditorApi
Value : YOUR_API_KEY
```
### Abuse IP DB
```
Name : abuseipdbAPI
Value : YOUR_API_KEY
```

# Installing

To install just import the Powershell module using
```
import-module first_impact_phishing_analysis.psm1
```
