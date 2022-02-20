<!-- PROJECT LOGO -->
<br />
<div align="center">
  <a href="https://github.com/kyReid/greynoise-parser">
    <img src="images/icon.png" alt="Logo" width="80" height="80">
  </a>

  <h3 align="center">Greynoise Parser</h3>
</div>

## About

This parsing tool was built to  parse and organize valuable information queried using the Greynoise API

#### USECASES
1. Takes a list of IP addresses to then determine if any of them have been observed conducting malicious activity. For organizations this may serve as an indicator that the organization has suffered a breach.
2. Queries Greynoise based on commands input by the user. Gathers information such as (IP Address,Actor,Classification,Tags,Country,Organization,Tor,Operating System,Category,Scans,Bot, and CVE).

## Getting Started

### Built With

**packages**
- ipaddress = "*"
- greynoise = "*"
- argparse = "*"

**requires**
- python_version = "3.9"
  
### Installing

1. Clone the repository ``git clone https://github.com/KyReid/greynoise.git ``
2. Use the greynoise setup CLI command to input you API key

    - CLI IP Command: ``$ greynoise ip <ip_address> --api-key "<api_key>"``
  
    - API Client: ``$ api_client = GreyNoise(api_key=<api_key>)``
  
4. Enter ```greynoise-parser.py -h for help```

## Authors

Kyle Reid

## Acknowledgments

[Greynoise](https://docs.greynoise.io/docs/libraries-sample-code)
