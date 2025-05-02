# ethContractor

A tool for analyzing Ethereum smart contracts and transactions to identify potential phishing attempts and/or other malicious behavior on the blockchain.

## Overview

ethContractor analyzes Ethereum addresses and their transactions to identify potential phishing operations and/or other malicious behavior. It examines transaction input data, detects contract interactions, and decodes embedded strings to identify suspicious URLs and domains. The tool highlights potential phishing indicators and provides a comprehensive summary of all discovered domains as Indicators of Compromise (IOCs).

## Features

- Ethereum address and transaction analysis
- Smart contract interaction detection
- Transaction input data decoding
- Automatic detection of suspicious URLs and domains
- Phishing indicator highlighting
- Color-coded output for improved readability
- Comprehensive IOC summary with domain frequency analysis
- Case-insensitive address comparison for better accuracy

## Requirements

- Python 3.6+
- Etherscan API key

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/ethContractor.git
   cd ethContractor
   ```

2. Create a virtual environment and activate it:
   ```
   python3 -m venv env
   source env/bin/activate
   ```

3. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

4. Create a `.env` file with your Etherscan API key:
   ```
   ETHERSCAN_API_KEY=your_api_key_here
   ```

## Usage

### Analyze an Ethereum Account

```
python ethcontractor.py -e 0x3249b1630d6a2a....
```


## How It Works

ethContractor analyzes Ethereum transactions in multiple stages:

1. Retrieves transaction data for the specified Ethereum address using the Etherscan API
2. Identifies contract interactions by examining transaction 'to' addresses and input data
3. Uses both direct and indirect references to ensure comprehensive detection
4. Processes transaction input data and decodes it to extract meaningful information
5. Applies regular expression pattern matching to identify potential domains and URLs
6. Highlights suspicious indicators using color-coded output
7. Aggregates all discovered domains and displays them as potential IOCs
8. Provides frequency analysis to show which domains appear most often

## Example Output

When analyzing a phishing threat actor's address, ethContractor will produce output similar to:

```
+----------------------------------------------------------+
| TX 7 2025-01-23 00:32:23                                 |
+----------------------------------------------------------+
| Hash: 0xddacecc8e25b652....                               |
| Method: 0xac292d30                                       |
| Function: s(string n)                                    |
+----------------------------------------------------------+
+----------------------------------------------------------+
| DECODED DATA                                             |
| ·)-0······························· ···················· |
| ············secured-chrono24[.]com/home/······            |
+----------------------------------------------------------+

------------------------------------------------------------
[+] INDICATORS OF COMPROMISE
------------------------------------------------------------
+----------------------------------------------------------+
| DOMAINS OF INTEREST                                      |
+----------------------------------------------------------+
| client-blockfi[.]com          client[.]842393-bittrex[.]com   |
| client-kroll[.]com            client[.]842739-bittrex[.]com   |
| client[.]23827-bittrex[.]com    client[.]87242-blockfi[.]com    |
| ...                                                      |
+----------------------------------------------------------+
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

