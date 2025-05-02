#!/usr/bin/env python3

import os
import argparse
import re
from datetime import datetime
from colorama import Fore, init

# Initialize colorama
init(autoreset=True)

# load python-dotenv
from dotenv import load_dotenv
load_dotenv()

from utils.ethacc import eth_account, transaction

ETHERSCAN_API_KEY = os.getenv("ETHERSCAN_API_KEY")

# Global collection to track all unique domains across all analyses
all_discovered_domains = set()


def eth_account_operations(address):
    print(f"{Fore.GREEN}[+] {Fore.CYAN}Getting transactions for address: {Fore.WHITE}{address}")
    acc = eth_account(ETHERSCAN_API_KEY, address)

    # Get transaction data (now returns dict with complete_data and transactions)
    result = acc.get_transactions()

    # Access the full API responses and transactions separately
    complete_data = result['complete_data']
    transactions = result['transactions']

    # Print summary information
    print(f"{Fore.GREEN}[+] {Fore.CYAN}Found {Fore.WHITE}{len(transactions)} {Fore.CYAN}transactions across {Fore.WHITE}{len(complete_data)} {Fore.CYAN}pages")

    # Print all transactions, not just the most recent ones
    if transactions:
        print(f"{Fore.GREEN}[+] {Fore.CYAN}All transactions:")
        for i, tx in enumerate(transactions):
            # Convert hex value to ETH (dividing by 10^18)
            eth_value = float(int(tx.get('value', '0'), 16)/1e18) if tx.get('value') else 0.0
            print(f"{Fore.WHITE}  {i+1}. {Fore.YELLOW}Hash: {Fore.MAGENTA}{tx.get('hash')} {Fore.CYAN}| Value: {Fore.WHITE}{eth_value:.6f} ETH")

        # Add a summary of what types of transactions were found
        contract_txs = sum(1 for tx in transactions if tx.get('input') and tx.get('input') != '0x')
        value_txs = sum(1 for tx in transactions if float(int(tx.get('value', '0'), 16)) > 0)
        print(f"\n{Fore.GREEN}[+] {Fore.CYAN}Summary: {Fore.WHITE}{contract_txs} {Fore.CYAN}contract interactions, {Fore.WHITE}{value_txs} {Fore.CYAN}value transfers")

        # Create an instance of the transaction class to parse contract interactions
        contract_data = transaction(address, transactions)
        contract_addresses = contract_data.contract_addresses()

        # Display contract addresses in a more readable format
        # store contract addresses in a list
        contract_addresses_list = []
        if contract_addresses:
            print(f"\n{Fore.GREEN}[+] {Fore.CYAN}Found {Fore.WHITE}{len(contract_addresses)} {Fore.CYAN}contract interactions:")
            for i, address in enumerate(contract_addresses):
                print(f"  {Fore.WHITE}{i+1}. {Fore.MAGENTA}{address}")
                contract_addresses_list.append(address)

            # Process inputs for each contract
            for contract_address in contract_addresses_list:
                process_contract_inputs(contract_address, transactions)
        else:
            print(f"\n{Fore.YELLOW}[!] No contract interactions found for this address")
    return result

def process_contract_inputs(contract_address, transactions):
    """Process and display contract input data"""
    # Initialize variables to track potential phishing URLs
    potential_phishing_urls = []
    all_detected_domains = set()

    input_data_found = False
    
    # Create regex patterns using the imported re module
    selector_pattern = re.compile(r'^0x[a-fA-F0-9]{8}')
    domain_pattern = re.compile(r'([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)*)')
    # Also define URL pattern which is used later
    url_pattern = re.compile(r'https?://[\w\.-]+(?:/[\w\.-]*)*/?')

    # Process transactions for this contract - use case-insensitive comparison
    contract_txs = []
    contract_addr_lower = contract_address.lower()
    
    for tx in transactions:
        # Normalize addresses for reliable comparison
        tx_to = tx.get('to', '').lower() if tx.get('to') else ''
        tx_from = tx.get('from', '').lower() if tx.get('from') else ''
        tx_contract_addr = tx.get('contractAddress', '').lower() if tx.get('contractAddress') else ''
        tx_input = tx.get('input', '0x')
        
        # Make sure we catch interaction from any direction - this is critical!
        # We want transactions TO the contract as well as transactions FROM the contract
        if tx_input and tx_input != '0x' and (
            # Contract is the destination
            tx_to == contract_addr_lower or
            # Contract was created in this transaction
            tx_contract_addr == contract_addr_lower or
            tx.get('creates', '').lower() == contract_addr_lower or
            # The contract was directly mentioned in transaction input data
            contract_addr_lower in tx_input
        ):
            contract_txs.append(tx)

    if contract_txs:
        # Include contract address in the summary
        short_addr = contract_address[:10] + '...' + contract_address[-8:] if len(contract_address) > 22 else contract_address
        print(f"{Fore.GREEN}[+] {Fore.CYAN}Found {len(contract_txs)} {Fore.CYAN}transaction inputs for contract {Fore.WHITE}{short_addr}{Fore.RESET}")

        for i, tx in enumerate(contract_txs, 1):
            input_data = tx.get('input')

            if input_data and input_data != '0x':
                input_data_found = True

                # Extract function selector
                selector_match = selector_pattern.match(input_data)
                method_id = selector_match.group(0) if selector_match else 'Unknown'

                # Get function name (in this version, just show method_id)
                function_name = "Unknown"

                # If input data starts with 0xac292d30, it's likely a function named "s" with a string parameter
                if method_id == "0xac292d30":
                    function_name = "s(string n)"
                # Add other known function signatures here

                # Format timestamp
                timestamp = int(tx.get('timeStamp', '0'))
                date_str = datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")

                # Display transaction details with simpler formatting
                print(f"\n{Fore.CYAN}+{'-' * 58}+")
                print(f"{Fore.CYAN}| {Fore.YELLOW}TX {i} {date_str}{' ' * (43 - len(str(i)))}|")
                print(f"{Fore.CYAN}+{'-' * 58}+")

                # Truncate hash if too long
                tx_hash = tx.get('hash', '')
                if len(tx_hash) > 45:
                    tx_hash = tx_hash[:42] + '...'

                # Print transaction details (more compact) - removed Block line
                print(f"{Fore.CYAN}| {Fore.YELLOW}Hash: {Fore.WHITE}{tx_hash}{' ' * (46 - len(tx_hash))}|")
                print(f"{Fore.CYAN}| {Fore.YELLOW}Method: {Fore.WHITE}{method_id}{' ' * (45 - len(method_id))}|")
                print(f"{Fore.CYAN}| {Fore.YELLOW}Function: {Fore.WHITE}{function_name}{' ' * (43 - len(function_name))}|")
                print(f"{Fore.CYAN}+{'-' * 58}+")

                # Try to decode the input data if it's possibly ASCII
                if len(input_data) > 2:  # Check if there's something beyond the '0x' prefix
                    # Skip the '0x' prefix and convert hex to bytes
                    try:
                        input_bytes = bytes.fromhex(input_data[2:])
                        # Try to decode as ASCII, replacing non-printable chars with dots
                        ascii_text = ''
                        for byte in input_bytes:
                            if 32 <= byte <= 126:  # ASCII printable range
                                ascii_text += chr(byte)
                            else:
                                ascii_text += '·'  # Use middle dot for non-printable chars

                        # If we found something potentially readable, display i
                        if ascii_text and not all(c == '·' for c in ascii_text):
                            # Extract and highlight any URLs or domains found in the decoded tex
                            print(f"{Fore.CYAN}+{'-' * 58}+")
                            print(f"{Fore.CYAN}| {Fore.YELLOW}DECODED DATA{' ' * 47}|")

                            # URL pattern is defined at the top of the function

                            # Split ASCII text into chunks that fit in our display box
                            chunk_size = 56
                            text_chunks = [ascii_text[i:i+chunk_size] for i in range(0, len(ascii_text), chunk_size)]

                            domain_matches = set()  # Track domains found in this transaction

                            for chunk in text_chunks:
                                highlighted_chunk = chunk

                                # Find all domain matches in this chunk
                                for domain in domain_pattern.finditer(chunk):
                                    domain_name = domain.group(0)
                                    domain_matches.add(domain_name)
                                    all_discovered_domains.add(domain_name)

                                # Check for phishing indicators but don't show the warning
                                phishing_indicators = ['client', 'login', 'secure', 'account', 'verify', 'wallet',
                                                'reward', 'bonus', 'crypto']

                                # Look for URL matches to highligh
                                for match in url_pattern.finditer(chunk):
                                    url = match.group(0)
                                    start, end = match.span()

                                    # Check if this looks like a phishing URL
                                    is_phishing = False
                                    for indicator in phishing_indicators:
                                        if indicator.lower() in url.lower():
                                            is_phishing = True
                                            break

                                    # Store URL for later analysis
                                    potential_phishing_urls.append({
                                        'url': url,
                                        'tx_hash': tx.get('hash'),
                                        'is_phishing': is_phishing
                                    })

                                    # Highlight the URL in the tex
                                    # Construct the highlighted chunk by replacing the URL with a colored version
                                    if is_phishing:
                                        colored_url = f"{Fore.RED}{url}{Fore.WHITE}"
                                    else:
                                        colored_url = f"{Fore.GREEN}{url}{Fore.WHITE}"

                                    highlighted_chunk = highlighted_chunk[:start] + colored_url + highlighted_chunk[end:]

                                # Display the chunk with any highlights
                                print(f"{Fore.CYAN}| {Fore.WHITE}{highlighted_chunk}{' ' * (56 - len(chunk))}|")
                    except Exception as e:
                        # Print error but continue with next transaction
                        print(f"{Fore.RED}[!] Error decoding input data: {e}")

                # End the transaction box
                print(f"{Fore.CYAN}+{'-' * 58}+")

    # Print domain analysis at the end if there are any domains found
    if potential_phishing_urls:
        print(f"\n{Fore.CYAN}+{'-' * 58}+")
        print(f"{Fore.CYAN}| {Fore.YELLOW}DOMAIN ANALYSIS{' ' * 43}|")
        print(f"{Fore.CYAN}+{'-' * 58}+")

        # Count phishing URLs
        phishing_count = sum(1 for item in potential_phishing_urls if item.get('is_phishing', False))

        # Extract all unique domains from URLs
        domains_by_frequency = {}
        url_domains = set()  # Track domains to count unique ones

        for item in potential_phishing_urls:
            url = item['url']
            domain_match = domain_pattern.search(url)
            if domain_match:
                domain = domain_match.group(0)
                url_domains.add(domain)
                # Add to global domains collection
                all_discovered_domains.add(domain)
                if domain not in domains_by_frequency:
                    domains_by_frequency[domain] = 0
                domains_by_frequency[domain] += 1

        # Display URL summary with accurate domain count
        print(f"{Fore.CYAN}| {Fore.YELLOW}URLs: {Fore.WHITE}{len(potential_phishing_urls)} {Fore.YELLOW}- {Fore.WHITE}{len(url_domains)} {Fore.YELLOW}domains - {Fore.WHITE}{phishing_count} {Fore.YELLOW}phishing{' ' * 7}|")

        # Sort domains by frequency
        sorted_domains = sorted(domains_by_frequency.items(), key=lambda x: x[1], reverse=True)

        print(f"{Fore.CYAN}+{'-' * 58}+")
        print(f"{Fore.CYAN}| {Fore.YELLOW}Domain Frequency:{' ' * 42}|")

        for domain, count in sorted_domains:
            # Format domain and count to fit in box
            domain_text = f"{domain}: {count} occurrences"
            if len(domain_text) > 56:
                domain_text = domain_text[:53] + '...'
            padding = ' ' * (56 - len(domain_text))
            print(f"{Fore.CYAN}| {Fore.WHITE}{domain_text}{padding}|")

        # End the box after domain frequency
        print(f"{Fore.CYAN}+{'-' * 58}+")
    else:
        # Try a different approach - look for any transactions mentioning this contract address
        # This catches cases where the contract might be referenced in other ways
        fallback_txs = []
        contract_addr_lower = contract_address.lower()
        
        # Analyze all transactions that might involve this contract
        # This is a more general approach that doesn't rely on hardcoded special cases
        for tx in transactions:
            # Get input data and convert to lowercase for searching
            tx_to = tx.get('to', '').lower()
            tx_input = tx.get('input', '0x').lower()
            
            # Check for direct transaction where we are sending TO the contract
            if tx_to == contract_addr_lower and tx_input != '0x' and len(tx_input) > 10:
                fallback_txs.append(tx)
            # Also check if this transaction mentions our contract address anywhere in the input
            elif contract_addr_lower in tx_input and tx_input != '0x' and len(tx_input) > 10:
                fallback_txs.append(tx)
        
        if fallback_txs:
            # Found some transactions that mention this contract!
            short_addr = contract_address[:10] + '...' + contract_address[-8:] if len(contract_address) > 22 else contract_address
            print(f"{Fore.GREEN}[+] {Fore.CYAN}Found {len(fallback_txs)} {Fore.CYAN}indirect references to contract {Fore.WHITE}{short_addr}{Fore.RESET}")
            
            # Process these transactions just like we would direct contract calls
            for i, tx in enumerate(fallback_txs, 1):
                input_data = tx.get('input')
                
                if input_data and input_data != '0x':
                    input_data_found = True
                    
                    # Extract function selector
                    selector_match = selector_pattern.match(input_data)
                    method_id = selector_match.group(0) if selector_match else 'Unknown'
                    
                    # Get function name
                    function_name = "Unknown"
                    
                    # Common function names
                    if method_id == "0xac292d30":
                        function_name = "s(string n)"
                    
                    # Format timestamp
                    timestamp = int(tx.get('timeStamp', '0'))
                    date_str = datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")
                    
                    # Display transaction details with simpler formatting
                    print(f"\n{Fore.CYAN}+{'-' * 58}+")
                    print(f"{Fore.CYAN}| {Fore.YELLOW}TX {i} {date_str}{' ' * (43 - len(str(i)))}|")
                    print(f"{Fore.CYAN}+{'-' * 58}+")
                    
                    # Truncate hash if too long
                    tx_hash = tx.get('hash', '')
                    if len(tx_hash) > 45:
                        tx_hash = tx_hash[:42] + '...'
                    
                    # Print transaction details (more compact) - without Block line
                    print(f"{Fore.CYAN}| {Fore.YELLOW}Hash: {Fore.WHITE}{tx_hash}{' ' * (46 - len(tx_hash))}|")
                    print(f"{Fore.CYAN}| {Fore.YELLOW}Method: {Fore.WHITE}{method_id}{' ' * (45 - len(method_id))}|")
                    print(f"{Fore.CYAN}| {Fore.YELLOW}Function: {Fore.WHITE}{function_name}{' ' * (43 - len(function_name))}|")
                    print(f"{Fore.CYAN}+{'-' * 58}+")
                    
                    # Same decoded data processing as the main function
                    # Try to decode the input data if it's possibly ASCII
                    if len(input_data) > 2:
                        try:
                            # Skip the '0x' prefix and convert hex to bytes
                            hex_data = input_data[2:]
                            data_bytes = bytes.fromhex(hex_data)
                            
                            # Try to decode as ASCII, replacing non-printable chars with dots
                            ascii_text = ''
                            for b in data_bytes:
                                if 32 <= b <= 126:  # Printable ASCII range
                                    ascii_text += chr(b)
                                else:
                                    ascii_text += '·'
                            
                            # If we found something potentially readable, display it
                            if ascii_text and not all(c == '·' for c in ascii_text):
                                # Extract and highlight any URLs or domains found in the decoded text
                                print(f"{Fore.CYAN}+{'-' * 58}+")
                                print(f"{Fore.CYAN}| {Fore.YELLOW}DECODED DATA{' ' * 47}|")
                                
                                # URL pattern is defined at the top of the function
                                
                                # Split ASCII text into chunks that fit in our display box
                                chunk_size = 56
                                text_chunks = [ascii_text[i:i+chunk_size] for i in range(0, len(ascii_text), chunk_size)]
                                
                                domain_matches = set()  # Track domains found in this transaction
                                
                                for chunk in text_chunks:
                                    highlighted_chunk = chunk
                                    
                                    # Check for phishing indicators but don't show the warning
                                    phishing_indicators = ['client', 'login', 'secure', 'account', 'verify', 'wallet', 
                                                    'reward', 'bonus', 'crypto']
                                    
                                    # Look for URL matches to highlight
                                    for match in url_pattern.finditer(chunk):
                                        url = match.group(0)
                                        start, end = match.span()
                                        
                                        # Check if this looks like a phishing URL
                                        is_phishing = False
                                        for indicator in phishing_indicators:
                                            if indicator.lower() in url.lower():
                                                is_phishing = True
                                                break
                                        
                                        # Store URL for later analysis
                                        potential_phishing_urls.append({
                                            'url': url,
                                            'tx_hash': tx.get('hash'),
                                            'is_phishing': is_phishing
                                        })
                                        
                                        # Highlight the URL in the text
                                        # Construct the highlighted chunk by replacing the URL with a colored version
                                        if is_phishing:
                                            colored_url = f"{Fore.RED}{url}{Fore.WHITE}"
                                        else:
                                            colored_url = f"{Fore.GREEN}{url}{Fore.WHITE}"
                                        
                                        highlighted_chunk = highlighted_chunk[:start] + colored_url + highlighted_chunk[end:]
                                    
                                    # Display the chunk with any highlights
                                    print(f"{Fore.CYAN}| {Fore.WHITE}{highlighted_chunk}{' ' * (56 - len(chunk))}|")
                            
                                # Look for domains in the text
                                for match in domain_pattern.finditer(ascii_text):
                                    domain = match.group(1)
                                    if domain and '.' in domain:  # Valid domain must have at least one dot
                                        domain_matches.add(domain)
                                        # Add to the global collection
                                        all_discovered_domains.add(domain)
                        except Exception as e:
                            # Print error but continue with next transaction
                            print(f"{Fore.RED}[!] Error decoding input data: {e}")
                    
                    # End the transaction box
                    print(f"{Fore.CYAN}+{'-' * 58}+")
        else:
            print(f"\n{Fore.YELLOW}[!] No input data found for contract {Fore.MAGENTA}{contract_address}")


def display_iocs():
    """Display all unique domains discovered as Indicators of Compromise"""
    if not all_discovered_domains:
        return

    print(f"\n{Fore.WHITE}{'-' * 60}")
    print(f"{Fore.YELLOW}[+] INDICATORS OF COMPROMISE{Fore.RESET}")
    print(f"{Fore.WHITE}{'-' * 60}")

    print(f"{Fore.CYAN}+{'-' * 58}+")
    print(f"{Fore.CYAN}| {Fore.RED}DOMAINS OF INTEREST{' ' * 39}|")

    # Display in a more compact format - 2 column layout if enough domains
    sorted_domains = sorted(all_discovered_domains)

    # Determine if we should use 2 column layout (8+ domains)
    if len(sorted_domains) >= 8:
        # Calculate rows needed
        rows = (len(sorted_domains) + 1) // 2

        # Print header separator
        print(f"{Fore.CYAN}+{'-' * 58}+")

        # Print domains in two columns
        for i in range(rows):
            left_domain = sorted_domains[i] if i < len(sorted_domains) else ""
            right_idx = i + rows
            right_domain = sorted_domains[right_idx] if right_idx < len(sorted_domains) else ""

            if right_domain:
                # Truncate if needed
                if len(left_domain) > 27:
                    left_domain = left_domain[:24] + "..."
                if len(right_domain) > 27:
                    right_domain = right_domain[:24] + "..."

                padding = ' ' * (27 - len(left_domain))
                print(f"{Fore.CYAN}| {Fore.WHITE}{left_domain}{padding} {Fore.WHITE}{right_domain}{' ' * (27 - len(right_domain))}|")
            else:
                # Just show left domain on the last row if odd number
                if len(left_domain) > 56:
                    left_domain = left_domain[:53] + "..."
                padding = ' ' * (56 - len(left_domain))
                print(f"{Fore.CYAN}| {Fore.WHITE}{left_domain}{padding}|")
    else:
        # Single column layout for few domains
        print(f"{Fore.CYAN}+{'-' * 58}+")
        for domain in sorted_domains:
            if len(domain) > 56:
                domain = domain[:53] + "..."
            padding = ' ' * (56 - len(domain))
            print(f"{Fore.CYAN}| {Fore.WHITE}{domain}{padding}|")

    print(f"{Fore.CYAN}+{'-' * 58}+")

if __name__ == "__main__":
    # parse command line arguments for either eth address or contract address
    parser = argparse.ArgumentParser(description="Extract information from Ethereum contracts")
    parser.add_argument("-e", "--eth", help="Ethereum address to analyze")
    args = parser.parse_args()

    # check if either -c or -e is provided
    if not args.eth:
        print("Error: -e must be provided")
        exit(1)

    if args.eth:
        # get account information
        print(f"Getting account information for {args.eth}")
        eth_account_operations(args.eth)

    # Display IOCs at the end of the analysis
    display_iocs()