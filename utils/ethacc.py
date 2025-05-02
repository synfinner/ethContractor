import requests
from time import sleep

# ethereum account class
class eth_account:
    def __init__(self, api_key, address):
        self.api_key = api_key
        self.address = address
        self.headers = {"User-Agent": "ethContractor"}
        self.trans_page = 1
        self.etherscan_transaction = f"https://api.etherscan.io/v2/api?chainid=1&module=account&action=txlist&address={address}&startblock=0&endblock=99999999&page={self.trans_page}&offset=10&sort=desc&apikey={api_key}"
        
    def get_transactions(self):
        page = self.trans_page
        # increment page and update url in a loop until the response json message is not "OK"
        # Store complete response data, not just the 'result' field
        all_data = []
        transactions = []
        
        while True:
            response = requests.get(self.etherscan_transaction, headers=self.headers)
            data = response.json()
            
            # Store the complete response data
            all_data.append(data)
            
            # Check if we've reached the end of pagination
            if data['message'] != "OK" or not data.get('result') or len(data['result']) == 0:
                break
                
            # Add results to our transactions list
            transactions.extend(data['result'])
            
            # Increment the page for next request
            page += 1
            self.trans_page = page
            self.etherscan_transaction = f"https://api.etherscan.io/v2/api?chainid=1&module=account&action=txlist&address={self.address}&startblock=0&endblock=99999999&page={self.trans_page}&offset=10&sort=desc&apikey={self.api_key}"
            
            # Rate limiting to avoid API throttling
            sleep(1.25)
        
        # Return both the full API responses and the extracted transactions list
        return {
            "complete_data": all_data,  # Full JSON responses from all API calls
            "transactions": transactions  # Just the transaction results for convenience
        }

# transaction parsing class to extract contract interactions
class transaction:
    def __init__(self, address, tx):
        self.tx = tx
        self.address = address # store the address as it will be the sender of transaction
        
    def contract_addresses(self):
        # Parse the transactions to find contract addresses
        # A transaction is considered a contract interaction if:
        # 1. It has non-empty input data (indicates contract method call)
        # 2. It's sent to an address (the contract) OR it creates a contract
        
        try:
            # Track unique contract addresses
            unique_addresses = set()
            
            for tx in self.tx:
                # Always normalize addresses to lowercase for comparison
                tx_from = tx.get('from', '').lower()
                tx_to = tx.get('to', '').lower() if tx.get('to') else ''
                tx_input = tx.get('input', '0x')
                tx_contract_addr = tx.get('contractAddress', '').lower() if tx.get('contractAddress') else ''
                tx_creates = tx.get('creates', '').lower() if tx.get('creates') else ''
                
                # Check for transactions from our address with non-empty input data (contract calls)
                if tx_from == self.address.lower() and tx_input and tx_input != '0x':
                    if tx_to and tx_to not in unique_addresses:
                        unique_addresses.add(tx_to)
                
                # Check for contract creation transactions
                if tx_contract_addr and tx_contract_addr not in unique_addresses:
                    unique_addresses.add(tx_contract_addr)
                
                # Check for 'creates' field (some APIs include this)
                if tx_creates and tx_creates not in unique_addresses:
                    unique_addresses.add(tx_creates)
                
            # Convert set to list for return
            contract_addresses = list(unique_addresses)
            
        except Exception as e:
            print(f"Error processing transactions: {e}")
            return []
            
        return contract_addresses
    
    def get_contract_inputs(self, contract_address):
        """Extract input data for interactions with a specific contract address
        
        Args:
            contract_address: The contract address to look for interactions with
            
        Returns:
            A list of dictionaries containing input data and metadata for each interaction
        """
        inputs = []
        
        try:
            for tx in self.tx:
                # Check if this is from our address to the contract address
                if (tx.get('from', '').lower() == self.address.lower() and 
                    tx.get('to', '').lower() == contract_address.lower() and 
                    tx.get('input') and tx.get('input') != '0x'):
                    
                    # Extract methodId if available, otherwise get it from input
                    method_id = tx.get('methodId', '')
                    if not method_id and len(tx.get('input', '')) >= 10:
                        method_id = tx.get('input', '')[:10]  # First 10 chars (0x + 8 chars)
                    
                    # Get function name if available
                    function_name = tx.get('functionName', 'Unknown Function')
                    
                    # Add to inputs list
                    inputs.append({
                        'tx_hash': tx.get('hash', ''),
                        'block_number': tx.get('blockNumber', ''),
                        'timestamp': tx.get('timeStamp', ''),
                        'input': tx.get('input', ''),
                        'method_id': method_id,
                        'function_name': function_name,
                        'value': tx.get('value', '0')
                    })
        except Exception as e:
            print(f"Error extracting input data: {e}")
        
        return inputs