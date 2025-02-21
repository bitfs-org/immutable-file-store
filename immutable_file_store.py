import hashlib
import argparse
import os
import asyncio
from typing import Tuple, Dict
import requests
from bsv import (
    PrivateKey, P2PKH, Transaction, TransactionInput, TransactionOutput, Network
)
from bsv.script.type import OpReturn
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import secrets
import json
from datetime import datetime
from secure_channel import SecureChannel
import time

# Network configuration and API endpoints
NETWORK = 'test'  # or 'main' for mainnet
WHATSONCHAIN_API = {
    'test': 'https://api.whatsonchain.com/v1/bsv/test',
    'main': 'https://api.whatsonchain.com/v1/bsv/main'
}

# Directory configuration
TEST_DATA_DIR = 'test_data'
PRIVATE_DIR = 'private'

class FileStore:
    def __init__(self, network: str = 'test'):
        """Initialize with network selection and master keys"""
        self.network = network
        self.api_url = WHATSONCHAIN_API[network]
        
        # Ensure directories exist
        os.makedirs(TEST_DATA_DIR, exist_ok=True)
        os.makedirs(PRIVATE_DIR, exist_ok=True)
        
        # Try to load existing private key or generate a new one
        key_file = os.path.join(PRIVATE_DIR, 'master_key.wif')
        if os.path.exists(key_file):
            with open(key_file, 'r') as f:
                wif = f.read().strip()
                self.master_private_key = PrivateKey(wif)
                print("Loaded existing private key")
        else:
            # Generate master key pair
            self.master_private_key = PrivateKey(secrets.token_bytes(32))
            # Save private key in WIF format
            with open(key_file, 'w') as f:
                f.write(self.master_private_key.wif(network=Network.TESTNET if network == "test" else Network.MAINNET))
            print("Generated and saved new private key")
        
        self.p2pkh = P2PKH()
        
        # Get the master public key
        self.master_public_key = self.master_private_key.public_key()
        
        # Initialize file index
        self.index_file = os.path.join(TEST_DATA_DIR, 'file_index.json')
        self.file_index = self._load_file_index()
        
        print(f"Master public key: {self.master_public_key.hex()}")
        
        # Initialize secure channel
        self.secure_channel = SecureChannel(self.master_private_key)

    def _load_file_index(self) -> Dict:
        """Load file index from disk or create new one"""
        if os.path.exists(self.index_file):
            try:
                with open(self.index_file, 'r') as f:
                    return json.load(f)
            except json.JSONDecodeError:
                print(f"Warning: Could not parse {self.index_file}, creating new index")
                return {}
        return {}

    def _save_file_index(self):
        """Save file index to disk"""
        with open(self.index_file, 'w') as f:
            json.dump(self.file_index, f, indent=2)

    def _add_file_to_index(self, original_path: str, file_hash: str, tx_id: str, file_address: str):
        """Add file metadata to index"""
        file_name = os.path.basename(original_path)
        file_size = os.path.getsize(original_path)
        
        metadata = {
            'file_name': file_name,
            'original_path': original_path,
            'file_size': file_size,
            'file_hash': file_hash,
            'transaction_id': tx_id,
            'file_address': file_address,
            'upload_time': datetime.now().isoformat(),
            'network': self.network
        }
        
        # Use file_hash as key to avoid duplicates
        self.file_index[file_hash] = metadata
        self._save_file_index()
        
        print("\nFile metadata saved to index:")
        print(json.dumps(metadata, indent=2))

    def list_files(self):
        """List all files in the index"""
        if not self.file_index:
            print("No files in index")
            return
        
        print("\nStored files:")
        for file_hash, metadata in self.file_index.items():
            print(f"\nFile: {metadata['file_name']}")
            print(f"Hash: {file_hash}")
            print(f"Size: {metadata['file_size']} bytes")
            print(f"Address: {metadata['file_address']}")
            print(f"Transaction: {metadata['transaction_id']}")
            print(f"Upload time: {metadata['upload_time']}")
            print(f"Network: {metadata['network']}")

    def _generate_file_keys(self, file_hash: bytes, index: bytes = b"1") -> Tuple[bytes, bytes, bytes]:
        """Generate deterministic keys for a file following the paper's method"""
        # Calculate s(file.1) = H[ Da(0) | H(file) | INDEX ]
        s_file_1 = hashlib.sha256(
            self.master_private_key.serialize() + file_hash + index
        ).digest()
        
        # Generate deterministic private key for the file
        file_private_key = PrivateKey(s_file_1)
        
        # Generate symmetric encryption key
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=file_hash,
            iterations=100000,
        )
        symmetric_key = base64.urlsafe_b64encode(
            kdf.derive(s_file_1)
        )
        
        return s_file_1, symmetric_key, file_private_key.serialize()

    def broadcast_transaction(self, tx_id: str, tx_hex: bytes) -> bool:
        """Broadcast a transaction to the network"""
        try:
            url = f"{self.api_url}/tx/raw"
            print(f"Broadcasting transaction to: {url}")
            response = requests.post(url, json={"txhex": tx_hex.hex()})
            print(f"Broadcast response status: {response.status_code}")
            print(f"Broadcast response: {response.text}")
            
            if response.status_code != 200:
                raise Exception(f"Failed to broadcast transaction: {response.text}")
            
            return True
        except Exception as e:
            print(f"Error broadcasting transaction: {str(e)}")
            return False

    async def _create_file_transaction(self, encrypted_content: bytes, file_private_key: bytes) -> Transaction:
        """Create a BSV transaction with the encrypted file content"""
        try:
            # Create private key for this file
            file_key = PrivateKey(file_private_key)
            
            # Get the deterministic address for this file
            file_address = file_key.public_key().address(
                network=Network.TESTNET if self.network == "test" else Network.MAINNET
            )
            
            # Get UTXO for funding address
            address_info = self._get_address_info(str(self.master_private_key.public_key().address(
                network=Network.TESTNET if self.network == "test" else Network.MAINNET
            )))
            
            if not address_info.get('utxos'):
                raise Exception("No UTXOs available for the address")
            
            # Get source transaction
            utxo = address_info['utxos'][0]
            source_tx_url = f"{self.api_url}/tx/{utxo['tx_hash']}/hex"
            print(f"Fetching source transaction from: {source_tx_url}")
            response = requests.get(source_tx_url)
            
            if response.status_code != 200:
                raise Exception(f"Failed to get source transaction: {response.text}")
            
            source_tx = Transaction.from_hex(response.text)
            
            # Create input
            tx_input = TransactionInput(
                source_transaction=source_tx,
                source_txid=source_tx.txid(),
                source_output_index=utxo['tx_pos'],
                unlocking_script_template=self.p2pkh.unlock(self.master_private_key)
            )
            
            # Create OP_RETURN output with encrypted content
            op_return = OpReturn()
            data_output = TransactionOutput(
                satoshis=0,
                locking_script=op_return.lock([encrypted_content])
            )
            
            # Use fixed fee
            fee = 1000  # 1000 satoshis
            
            # Create output to file's deterministic address
            file_p2pkh = P2PKH()
            file_output = TransactionOutput(
                satoshis=utxo['value'] - fee,  # Subtract fee
                locking_script=file_p2pkh.lock(file_address)
            )
            
            # Create and sign transaction
            tx = Transaction([tx_input], [data_output, file_output])
            tx.sign()
            
            return tx
            
        except Exception as e:
            print(f"Error in _create_file_transaction: {str(e)}")
            raise

    async def put_file(self, file_path: str) -> Tuple[str, str]:
        """Store file on BSV blockchain"""
        try:
            with open(file_path, 'rb') as file:
                file_content = file.read()
            
            encrypted_content, file_hash, file_private_key = self.encrypt_file(file_content)
            
            # Create BSV transaction
            tx = await self._create_file_transaction(encrypted_content, file_private_key)
            
            # Get the deterministic address for this file
            file_key = PrivateKey(file_private_key)
            file_address = file_key.public_key().address(
                network=Network.TESTNET if self.network == "test" else Network.MAINNET
            )
            
            # Broadcast transaction
            tx_hex = tx.serialize()
            tx_id = tx.txid()
            
            # Try to broadcast the transaction
            broadcast_success = self.broadcast_transaction(tx_id, tx_hex)
            if not broadcast_success:
                raise Exception("Failed to broadcast transaction")
            
            # Wait for transaction to appear in mempool
            print("\nWaiting for transaction to appear in mempool...")
            max_attempts = 5
            attempt = 0
            while attempt < max_attempts:
                if attempt > 0:
                    print(f"Retry attempt {attempt}/{max_attempts}")
                    time.sleep(2)
                
                # Check mempool
                mempool_url = f"{self.api_url}/tx/{tx_id}/hex"
                response = requests.get(mempool_url)
                if response.status_code == 200:
                    print("Transaction found in mempool")
                    break
                
                attempt += 1
            
            if attempt >= max_attempts:
                print("Warning: Transaction not found in mempool after retries")
            
            # Add file to index
            self._add_file_to_index(
                original_path=file_path,
                file_hash=file_hash.hex(),
                tx_id=tx_id,
                file_address=str(file_address)
            )
            
            # Print debug information
            print(f"File hash: {file_hash.hex()}")
            print(f"File address: {file_address}")
            print(f"Encrypted content size: {len(encrypted_content)} bytes")
            print(f"Transaction broadcast with {len(encrypted_content)} bytes of data")
            print(f"Transaction ID: {tx_id}")
            
            # Print block explorer URLs
            print("\nView transaction on block explorers:")
            for name, url in self.get_explorer_urls(tx_id).items():
                print(f"- {name}: {url}")
            
            return str(file_address), tx_id

        except Exception as e:
            raise Exception(f"Error storing file: {str(e)}")

    def encrypt_file(self, file_content: bytes) -> Tuple[bytes, bytes, bytes]:
        """Encrypt file content and generate necessary keys"""
        file_hash = hashlib.sha256(file_content).digest()
        s_file_1, symmetric_key, file_private_key = self._generate_file_keys(file_hash)
        
        # Use Fernet for secure symmetric encryption
        fernet = Fernet(symmetric_key)
        encrypted_content = fernet.encrypt(file_content)
        
        return encrypted_content, file_hash, file_private_key

    def decrypt_file(self, encrypted_content: bytes, file_hash: bytes) -> bytes:
        """Decrypt file content using regenerated keys"""
        _, symmetric_key, file_private_key = self._generate_file_keys(file_hash)
        
        fernet = Fernet(symmetric_key)
        decrypted_content = fernet.decrypt(encrypted_content)
        
        return decrypted_content

    def _get_address_info(self, address: str) -> dict:
        """Get address information from WhatsOnChain API"""
        try:
            # Get UTXOs (both confirmed and unconfirmed)
            unspent_url = f"{self.api_url}/address/{address}/unspent"
            unspent_response = requests.get(unspent_url)
            print(f"UTXOs response: {unspent_response.text}")
            utxos = unspent_response.json() if unspent_response.text.strip() else []
            print(f"All UTXOs: {utxos}")
            return {"utxos": utxos}
        except Exception as e:
            print(f"Error getting address info: {str(e)}")
            return {"utxos": []}

    def get_explorer_urls(self, tx_id: str) -> dict:
        """Get block explorer URLs for a transaction"""
        if self.network == 'test':
            return {
                'whatsonchain': f'https://test.whatsonchain.com/tx/{tx_id}',
                'bitcoincloud': f'https://testnet.bitcoincloud.net/tx/{tx_id}'
            }
        else:
            return {
                'whatsonchain': f'https://whatsonchain.com/tx/{tx_id}',
                'bitcoincloud': f'https://bitcoincloud.net/tx/{tx_id}'
            }

    def get_file(self, file_hash: str, save_path: str, save_name: str, max_retries: int = 3, retry_delay: float = 2.0) -> str:
        """Retrieve and decrypt file from BSV blockchain"""
        try:
            # Get file metadata from index
            if file_hash not in self.file_index:
                raise Exception(f"File with hash {file_hash} not found in index")
            
            metadata = self.file_index[file_hash]
            tx_id = metadata["transaction_id"]
            
            # Print block explorer URLs
            print("\nView transaction on block explorers:")
            for name, url in self.get_explorer_urls(tx_id).items():
                print(f"- {name}: {url}")
            print()
            
            encrypted_content = None
            attempt = 0
            while attempt < max_retries and not encrypted_content:
                if attempt > 0:
                    print(f"\nRetry attempt {attempt}/{max_retries}")
                    time.sleep(retry_delay)
                
                # Try to get transaction from mempool first
                mempool_url = f"{self.api_url}/tx/{tx_id}/hex"
                print(f"Fetching transaction from mempool: {mempool_url}")
                mempool_response = requests.get(mempool_url)
                print(f"Mempool response status: {mempool_response.status_code}")
                
                if mempool_response.status_code == 200:
                    print("Transaction found in mempool")
                    tx_hex = mempool_response.text
                    tx = Transaction.from_hex(tx_hex)
                    
                    # Find OP_RETURN output
                    for output in tx.outputs:
                        script = output.locking_script.script
                        if script.startswith(bytes.fromhex('006a')):  # OP_FALSE OP_RETURN
                            # Parse OP_RETURN data
                            # Format: OP_FALSE (00) + OP_RETURN (6a) + OP_PUSHDATA1 (4c) + length (xx) + data
                            if len(script) > 3 and script[2] == 0x4c:  # OP_PUSHDATA1
                                data_length = script[3]
                                encrypted_content = script[4:4+data_length]
                                print(f"Found OP_RETURN data in mempool tx")
                                break
                else:
                    # Try to get confirmed transaction
                    print("Transaction not found in mempool, trying blockchain...")
                    tx_url = f"{self.api_url}/tx/{tx_id}/raw"
                    tx_response = requests.get(tx_url)
                    print(f"Blockchain response status: {tx_response.status_code}")
                    
                    if tx_response.status_code == 200:
                        print("Transaction found in blockchain")
                        tx_data = tx_response.json()
                        # Extract encrypted content from OP_RETURN output
                        for vout in tx_data["vout"]:
                            script = vout["scriptPubKey"]["hex"]
                            if script.startswith("006a"):  # OP_FALSE OP_RETURN
                                if len(script) > 3 and script[2:4] == "4c":  # OP_PUSHDATA1
                                    data_length = int(script[4:6], 16)  # Length is 2 hex digits
                                    encrypted_content = bytes.fromhex(script[6:6+data_length*2])
                                    print(f"Found OP_RETURN data in confirmed tx")
                                    break
                
                attempt += 1
            
            if not encrypted_content:
                raise Exception("Transaction not found in mempool or blockchain after retries")
            
            print(f"Encrypted content size: {len(encrypted_content)} bytes")
            
            # Use the file hash from the index for decryption
            file_hash_bytes = bytes.fromhex(file_hash)
            decrypted_content = self.decrypt_file(encrypted_content, file_hash_bytes)
            
            # Save decrypted file
            full_path = os.path.join(save_path, save_name)
            with open(full_path, 'wb') as file:
                file.write(decrypted_content)
            
            print(f"\nFile metadata:")
            print(f"Name: {metadata['file_name']}")
            print(f"Size: {metadata['file_size']} bytes")
            print(f"Original path: {metadata['original_path']}")
            print(f"Upload time: {metadata['upload_time']}")
            
            return full_path

        except Exception as e:
            raise Exception(f"Error retrieving file: {str(e)}")

    async def share_file(self, file_hash: str, recipient_public_key: bytes) -> str:
        """Share a file with another user"""
        try:
            # Get file metadata
            if file_hash not in self.file_index:
                raise Exception(f"File with hash {file_hash} not found in index")
            
            metadata = self.file_index[file_hash]
            
            # Create share info
            share_info = {
                "file_hash": file_hash,
                "transaction_id": metadata["transaction_id"],
                "file_address": metadata["file_address"],
                "file_name": metadata["file_name"],
                "shared_time": datetime.now().isoformat()
            }
            
            # Encrypt share info for recipient
            encrypted_info = self.secure_channel.encrypt_for_peer(
                json.dumps(share_info).encode(),
                recipient_public_key
            )
            
            # Create and broadcast share transaction
            tx = await self._create_share_transaction(encrypted_info)
            tx_id = tx.txid()
            
            print(f"\nFile shared successfully:")
            print(f"Transaction ID: {tx_id}")
            print("\nView share transaction on block explorers:")
            for name, url in self.get_explorer_urls(tx_id).items():
                print(f"- {name}: {url}")
            
            return tx_id
            
        except Exception as e:
            raise Exception(f"Error sharing file: {str(e)}")

    async def _create_share_transaction(self, encrypted_info: bytes) -> Transaction:
        """Create a transaction containing encrypted share information"""
        try:
            # Get UTXO for funding address
            address_info = self._get_address_info(str(self.master_public_key.address(
                network=Network.TESTNET if self.network == "test" else Network.MAINNET
            )))
            
            if not address_info.get('utxos'):
                raise Exception("No UTXOs available for the address")
            
            # Get source transaction
            utxo = address_info['utxos'][0]
            source_tx_url = f"{self.api_url}/tx/{utxo['tx_hash']}/hex"
            response = requests.get(source_tx_url)
            
            if response.status_code != 200:
                raise Exception(f"Failed to get source transaction: {response.text}")
            
            source_tx = Transaction.from_hex(response.text)
            
            # Create input
            tx_input = TransactionInput(
                source_transaction=source_tx,
                source_txid=source_tx.txid(),
                source_output_index=utxo['tx_pos'],
                unlocking_script_template=self.p2pkh.unlock(self.master_private_key)
            )
            
            # Create OP_RETURN output with encrypted share info
            op_return = OpReturn()
            data_output = TransactionOutput(
                satoshis=0,
                locking_script=op_return.lock([encrypted_info])
            )
            
            # Use fixed fee
            fee = 1000  # 1000 satoshis
            
            # Create change output
            change_output = TransactionOutput(
                satoshis=utxo['value'] - fee,  # Subtract fee
                locking_script=self.p2pkh.lock(self.master_public_key.address(
                    network=Network.TESTNET if self.network == "test" else Network.MAINNET
                ))
            )
            
            # Create and sign transaction
            tx = Transaction([tx_input], [data_output, change_output])
            tx.sign()
            
            return tx
            
        except Exception as e:
            raise Exception(f"Error creating share transaction: {str(e)}")

    async def receive_shared_file(self, share_tx_id: str, sender_public_key: bytes) -> dict:
        """Receive a shared file from another user"""
        try:
            # Get share transaction
            tx_url = f"{self.api_url}/tx/{share_tx_id}/raw"
            response = requests.get(tx_url)
            
            if response.status_code != 200:
                raise Exception("Share transaction not found")
            
            tx_data = response.json()
            
            # Extract encrypted share info from OP_RETURN output
            encrypted_info = None
            for vout in tx_data["vout"]:
                script = vout["scriptPubKey"]["hex"]
                if script.startswith("006a"):  # OP_FALSE OP_RETURN
                    if len(script) > 3 and script[2] == 0x4c:  # OP_PUSHDATA1
                        data_length = script[3]
                        encrypted_info = bytes.fromhex(script)[4:4+data_length]
                        break
            
            if not encrypted_info:
                raise Exception("No share information found in transaction")
            
            # Decrypt share info
            decrypted_info = self.secure_channel.decrypt_from_peer(
                encrypted_info,
                sender_public_key
            )
            
            share_info = json.loads(decrypted_info.decode())
            
            print(f"\nReceived shared file:")
            print(f"File name: {share_info['file_name']}")
            print(f"File hash: {share_info['file_hash']}")
            print(f"Original transaction: {share_info['transaction_id']}")
            print(f"Shared time: {share_info['shared_time']}")
            
            return share_info
            
        except Exception as e:
            raise Exception(f"Error receiving shared file: {str(e)}")

async def main():
    parser = argparse.ArgumentParser(description='Immutable File and Data Store')
    parser.add_argument('operation', choices=['put', 'get', 'list', 'share', 'receive'], 
                      help='Operation to perform')
    parser.add_argument('--file', help='Local file path for put operation')
    parser.add_argument('--hash', help='File hash for get/share operation')
    parser.add_argument('--save_path', help='Path to save the downloaded file')
    parser.add_argument('--save_name', help='Name to save the downloaded file as')
    parser.add_argument('--recipient', help='Recipient public key for sharing (hex)')
    parser.add_argument('--sender', help='Sender public key for receiving (hex)')
    parser.add_argument('--share-tx', help='Share transaction ID for receiving')
    parser.add_argument('--retries', type=int, default=3, help='Number of retries for get operation')
    parser.add_argument('--retry-delay', type=float, default=2.0, help='Delay between retries in seconds')

    args = parser.parse_args()
    
    file_store = FileStore(NETWORK)

    try:
        if args.operation == 'put':
            if not args.file:
                raise ValueError("--file argument is required for 'put' operation")
            
            address, tx_id = await file_store.put_file(args.file)
            print(f"File stored successfully:")
            print(f"Address: {address}")
            print(f"Transaction ID: {tx_id}")

        elif args.operation == 'get':
            if not args.hash:
                raise ValueError("--hash argument is required for 'get' operation")
            
            save_path = args.save_path or TEST_DATA_DIR
            save_name = args.save_name or 'retrieved_file'
            
            file_path = file_store.get_file(
                args.hash, 
                save_path, 
                save_name,
                max_retries=args.retries,
                retry_delay=args.retry_delay
            )
            print(f"\nFile retrieved successfully and saved to: {file_path}")
            
        elif args.operation == 'list':
            file_store.list_files()

        elif args.operation == 'share':
            if not args.recipient:
                raise ValueError("--recipient argument is required for 'share' operation")
            
            share_tx_id = await file_store.share_file(args.hash, bytes.fromhex(args.recipient))
            print(f"File shared successfully:")
            print(f"Transaction ID: {share_tx_id}")

        elif args.operation == 'receive':
            if not args.share_tx:
                raise ValueError("--share-tx argument is required for 'receive' operation")
            
            if not args.sender:
                raise ValueError("--sender argument is required for 'receive' operation")
            
            share_info = await file_store.receive_shared_file(args.share_tx, bytes.fromhex(args.sender))
            print(f"Received shared file:")
            print(f"File name: {share_info['file_name']}")
            print(f"File hash: {share_info['file_hash']}")
            print(f"Original transaction: {share_info['transaction_id']}")
            print(f"Shared time: {share_info['shared_time']}")

    except Exception as e:
        print(f"Error: {str(e)}")
        return 1

    return 0

if __name__ == "__main__":
    exit(asyncio.run(main()))
