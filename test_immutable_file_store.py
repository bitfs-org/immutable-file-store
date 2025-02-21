import unittest
import os
import json
import asyncio
from immutable_file_store import FileStore, TEST_DATA_DIR, PRIVATE_DIR
from bsv import PrivateKey
import secrets
import sys

class AsyncioTestCase(unittest.TestCase):
    def run(self, result=None):
        """Run the test case in an event loop"""
        loop = asyncio.get_event_loop()
        return loop.run_until_complete(self._run_test(result))
    
    async def _run_test(self, result=None):
        """Run the test case asynchronously"""
        result = result or self.defaultTestResult()
        result.startTest(self)
        try:
            try:
                await self.setUp()
            except Exception:
                result.addError(self, sys.exc_info())
                return
            try:
                testMethod = getattr(self, self._testMethodName)
                if asyncio.iscoroutinefunction(testMethod):
                    await testMethod()
                else:
                    testMethod()
            except Exception:
                result.addError(self, sys.exc_info())
            finally:
                try:
                    await self.tearDown()
                except Exception:
                    result.addError(self, sys.exc_info())
        finally:
            result.stopTest(self)

class TestImmutableFileStore(AsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        """Set up test fixtures that will be shared across all tests"""
        # Create test directories if they don't exist
        os.makedirs(TEST_DATA_DIR, exist_ok=True)
        os.makedirs(PRIVATE_DIR, exist_ok=True)
        
        # Create a test file
        cls.test_file_path = os.path.join(TEST_DATA_DIR, 'test_file.txt')
        cls.test_content = b"This is a test file for immutable file store testing."
        with open(cls.test_file_path, 'wb') as f:
            f.write(cls.test_content)

    async def setUp(self):
        """Set up test fixtures before each test"""
        self.file_store = FileStore('test')  # Use testnet for testing
        
        # Create a test file for each test
        self.current_test_file = os.path.join(TEST_DATA_DIR, f'test_file_{self._testMethodName}.txt')
        with open(self.current_test_file, 'wb') as f:
            f.write(f"Test content for {self._testMethodName}".encode())

    async def tearDown(self):
        """Clean up after each test"""
        # Remove test file
        if os.path.exists(self.current_test_file):
            os.remove(self.current_test_file)

    @classmethod
    def tearDownClass(cls):
        """Clean up after all tests"""
        # Remove test files
        if os.path.exists(cls.test_file_path):
            os.remove(cls.test_file_path)

    def test_initialization(self):
        """Test FileStore initialization"""
        self.assertIsNotNone(self.file_store.master_private_key)
        self.assertIsNotNone(self.file_store.master_public_key)
        self.assertTrue(os.path.exists(os.path.join(PRIVATE_DIR, 'master_key.wif')))
        self.assertTrue(os.path.exists(os.path.join(TEST_DATA_DIR, 'file_index.json')))

    def test_file_keys_generation(self):
        """Test deterministic key generation for files"""
        # Generate file hash
        file_hash = secrets.token_bytes(32)
        
        # Generate keys
        s_file_1, symmetric_key, file_private_key = self.file_store._generate_file_keys(file_hash)
        
        # Test key properties
        self.assertEqual(len(s_file_1), 32)  # SHA256 output is 32 bytes
        self.assertTrue(symmetric_key.endswith(b'='))  # Base64 encoded
        self.assertEqual(len(file_private_key), 32)  # Private key is 32 bytes

    def test_file_encryption_decryption(self):
        """Test file content encryption and decryption"""
        # Test content
        test_content = b"This is a test message for encryption and decryption."
        
        # Encrypt
        encrypted_content, file_hash, file_private_key = self.file_store.encrypt_file(test_content)
        
        # Decrypt
        decrypted_content = self.file_store.decrypt_file(encrypted_content, file_hash)
        
        # Verify
        self.assertEqual(test_content, decrypted_content)

    def test_file_index_operations(self):
        """Test file index loading, saving, and updating"""
        # Add a test entry
        test_hash = "test_hash"
        test_tx_id = "test_tx_id"
        test_address = "test_address"
        
        self.file_store._add_file_to_index(
            original_path=self.current_test_file,
            file_hash=test_hash,
            tx_id=test_tx_id,
            file_address=test_address
        )
        
        # Verify entry was added
        self.assertIn(test_hash, self.file_store.file_index)
        self.assertEqual(self.file_store.file_index[test_hash]['transaction_id'], test_tx_id)
        
        # Load index in a new FileStore instance
        new_store = FileStore('test')
        self.assertIn(test_hash, new_store.file_index)
        self.assertEqual(new_store.file_index[test_hash]['transaction_id'], test_tx_id)

    def test_explorer_urls(self):
        """Test block explorer URL generation"""
        test_tx_id = "test_tx_id"
        
        # Test testnet URLs
        testnet_urls = self.file_store.get_explorer_urls(test_tx_id)
        self.assertIn('whatsonchain', testnet_urls)
        self.assertIn('bitcoincloud', testnet_urls)
        self.assertTrue(testnet_urls['whatsonchain'].startswith('https://test.whatsonchain.com'))
        
        # Test mainnet URLs
        mainnet_store = FileStore('main')
        mainnet_urls = mainnet_store.get_explorer_urls(test_tx_id)
        self.assertTrue(mainnet_urls['whatsonchain'].startswith('https://whatsonchain.com'))

    async def test_transaction_creation(self):
        """Test BSV transaction creation"""
        # This is a basic test that just verifies the transaction structure
        # For full testing, we would need to mock the blockchain API calls
        test_content = b"Test content for transaction"
        encrypted_content, file_hash, file_private_key = self.file_store.encrypt_file(test_content)
        
        try:
            tx = await self.file_store._create_file_transaction(encrypted_content, file_private_key)
            # If no UTXOs are available, this will raise an exception
            if tx:
                self.assertEqual(len(tx.inputs), 1)
                self.assertEqual(len(tx.outputs), 2)  # OP_RETURN + P2PKH
                # Check if transaction has unlocking script (signature)
                self.assertIsNotNone(tx.inputs[0].unlocking_script)
                self.assertIsNotNone(tx.inputs[0].unlocking_script.script)
                self.assertTrue(len(tx.inputs[0].unlocking_script.script) > 0)
        except Exception as e:
            # Skip if no UTXOs available
            if "No UTXOs available" in str(e):
                self.skipTest("No UTXOs available for testing")
            else:
                raise

if __name__ == '__main__':
    unittest.main(verbosity=2) 