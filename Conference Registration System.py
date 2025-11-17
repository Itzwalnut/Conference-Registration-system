# blockchain_ex1.py
import hashlib
import time
import json
from datetime import datetime
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import uuid
import os
import getpass
import base64

class AttendeeWallet:
    """Secure wallet for storing attendee's private key"""
    def __init__(self, attendee_id, wallet_path="wallets"):
        self.attendee_id = attendee_id
        self.wallet_path = wallet_path
        self.private_key_file = os.path.join(wallet_path, f"{attendee_id}_private_key.pem")
        
        # Create wallet directory if it doesn't exist
        if not os.path.exists(wallet_path):
            os.makedirs(wallet_path)
    
    def save_private_key(self, private_key, password=None):
        """Save private key securely to wallet"""
        try:
            # Serialize private key with encryption if password provided
            if password:
                encryption_algorithm = serialization.BestAvailableEncryption(password.encode())
            else:
                encryption_algorithm = serialization.NoEncryption()
            
            pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=encryption_algorithm
            )
            
            # Set restrictive file permissions (Windows)
            with open(self.private_key_file, 'wb') as f:
                f.write(pem)
            
            # Make file read-only
            os.chmod(self.private_key_file, 0o600)
            
            print(f"✓ Private key saved securely to {self.private_key_file}")
            return True
        except Exception as e:
            print(f"✗ Error saving private key: {e}")
            return False
    
    def load_private_key(self, password=None):
        """Load private key from wallet"""
        try:
            if not os.path.exists(self.private_key_file):
                print(f"✗ Private key file not found: {self.private_key_file}")
                return None
            
            with open(self.private_key_file, 'rb') as f:
                pem_data = f.read()
            
            if password:
                private_key = serialization.load_pem_private_key(
                    pem_data,
                    password=password.encode(),
                    backend=default_backend()
                )
            else:
                private_key = serialization.load_pem_private_key(
                    pem_data,
                    password=None,
                    backend=default_backend()
                )
            
            return private_key
        except Exception as e:
            print(f"✗ Error loading private key: {e}")
            return None

class AttendeeRegistration:
    """Handles attendee registration with key pair generation and blockchain recording"""
    
    def __init__(self, blockchain):
        self.blockchain = blockchain
        self.wallet = None
    
    def generate_keypair(self):
        """Generate RSA public-private key pair"""
        try:
            print("Generating RSA key pair (2048-bit)...")
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            public_key = private_key.public_key()
            print("✓ Key pair generated successfully")
            return private_key, public_key
        except Exception as e:
            print(f"✗ Error generating key pair: {e}")
            return None, None
    
    def export_public_key(self, public_key):
        """Export public key to PEM format for blockchain storage"""
        try:
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            return public_pem.decode('utf-8')
        except Exception as e:
            print(f"✗ Error exporting public key: {e}")
            return None
    
    def register_attendee(self, name, conference_id=None, password=None):
        """
        Complete attendee registration process:
        1. Generate key pair
        2. Create wallet and store private key securely
        3. Register to blockchain with public key
        """
        print("\n" + "="*60)
        print("ATTENDEE REGISTRATION PROCESS")
        print("="*60)
        
        # Step 1: Generate unique attendee ID
        attendee_id = str(uuid.uuid4())[:8].upper()
        print(f"1. Generated Attendee ID: {attendee_id}")
        
        # Step 2: Generate key pair
        private_key, public_key = self.generate_keypair()
        if not private_key:
            return None
        
        # Step 3: Create wallet and save private key
        self.wallet = AttendeeWallet(attendee_id)
        print(f"\n2. Creating wallet for attendee {attendee_id}...")
        
        if not self.wallet.save_private_key(private_key, password):
            return None
        
        # Step 4: Export and register public key to blockchain
        print(f"\n3. Registering to blockchain...")
        public_key_pem = self.export_public_key(public_key)
        
        if conference_id is None:
            conference_id = "CONF2024"
        
        # Create registration transaction
        registration_data = {
            "type": "attendee_registration",
            "attendee_id": attendee_id,
            "name": name,
            "conference_id": conference_id,
            "public_key": public_key_pem,
            "registration_time": datetime.now().isoformat(),
            "status": "registered"
        }
        
        # Add registration transaction to blockchain
        registration_tx = Transaction(
            sender="attendee_system",
            receiver=attendee_id,
            amount=0
        )
        
        # Store registration data in blockchain
        registration_block = Block(
            index=len(self.blockchain.chain),
            timestamp=time.time(),
            data=registration_data,
            previous_hash=self.blockchain.get_latest_block().hash
        )
        
        self.blockchain.add_block(registration_block)
        print(f"   ✓ Registration recorded on blockchain")
        
        # Step 5: Display registration summary
        print("\n" + "="*60)
        print("REGISTRATION SUCCESSFUL")
        print("="*60)
        print(f"Attendee Name:      {name}")
        print(f"Attendee ID:        {attendee_id}")
        print(f"Conference:         {conference_id}")
        print(f"Public Key (Hash):  {hashlib.sha256(public_key_pem.encode()).hexdigest()[:16]}...")
        print(f"Wallet Location:    {self.wallet.private_key_file}")
        print(f"Blockchain Block:   {registration_block.hash[:16]}...")
        print("="*60 + "\n")
        
        return {
            "attendee_id": attendee_id,
            "name": name,
            "conference_id": conference_id,
            "wallet": self.wallet,
            "public_key": public_key,
            "private_key": private_key,
            "blockchain_hash": registration_block.hash
        }

    def sign_attendance(self, attendee_record, session_id, password=None):
        """
        Create an attendance certificate (attendee_id, session_id, timestamp), sign it
        with the attendee's private key, and broadcast the signed certificate as a
        pending transaction to the blockchain network (pending_transactions pool).

        Returns the Transaction object if successful, else None.
        """
        try:
            attendee_id = attendee_record.get('attendee_id')
            wallet = attendee_record.get('wallet')
            if not attendee_id or not wallet:
                print("✗ Invalid attendee record")
                return None

            # Load private key from the attendee's wallet
            private_key = wallet.load_private_key(password=password)
            if private_key is None:
                print("✗ Unable to load private key for signing (wrong password or missing file)")
                return None

            # Build certificate
            cert = {
                'attendee_id': attendee_id,
                'session_id': session_id,
                'timestamp': datetime.now().isoformat()
            }

            # Canonical JSON bytes for signing
            cert_bytes = json.dumps(cert, sort_keys=True).encode('utf-8')

            # Sign using PKCS1v15 + SHA256
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import padding

            signature = private_key.sign(
                cert_bytes,
                padding.PKCS1v15(),
                hashes.SHA256()
            )

            signature_b64 = base64.b64encode(signature).decode('utf-8')

            # Attach public key (PEM) so verifiers can verify signature
            public_key_pem = None
            pk_obj = attendee_record.get('public_key')
            if pk_obj is None:
                public_key_pem = None
            elif isinstance(pk_obj, str):
                public_key_pem = pk_obj
            else:
                # Export the public key object to PEM
                public_key_pem = self.export_public_key(pk_obj)

            # Create transaction data payload
            attendance_payload = {
                'type': 'attendance',
                'certificate': cert,
                'signature': signature_b64,
                'public_key': public_key_pem
            }

            # Create a transaction and broadcast to pending pool
            tx = Transaction(sender=attendee_id, receiver=session_id, amount=0, data=attendance_payload)
            self.blockchain.add_transaction(tx)
            print(f"✓ Attendance certificate signed and broadcast for attendee {attendee_id} (session {session_id})")
            return tx
        except Exception as e:
            print(f"✗ Error signing attendance: {e}")
            return None

    def verify_attendance_signature(self, transaction):
        """
        Verify the digital signature of an attendance record in a transaction.
        Returns True if signature is valid, False otherwise.
        """
        try:
            # Check if transaction has attendance data
            if not transaction.data or transaction.data.get('type') != 'attendance':
                return False

            cert = transaction.data.get('certificate')
            signature_b64 = transaction.data.get('signature')
            public_key_pem = transaction.data.get('public_key')

            if not cert or not signature_b64 or not public_key_pem:
                return False

            # Decode signature from base64
            signature = base64.b64decode(signature_b64)

            # Recreate canonical certificate bytes
            cert_bytes = json.dumps(cert, sort_keys=True).encode('utf-8')

            # Load public key from PEM
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import padding

            public_key = serialization.load_pem_public_key(
                public_key_pem.encode('utf-8'),
                backend=default_backend()
            )

            # Verify signature
            public_key.verify(
                signature,
                cert_bytes,
                padding.PKCS1v15(),
                hashes.SHA256()
            )

            return True
        except Exception as e:
            return False

class Transaction:
    def __init__(self, sender, receiver, amount, data=None):
        # Allow optional data payload for transactions (e.g., attendance certificates)
        payload_str = json.dumps(data, sort_keys=True) if data is not None else ""
        self.id = hashlib.sha256(f"{sender}{receiver}{amount}{payload_str}{time.time()}".encode()).hexdigest()[:8]
        self.timestamp = time.time()
        self.sender = sender
        self.receiver = receiver
        self.amount = amount
        self.data = data
    
    def __str__(self):
        data_summary = f", Data: {type(self.data).__name__}" if self.data is not None else ""
        return f"Transaction[ID: {self.id}, From: {self.sender}, To: {self.receiver}, Amount: {self.amount}{data_summary}]"

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "sender": self.sender,
            "receiver": self.receiver,
            "amount": self.amount,
            "data": self.data
        }

class Block:
    def __init__(self, index, timestamp, data, previous_hash, difficulty=4 , nonce=0):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.difficulty = difficulty
        self.nonce = nonce
        self.hash = self.calculate_hash()
    
    def calculate_hash(self):
        """计算区块的SHA-256哈希值"""
        block_string = json.dumps({ 
            "index": self.index,
            "timestamp": self.timestamp,
            "data": self.data,
            "previous_hash": self.previous_hash,
            "difficulty": self.difficulty,
            "nonce": self.nonce
        }, sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()
    
    def __str__(self):
        return f"Block {self.index} [Hash: {self.hash[:16]}..., Prev: {self.previous_hash[:16]}..., Data: {self.data}]"

class Blockchain:
    def __init__(self):
        self.chain = [self.create_genesis_block()]
    
    def create_genesis_block(self):
        """创建创世区块"""
        return Block(0, time.time(), "Genesis Block", "0")
    
    def get_latest_block(self):
        """获取最新的区块"""
        return self.chain[-1]
    
    def add_block(self, new_block):
        """添加新区块到区块链"""
        # Only set the previous hash if it hasn't been set yet
        if not new_block.previous_hash:
            new_block.previous_hash = self.get_latest_block().hash
            # For POWBlock, we need to mine again after setting previous_hash
            if isinstance(new_block, POWBlock):
                new_block.hash = new_block.mine_block()
            else:
                new_block.hash = new_block.calculate_hash()
        self.chain.append(new_block)
    
    def is_chain_valid(self):
        """验证区块链的完整性"""
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i-1]
            
            # 检查当前区块的哈希是否正确
            if current_block.hash != current_block.calculate_hash():
                print(f"Block {current_block.index} has invalid hash!")
                return False
            
            # 检查区块是否正确地指向之前的区块
            if current_block.previous_hash != previous_block.hash:
                print(f"Block {current_block.index} has invalid previous hash!")
                return False
        
        return True
    
    def display_chain(self):
        """显示整个区块链"""
        print("\n" + "="*50)
        print("BLOCKCHAIN")
        print("="*50)
        for block in self.chain:
            print(block)
        print("="*50)

class POWBlock(Block):
    def __init__(self, index, timestamp, data, previous_hash, difficulty=4, nonce=0):
        super().__init__(index, timestamp, data, previous_hash, difficulty, nonce)
        # 重新计算哈希（包含nonce）
        self.hash = self.mine_block()

    def mine_block(self):
        """工作量证明挖矿过程"""
        print(f"Mining block {self.index} with difficulty {self.difficulty}...")
        start_time = time.time()
        # configurable safety cap to avoid infinite loops; if reached, try decreasing difficulty
        max_nonce = 100_000_000
        progress_every = 1_000_000
        while True:
            self.hash = self.calculate_hash()
            # 检查哈希是否满足难度要求（前n位为0）
            if self.hash[:self.difficulty] == "0" * self.difficulty:
                end_time = time.time()
                mining_time = end_time - start_time
                print(f"Block mined! Hash: {self.hash}, Nonce: {self.nonce}, Time: {mining_time:.2f}s")
                return self.hash
            self.nonce += 1
            # Periodic progress update for long mining runs
            if self.nonce % progress_every == 0:
                elapsed = time.time() - start_time
                print(f"Tried {self.nonce} nonces so far... elapsed {elapsed:.1f}s")
            # If we've tried too many nonces, attempt to lower difficulty and retry (but not below 1)
            if self.nonce > max_nonce:
                print(f"Reached max nonce ({max_nonce}) without success.")
                if self.difficulty > 1:
                    print(f"Lowering diffi555culty from {self.difficulty} to {self.difficulty - 1} and continuing mining.")
                    self.difficulty -= 1
                    self.nonce = 0
                    # continue trying with lower difficulty
                    continue
                # If difficulty is already at minimum, raise an exception since further attempts are futile
                raise Exception("Mining failed: too many iterations at minimum difficulty")

class TransactionBlock(POWBlock):
    def __init__(self, index, timestamp, transactions, previous_hash, difficulty=4, miner_reward=10):
        self.transactions = transactions
        self.miner_reward = miner_reward
        # Convert transactions to JSON-serializable format
        data = [tx.to_dict() for tx in transactions] if isinstance(transactions, list) else transactions
        super().__init__(index, timestamp, data, previous_hash, difficulty)
        
    def adjust_difficulty(self, target_block_time=10, block_sample_size=5):
        """动态调整难度基于最近的挖矿时间"""
        if len(self.chain) <= block_sample_size:
            return
        
        # 计算最近几个区块的平均挖矿时间
        recent_blocks = self.chain[-block_sample_size:]
        total_time = recent_blocks[-1].timestamp - recent_blocks[0].timestamp
        average_time = total_time / (block_sample_size - 1)
        
        print(f"\nAverage mining time for last {block_sample_size} blocks: {average_time:.2f}s")
        
        # 调整难度
        if average_time < target_block_time * 0.8:  # 挖矿太快
            self.difficulty += 1
            print(f"Increasing difficulty to {self.difficulty}")
        elif average_time > target_block_time * 1.2:  # 挖矿太慢
            self.difficulty = max(1, self.difficulty - 1)
            print(f"Decreasing difficulty to {self.difficulty}")
        else:
            print(f"Maintaining current difficulty: {self.difficulty}")

    def is_chain_valid(self):
        """验证区块链的完整性"""
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i-1]
            
            # 检查当前区块的哈希是否正确
            if current_block.hash != current_block.calculate_hash():
                print(f"Block {current_block.index} has invalid hash!")
                return False
            
            # 检查区块是否正确地指向之前的区块
            if current_block.previous_hash != previous_block.hash:
                print(f"Block {current_block.index} has invalid previous hash!")
                return False
        
        return True
 



class TransactionBlockchain(Blockchain):
    def __init__(self, initial_difficulty=4, mining_reward=10):
        self.difficulty = initial_difficulty
        self.mining_reward = mining_reward
        self.pending_transactions = []
        self.chain = [self.create_genesis_block()]

    def create_genesis_block(self):
        """创建创世区块（包含初始交易）"""
        # Create genesis block without mining
        genesis_transaction = Transaction("network", "founder", 1000)  # 初始资金
        genesis_block = Block(0, time.time(), [genesis_transaction.to_dict()], "0", self.difficulty)
        return genesis_block
    
    def add_transaction(self, transaction):
        """添加交易到待处理交易池"""
        # 在实际系统中，这里应该验证签名
        self.pending_transactions.append(transaction)
        print(f"Added transaction to pool: {transaction}")

    def adjust_difficulty(self, target_block_time=10):
        """动态调整难度基于最近的区块时间"""
        if len(self.chain) < 2:
            return
        
        # 获取最近两个区块的时间差
        latest_block = self.chain[-1]
        prev_block = self.chain[-2]
        time_diff = latest_block.timestamp - prev_block.timestamp
        
        print(f"\nBlock mining time: {time_diff:.2f}s")
        
        # 调整难度
        if time_diff < target_block_time * 0.8:  # 挖矿太快
            self.difficulty += 1
            print(f"Increasing difficulty to {self.difficulty}")
        elif time_diff > target_block_time * 1.2:  # 挖矿太慢
            self.difficulty = max(1, self.difficulty - 1)
            print(f"Decreasing difficulty to {self.difficulty}")
        else:
            print(f"Maintaining current difficulty: {self.difficulty}")

    def mine_pending_transactions(self, miner_address):
        """挖矿并打包待处理交易"""
        if not self.pending_transactions:
            print("No pending transactions to mine!")
            return
        print(f"\nMining block with {len(self.pending_transactions)} transactions...")
        print(f"Current mining difficulty: {self.difficulty}")
        latest_block = self.get_latest_block()
        
        # Record start time before mining
        start_time = time.time()
        
        new_block = TransactionBlock(
            index=len(self.chain),
            timestamp=start_time,  # Use mining start time as block timestamp
            transactions=self.pending_transactions,
            previous_hash=latest_block.hash,
            difficulty=self.difficulty,
            miner_reward=self.mining_reward
        )
        
        # Calculate actual mining time
        mining_time = time.time() - start_time
        print(f"\nBlock mining time: {mining_time:.2f}s")
        
        self.chain.append(new_block)
        print(f"Block mined! Miner {miner_address} receives {self.mining_reward} coins reward")
        
        # 清空待处理交易
        self.pending_transactions = []
        
        # 调整难度 using the actual mining time
        if len(self.chain) > 1:
            # Update difficulty based on actual mining time
            if mining_time < 5 * 0.8:  # 挖矿太快
                self.difficulty += 1
                print(f"Increasing difficulty to {self.difficulty}")
            elif mining_time > 5 * 1.2:  # 挖矿太慢
                self.difficulty = max(1, self.difficulty - 1)
                print(f"Decreasing difficulty to {self.difficulty}")
            else:
                print(f"Maintaining current difficulty: {self.difficulty}")

    def mine_valid_blocks(self, miner_address, registration_system):
        """
        Mine a block with signature verification:
        - Verify digital signatures on all pending attendance records
        - Only include transactions with valid signatures in the new block
        - Miners receive rewards for mining valid blocks
        - Return (valid_tx_count, block) if successful, (0, None) if no valid transactions
        """
        if not self.pending_transactions:
            print("No pending transactions to mine!")
            return 0, None

        print(f"\n" + "="*60)
        print(f"MINING BLOCK WITH SIGNATURE VERIFICATION")
        print(f"="*60)
        print(f"Total pending transactions: {len(self.pending_transactions)}")
        print(f"Current mining difficulty: {self.difficulty}")

        # Filter transactions with valid signatures
        valid_transactions = []
        invalid_transactions = []

        for tx in self.pending_transactions:
            if registration_system.verify_attendance_signature(tx):
                valid_transactions.append(tx)
                print(f"✓ Valid signature: TX {tx.id} (from {tx.sender})")
            else:
                invalid_transactions.append(tx)
                print(f"✗ Invalid signature: TX {tx.id} (from {tx.sender})")

        print(f"\nSignature verification result:")
        print(f"  Valid transactions: {len(valid_transactions)}")
        print(f"  Invalid transactions: {len(invalid_transactions)}")

        if not valid_transactions:
            print("✗ No valid transactions to mine!")
            # Remove invalid transactions from pending pool
            self.pending_transactions = invalid_transactions
            return 0, None

        # Create and mine block with only valid transactions
        latest_block = self.get_latest_block()
        start_time = time.time()

        new_block = TransactionBlock(
            index=len(self.chain),
            timestamp=start_time,
            transactions=valid_transactions,
            previous_hash=latest_block.hash,
            difficulty=self.difficulty,
            miner_reward=self.mining_reward
        )

        mining_time = time.time() - start_time
        print(f"\nBlock mined! Mining time: {mining_time:.2f}s")

        # Add miner reward transaction
        reward_tx = Transaction(
            sender="network",
            receiver=miner_address,
            amount=self.mining_reward
        )

        # Add block to chain
        self.chain.append(new_block)
        print(f"✓ Block #{new_block.index} added to blockchain")
        print(f"✓ Miner {miner_address} receives {self.mining_reward} coins as reward")
        print(f"✓ Block Hash: {new_block.hash[:16]}...")

        # Update pending pool with only invalid transactions
        self.pending_transactions = invalid_transactions
        if invalid_transactions:
            print(f"Note: {len(invalid_transactions)} invalid transactions remain in pending pool")

        # Adjust difficulty
        if len(self.chain) > 1:
            if mining_time < 5 * 0.8:
                self.difficulty += 1
                print(f"Increasing difficulty to {self.difficulty}")
            elif mining_time > 5 * 1.2:
                self.difficulty = max(1, self.difficulty - 1)
                print(f"Decreasing difficulty to {self.difficulty}")
            else:
                print(f"Maintaining current difficulty: {self.difficulty}")

        print("="*60)
        return len(valid_transactions), new_block

    def query_sessions_by_attendee(self, attendee_id):
        """
        Query all sessions attended by a specific attendee from the blockchain.
        Returns a list of (session_id, timestamp, block_index) tuples.
        """
        sessions = []
        for block in self.chain[1:]:  # Skip genesis block
            if isinstance(block.data, list):
                for tx_dict in block.data:
                    if isinstance(tx_dict, dict) and tx_dict.get('sender') == attendee_id:
                        if tx_dict.get('data') and tx_dict['data'].get('type') == 'attendance':
                            cert = tx_dict['data'].get('certificate', {})
                            session_id = cert.get('session_id')
                            timestamp = cert.get('timestamp')
                            if session_id:
                                sessions.append({
                                    'session_id': session_id,
                                    'timestamp': timestamp,
                                    'block_index': block.index,
                                    'transaction_id': tx_dict.get('id')
                                })
        return sessions

    def query_attendees_by_session(self, session_id):
        """
        Query all attendees who attended a specific session from the blockchain.
        Returns a list of (attendee_id, timestamp, block_index) tuples.
        """
        attendees = []
        for block in self.chain[1:]:  # Skip genesis block
            if isinstance(block.data, list):
                for tx_dict in block.data:
                    if isinstance(tx_dict, dict) and tx_dict.get('receiver') == session_id:
                        if tx_dict.get('data') and tx_dict['data'].get('type') == 'attendance':
                            cert = tx_dict['data'].get('certificate', {})
                            attendee_id = cert.get('attendee_id')
                            timestamp = cert.get('timestamp')
                            if attendee_id:
                                attendees.append({
                                    'attendee_id': attendee_id,
                                    'timestamp': timestamp,
                                    'block_index': block.index,
                                    'transaction_id': tx_dict.get('id')
                                })
        return attendees

    def query_attendee_registration_status(self, attendee_id):
        """
        Query the registration status of a specific attendee from the blockchain.
        Returns registration details if found, None otherwise.
        """
        for block in self.chain[1:]:  # Skip genesis block
            if isinstance(block.data, dict) and block.data.get('type') == 'attendee_registration':
                if block.data.get('attendee_id') == attendee_id:
                    return {
                        'attendee_id': attendee_id,
                        'name': block.data.get('name'),
                        'conference_id': block.data.get('conference_id'),
                        'registration_time': block.data.get('registration_time'),
                        'status': block.data.get('status'),
                        'block_index': block.index,
                        'block_hash': block.hash,
                        'public_key_hash': hashlib.sha256(block.data.get('public_key', '').encode()).hexdigest()[:16]
                    }
        return None


def main():
    # Create transaction blockchain
    blockchain = TransactionBlockchain()
    
    print("="*60)
    print("CONFERENCE REGISTRATION SYSTEM")
    print("="*60)
    
    # Create registration system
    registration_system = AttendeeRegistration(blockchain)
    registered_attendees = {}
    
    while True:
        print("\n" + "="*60)
        print("MAIN MENU")
        print("="*60)
        print("1. Register new attendee")
        print("2. View all registered attendees")
        print("3. Record session attendance (sign & broadcast)")
        print("4. Mine valid blocks (verify signatures & reward miners)")
        print("5. Verify specific attendee")
        print("6. View blockchain")
        print("7. Organizer queries (sessions, attendees, registration status)")
        print("8. Exit")
        print("="*60)
        
        choice = input("\nEnter your choice (1-8): ").strip()
        
        if choice == "1":
            print("\n--- ATTENDEE REGISTRATION ---")
            name = input("Enter attendee name: ").strip()
            if not name:
                print("✗ Name cannot be empty!")
                continue
            
            conference_id = input("Enter conference ID (default: TECHCONF2024): ").strip()
            if not conference_id:
                conference_id = "TECHCONF2024"
            
            password = input("Enter wallet password (for securing private key): ").strip()
            if not password:
                password = None
            
            # Register attendee
            attendee = registration_system.register_attendee(
                name=name,
                conference_id=conference_id,
                password=password
            )
            
            if attendee:
                registered_attendees[attendee['attendee_id']] = attendee
                print(f"✓ Registration successful!")
        
        elif choice == "2":
            print("\n--- REGISTERED ATTENDEES ---")
            if not registered_attendees:
                print("No attendees registered yet.")
            else:
                print(f"\nTotal registered: {len(registered_attendees)}\n")
                for att_id, att_data in registered_attendees.items():
                    print(f"  ID: {att_id}")
                    print(f"  Name: {att_data['name']}")
                    print(f"  Conference: {att_data['conference_id']}")
                    print(f"  Status: Registered on blockchain")
                    print()
        
        elif choice == "3":
            print("\n--- RECORD SESSION ATTENDANCE ---")
            if not registered_attendees:
                print("No attendees registered yet.")
                continue

            print("\nRegistered attendees:")
            attendee_ids = list(registered_attendees.keys())
            for i, att_id in enumerate(attendee_ids, 1):
                print(f"  {i}. {registered_attendees[att_id]['name']} ({att_id})")

            try:
                choice_idx = int(input("\nSelect attendee number to record attendance: ")) - 1
                if 0 <= choice_idx < len(attendee_ids):
                    att_id = attendee_ids[choice_idx]
                    attendee = registered_attendees[att_id]

                    session_id = input("Enter session ID: ").strip()
                    if not session_id:
                        print("✗ Session ID cannot be empty")
                        continue

                    pwd = input("Enter wallet password to sign attendance: ").strip()
                    pwd = pwd if pwd else None

                    tx = registration_system.sign_attendance(attendee, session_id, password=pwd)
                    if tx:
                        print(f"✓ Attendance recorded and added to pending pool (tx id: {tx.id})")
                        print(f"Pending transactions: {len(blockchain.pending_transactions)}")
                else:
                    print("✗ Invalid selection")
            except ValueError:
                print("✗ Invalid input")
        
        elif choice == "4":
            print("\n--- MINE VALID BLOCKS ---")
            if not blockchain.pending_transactions:
                print("No pending transactions to mine!")
                continue

            miner_address = input("Enter miner address/name: ").strip()
            if not miner_address:
                miner_address = "Miner1"

            valid_count, mined_block = blockchain.mine_valid_blocks(miner_address, registration_system)
            
            if mined_block:
                print(f"\n✓ Successfully mined block with {valid_count} valid transactions")
                print(f"  Block Index: {mined_block.index}")
                print(f"  Block Hash: {mined_block.hash[:16]}...")
            else:
                print(f"\n✗ No valid transactions to include in block")
        
        elif choice == "5":
            print("\n--- VERIFY ATTENDEE ---")
            if not registered_attendees:
                print("No attendees registered yet.")
                continue
            
            print("\nRegistered attendees:")
            attendee_ids = list(registered_attendees.keys())
            for i, att_id in enumerate(attendee_ids, 1):
                print(f"  {i}. {registered_attendees[att_id]['name']} ({att_id})")
            
            try:
                choice_idx = int(input("\nSelect attendee number: ")) - 1
                if 0 <= choice_idx < len(attendee_ids):
                    att_id = attendee_ids[choice_idx]
                    attendee = registered_attendees[att_id]
                    
                    print(f"\n--- Verification for {attendee['name']} ---")
                    print(f"Attendee ID: {attendee['attendee_id']}")
                    print(f"Name: {attendee['name']}")
                    print(f"Conference: {attendee['conference_id']}")
                    print(f"Wallet: {attendee['wallet'].private_key_file}")
                    print(f"Blockchain Hash: {attendee['blockchain_hash'][:16]}...")
                    
                    # Try to load private key
                    pwd = input("Enter wallet password to verify private key: ").strip()
                    loaded_key = attendee['wallet'].load_private_key(password=pwd if pwd else None)
                    if loaded_key:
                        print("✓ Private key successfully verified!")
                    else:
                        print("✗ Failed to load private key (incorrect password or not found)")
                else:
                    print("✗ Invalid selection")
            except ValueError:
                print("✗ Invalid input")
        
        elif choice == "6":
            print("\n--- BLOCKCHAIN VIEW ---")
            blockchain.display_chain()
        
        elif choice == "7":
            print("\n" + "="*60)
            print("ORGANIZER QUERIES")
            print("="*60)
            print("1. Query sessions attended by a specific attendee")
            print("2. Query attendees who attended a specific session")
            print("3. Query registration status of an attendee")
            print("4. Back to main menu")
            print("="*60)
            
            query_choice = input("\nEnter your choice (1-4): ").strip()
            
            if query_choice == "1":
                attendee_id = input("Enter attendee ID: ").strip()
                if not attendee_id:
                    print("✗ Attendee ID cannot be empty")
                    continue
                
                sessions = blockchain.query_sessions_by_attendee(attendee_id)
                if sessions:
                    print(f"\n--- Sessions attended by {attendee_id} ---")
                    print(f"Total sessions: {len(sessions)}\n")
                    for i, session_info in enumerate(sessions, 1):
                        print(f"{i}. Session ID: {session_info['session_id']}")
                        print(f"   Timestamp: {session_info['timestamp']}")
                        print(f"   Block Index: {session_info['block_index']}")
                        print(f"   Transaction ID: {session_info['transaction_id']}\n")
                else:
                    print(f"✗ No session attendance records found for attendee {attendee_id}")
            
            elif query_choice == "2":
                session_id = input("Enter session ID: ").strip()
                if not session_id:
                    print("✗ Session ID cannot be empty")
                    continue
                
                attendees = blockchain.query_attendees_by_session(session_id)
                if attendees:
                    print(f"\n--- Attendees in session {session_id} ---")
                    print(f"Total attendees: {len(attendees)}\n")
                    for i, attendee_info in enumerate(attendees, 1):
                        print(f"{i}. Attendee ID: {attendee_info['attendee_id']}")
                        print(f"   Timestamp: {attendee_info['timestamp']}")
                        print(f"   Block Index: {attendee_info['block_index']}")
                        print(f"   Transaction ID: {attendee_info['transaction_id']}\n")
                else:
                    print(f"✗ No attendance records found for session {session_id}")
            
            elif query_choice == "3":
                attendee_id = input("Enter attendee ID: ").strip()
                if not attendee_id:
                    print("✗ Attendee ID cannot be empty")
                    continue
                
                reg_info = blockchain.query_attendee_registration_status(attendee_id)
                if reg_info:
                    print(f"\n--- Registration Status for {attendee_id} ---")
                    print(f"Name: {reg_info['name']}")
                    print(f"Conference: {reg_info['conference_id']}")
                    print(f"Status: {reg_info['status']}")
                    print(f"Registration Time: {reg_info['registration_time']}")
                    print(f"Block Index: {reg_info['block_index']}")
                    print(f"Block Hash: {reg_info['block_hash'][:16]}...")
                    print(f"Public Key Hash: {reg_info['public_key_hash']}")
                else:
                    print(f"✗ No registration record found for attendee {attendee_id}")
            
            elif query_choice == "4":
                pass  # Return to main menu
            
            else:
                print("✗ Invalid choice")
        
        elif choice == "8":
            print("\n✓ Exiting system...")
            break
        
        else:
            print("✗ Invalid choice! Please enter 1-8")

if __name__ == "__main__":
    main()
