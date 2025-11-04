"""
Midnight Scavenger Mine Bot - NATIVE RUST OPTIMIZED Version
Uses native Rust library instead of WASM for 10-100x performance improvement
"""

import requests
import time
from datetime import datetime, timezone
import secrets
import json
import os
import sys
import threading
import logging
from multiprocessing import Process, Queue, Manager
from urllib.parse import quote
from pycardano import PaymentSigningKey, PaymentVerificationKey, Address, Network
import cbor2
import random

# Import native Rust library
try:
    import ashmaize_py
    NATIVE_ASHMAIZE = True
    print("✓ Using NATIVE Rust Ashmaize (FAST)")
except ImportError:
    print("❌ Native ashmaize_py not found. Please build it first.")
    print("   cd ~/ashmaize-python && cargo build --release")
    print("   cp target/release/libashmaize_py.so ashmaize_py.so")
    sys.exit(1)

# Developer donation address (5% of challenges)
DEVELOPER_ADDRESS = random.choice(["addr1v8sd2hwjvumewp3t4rtqz5uwejjv504tus5w279m5k6wkccm0j9gp", "addr1vyel9hlqeft4lwl5shgd28ryes3ejluug0lxhhusnvh2dyc0q92kw", "addr1vxl62mccauqktxyg59ehaskjk75na0pd4utrkvkv822ygsqqt28ph", "addr1vxenv7ucst58q9ju52mw9kjudlwelxnf53kd362jgq8qm5q68uh58", "addr1vylmy9xlwk2u5h5zhp2kwdvznrqgsu54vuc5r9fv8usv4dgdp76wm"])
DONATION_RATE = 0.05  # 5% (1 in 20 challenges)

# Cross-platform file locking
try:
    import portalocker
    HAS_PORTALOCKER = True
except ImportError:
    HAS_PORTALOCKER = False
    if os.name == 'nt':
        import msvcrt
    else:
        import fcntl


def lock_file(file_handle):
    """Acquire exclusive lock on file (cross-platform)"""
    if HAS_PORTALOCKER:
        portalocker.lock(file_handle, portalocker.LOCK_EX)
    elif os.name == 'nt':
        msvcrt.locking(file_handle.fileno(), msvcrt.LK_LOCK, 1)
    else:
        fcntl.flock(file_handle.fileno(), fcntl.LOCK_EX)


def unlock_file(file_handle):
    """Release lock on file (cross-platform)"""
    if HAS_PORTALOCKER:
        portalocker.unlock(file_handle)
    elif os.name == 'nt':
        file_handle.seek(0)
        msvcrt.locking(file_handle.fileno(), msvcrt.LK_UNLCK, 1)
    else:
        fcntl.flock(file_handle.fileno(), fcntl.LOCK_UN)


def setup_logging():
    """Setup file and console logging"""
    log_format = '%(asctime)s - %(levelname)s - [%(processName)s] - %(message)s'
    date_format = '%Y-%m-%d %H:%M:%S'

    logger = logging.getLogger('midnight_miner')
    logger.setLevel(logging.INFO)

    if logger.handlers:
        return logger

    file_handler = logging.FileHandler('miner.log')
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(logging.Formatter(log_format, date_format))

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.WARNING)
    console_handler.setFormatter(logging.Formatter(log_format, date_format))

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger


class ChallengeTracker:
    """Manages challenge tracking and completion status with cross-process file locking"""

    def __init__(self, challenges_file="challenges.json"):
        self.challenges_file = challenges_file
        if not os.path.exists(self.challenges_file):
            with open(self.challenges_file, 'w') as f:
                json.dump({}, f)

    def _locked_operation(self, modify_func):
        with open(self.challenges_file, 'r+') as f:
            lock_file(f)
            try:
                f.seek(0)
                content = f.read()
                challenges = json.loads(content) if content else {}

                modified_challenges, result = modify_func(challenges)

                f.seek(0)
                f.truncate()
                json.dump(modified_challenges, f, indent=2)
                f.flush()
                os.fsync(f.fileno())

                return result
            finally:
                unlock_file(f)

    def register_challenge(self, challenge):
        def modify(challenges):
            challenge_id = challenge['challenge_id']
            if challenge_id not in challenges:
                challenges[challenge_id] = {
                    'challenge_id': challenge['challenge_id'],
                    'day': challenge.get('day'),
                    'challenge_number': challenge.get('challenge_number'),
                    'difficulty': challenge['difficulty'],
                    'no_pre_mine': challenge['no_pre_mine'],
                    'no_pre_mine_hour': challenge['no_pre_mine_hour'],
                    'latest_submission': challenge['latest_submission'],
                    'discovered_at': datetime.now(timezone.utc).isoformat(),
                    'solved_by': []
                }
                return (challenges, True)
            return (challenges, False)

        return self._locked_operation(modify)

    def mark_solved(self, challenge_id, wallet_address):
        def modify(challenges):
            if challenge_id in challenges:
                if wallet_address not in challenges[challenge_id]['solved_by']:
                    challenges[challenge_id]['solved_by'].append(wallet_address)
                    return (challenges, True)
            return (challenges, False)

        return self._locked_operation(modify)

    def get_unsolved_challenge(self, wallet_address):
        def find_challenge(challenges):
            now = datetime.now(timezone.utc)
            candidates = []

            for challenge_id, data in challenges.items():
                if wallet_address not in data['solved_by']:
                    deadline = datetime.fromisoformat(data['latest_submission'].replace('Z', '+00:00'))
                    time_left = (deadline - now).total_seconds()
                    if time_left > 0:
                        candidates.append({
                            'challenge': data,
                            'time_left': time_left
                        })

            if not candidates:
                result = None
            else:
                candidates.sort(key=lambda x: x['time_left'], reverse=True)
                result = candidates[0]['challenge']

            return (challenges, result)

        return self._locked_operation(find_challenge)


class WalletManager:
    """Manages Cardano wallet generation, storage, and signing"""

    def __init__(self, wallet_file="wallets.json"):
        self.wallet_file = wallet_file
        self.wallets = []

    def generate_wallet(self, wallet_id):
        signing_key = PaymentSigningKey.generate()
        verification_key = PaymentVerificationKey.from_signing_key(signing_key)
        address = Address(verification_key.hash(), network=Network.MAINNET)
        pubkey = bytes(verification_key.to_primitive()).hex()

        return {
            'id': wallet_id,
            'address': str(address),
            'pubkey': pubkey,
            'signing_key': signing_key.to_primitive().hex(),
            'signature': None,
            'created_at': datetime.now(timezone.utc).isoformat()
        }

    def sign_terms(self, wallet_data, api_base):
        try:
            response = requests.get(f"{api_base}/TandC")
            message = response.json()["message"]
        except:
            message = "I agree to abide by the terms and conditions as described in version 1-0 of the Midnight scavenger mining process: 281ba5f69f4b943e3fb8a20390878a232787a04e4be22177f2472b63df01c200"

        signing_key_bytes = bytes.fromhex(wallet_data['signing_key'])
        signing_key = PaymentSigningKey.from_primitive(signing_key_bytes)
        address = Address.from_primitive(wallet_data['address'])

        address_bytes = bytes(address.to_primitive())

        protected = {1: -8, "address": address_bytes}
        protected_encoded = cbor2.dumps(protected)
        unprotected = {"hashed": False}
        payload = message.encode('utf-8')

        sig_structure = ["Signature1", protected_encoded, b'', payload]
        to_sign = cbor2.dumps(sig_structure)
        signature_bytes = signing_key.sign(to_sign)

        cose_sign1 = [protected_encoded, unprotected, payload, signature_bytes]
        wallet_data['signature'] = cbor2.dumps(cose_sign1).hex()

    def load_or_create_wallets(self, num_wallets, api_base, donation_enabled=True):
        first_time_setup = False
        if os.path.exists(self.wallet_file):
            print(f"✓ Loading wallets from {self.wallet_file}")
            with open(self.wallet_file, 'r') as f:
                self.wallets = json.load(f)

            existing_count = len(self.wallets)
            if existing_count >= num_wallets:
                print(f"✓ Using {num_wallets} existing wallets")
                self.wallets = self.wallets[:num_wallets]
                return self.wallets
            else:
                print(f"✓ Loaded {existing_count} existing wallets")
                print(f"✓ Creating {num_wallets - existing_count} additional wallets...")
                start_id = existing_count
        else:
            print(f"✓ Creating {num_wallets} new wallets...")
            start_id = 0
            first_time_setup = True

            if donation_enabled:
                print()
                print("="*70)
                print("DEVELOPER DONATION INFO")
                print("="*70)
                print("This miner donates 5% (1 in 20) of solved challenges to the")
                print("developer to support ongoing development and maintenance.")
                print()
                print("You can disable donations with the --no-donation flag, but")
                print("donations are greatly appreciated!")
                print("="*70)
                print()

        for i in range(start_id, num_wallets):
            wallet = self.generate_wallet(i)
            self.sign_terms(wallet, api_base)
            self.wallets.append(wallet)
            print(f"  Wallet {i+1}/{num_wallets}: {wallet['address'][:40]}...")

        with open(self.wallet_file, 'w') as f:
            json.dump(self.wallets, f, indent=2)

        print(f"✓ Saved {num_wallets} wallets to {self.wallet_file}")
        return self.wallets


class MinerWorker:
    """Individual mining worker for one wallet - NATIVE RUST OPTIMIZED"""

    def __init__(self, wallet_data, worker_id, status_dict, challenge_tracker, donation_enabled=True, api_base="https://scavenger.prod.gd.midnighttge.io/"):
        self.wallet_data = wallet_data
        self.worker_id = worker_id
        self.address = wallet_data['address']
        self.signature = wallet_data['signature']
        self.pubkey = wallet_data['pubkey']
        self.api_base = api_base
        self.status_dict = status_dict
        self.challenge_tracker = challenge_tracker
        self.donation_enabled = donation_enabled
        self.logger = logging.getLogger('midnight_miner')

        self.short_addr = self.address[:20] + "..."

        # OPTIMIZATION: Pre-generate random bytes buffer
        self.random_buffer = bytearray(8192)
        self.random_buffer_pos = len(self.random_buffer)

        # Initialize status
        self.status_dict[worker_id] = {
            'address': self.address,
            'current_challenge': 'Starting',
            'attempts': 0,
            'hash_rate': 0,
            'completed_challenges': 0,
            'initial_completed_challenges': 0,
            'night_allocation': 0.0,
            'last_update': time.time()
        }

    def get_fast_nonce(self):
        """OPTIMIZED: Get nonce from pre-generated buffer"""
        if self.random_buffer_pos >= len(self.random_buffer):
            self.random_buffer = bytearray(secrets.token_bytes(8192))
            self.random_buffer_pos = 0
        
        nonce_bytes = self.random_buffer[self.random_buffer_pos:self.random_buffer_pos + 8]
        self.random_buffer_pos += 8
        return nonce_bytes.hex()

    def register_wallet(self):
        url = f"{self.api_base}/register/{self.address}/{self.signature}/{self.pubkey}"
        try:
            response = requests.post(url, json={})
            response.raise_for_status()
            self.logger.info(f"Worker {self.worker_id} ({self.short_addr}): Wallet registered successfully")
            return True
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 400:
                error_msg = e.response.json().get('message', '')
                if 'already' in error_msg.lower():
                    self.logger.info(f"Worker {self.worker_id} ({self.short_addr}): Wallet already registered")
                    return True
            self.logger.error(f"Worker {self.worker_id} ({self.short_addr}): Registration failed - {e}")
            return False
        except Exception as e:
            self.logger.error(f"Worker {self.worker_id} ({self.short_addr}): Registration error - {e}")
            return False

    def get_current_challenge(self):
        try:
            response = requests.get(f"{self.api_base}/challenge")
            response.raise_for_status()
            data = response.json()
            if data.get("code") == "active":
                return data["challenge"]
        except:
            pass
        return None

    def get_statistics(self):
        try:
            response = requests.get(f"{self.api_base}/statistics/{self.address}")
            response.raise_for_status()
            return response.json()
        except:
            return None

    def update_statistics(self):
        stats = self.get_statistics()
        if stats:
            local = stats.get('local', {})
            completed = local.get('crypto_receipts', 0)
            night = local.get('night_allocation', 0) / 1000000.0

            current = dict(self.status_dict[self.worker_id])
            if current['initial_completed_challenges'] == 0 and completed > 0:
                current['initial_completed_challenges'] = completed

            current['completed_challenges'] = completed
            current['night_allocation'] = night
            current['last_update'] = time.time()
            self.status_dict[self.worker_id] = current

    def build_preimage_static_part(self, challenge, mining_address=None):
        address = mining_address if mining_address else self.address
        return (
            address + challenge["challenge_id"] +
            challenge["difficulty"] + challenge["no_pre_mine"] +
            challenge["latest_submission"] + challenge["no_pre_mine_hour"]
        )

    def submit_solution(self, challenge, nonce, mining_address=None):
        address = mining_address if mining_address else self.address
        url = f"{self.api_base.rstrip('/')}/solution/{address}/{challenge['challenge_id']}/{nonce}"

        try:
            response = requests.post(url, json={})
            response.raise_for_status()
            data = response.json()
            success = data.get("crypto_receipt") is not None
            if success:
                self.logger.info(f"Worker {self.worker_id} ({self.short_addr}): Solution ACCEPTED for challenge {challenge['challenge_id']}")
            else:
                self.logger.warning(f"Worker {self.worker_id} ({self.short_addr}): Solution REJECTED for challenge {challenge['challenge_id']} - No receipt")

            return (success, True)
        except requests.exceptions.HTTPError as e:
            error_detail = e.response.text
            self.logger.warning(f"Worker {self.worker_id} ({self.short_addr}): Solution REJECTED for challenge {challenge['challenge_id']} - {e.response.status_code}: {error_detail}")
            return (False, True)
        except Exception as e:
            self.logger.warning(f"Worker {self.worker_id} ({self.short_addr}): Solution submission error for challenge {challenge['challenge_id']} - {e}")
            return (False, False)

    def mine_challenge_native(self, challenge, rom, max_time=3600, mining_address=None):
        """NATIVE RUST MINING - 10-100x faster than WASM with batch processing"""
        start_time = time.time()
        attempts = 0
        last_status_update = start_time

        self.update_status(current_challenge=challenge['challenge_id'], attempts=0)

        preimage_static = self.build_preimage_static_part(challenge, mining_address)
        difficulty_value = int(challenge["difficulty"][:8], 16)

        # CRITICAL: Batch size - hash many nonces at once in native Rust
        BATCH_SIZE = 10000  # Process 10k hashes per batch!

        while time.time() - start_time < max_time:
            # Generate batch of nonces
            nonces = [self.get_fast_nonce() for _ in range(BATCH_SIZE)]
            preimages = [nonce + preimage_static for nonce in nonces]

            # Hash entire batch in native Rust (FAST!)
            hashes = rom.hash_batch(preimages)
            attempts += BATCH_SIZE

            # Check all results
            for i, hash_hex in enumerate(hashes):
                hash_value = int(hash_hex[:8], 16)
                if (hash_value | difficulty_value) == difficulty_value:
                    elapsed = time.time() - start_time
                    hash_rate = attempts / elapsed if elapsed > 0 else 0
                    self.update_status(hash_rate=hash_rate)
                    return nonces[i]

            # Update status every 5 seconds
            current_time = time.time()
            if current_time - last_status_update >= 5.0:
                elapsed = current_time - start_time
                hash_rate = attempts / elapsed if elapsed > 0 else 0
                self.update_status(attempts=attempts, hash_rate=hash_rate)
                last_status_update = current_time

        return None

    def update_status(self, **kwargs):
        current = dict(self.status_dict[self.worker_id])
        current.update(kwargs)
        current['last_update'] = time.time()
        self.status_dict[self.worker_id] = current

    def run(self):
        """Main worker loop with NATIVE RUST"""
        self.update_status(current_challenge='Initializing...')
        self.logger.info(f"Worker {self.worker_id} ({self.short_addr}): Starting mining worker (NATIVE RUST)")

        if not self.register_wallet():
            self.update_status(current_challenge='Registration failed')
            return

        self.update_status(current_challenge='Ready (Native Rust)')
        rom_cache = {}
        last_stats_update = 0

        while True:
            try:
                # Update statistics every 10 minutes
                if time.time() - last_stats_update > 600:
                    self.update_statistics()
                    last_stats_update = time.time()

                # Get current challenge from API and register it
                api_challenge = self.get_current_challenge()
                if api_challenge:
                    is_new = self.challenge_tracker.register_challenge(api_challenge)
                    if is_new:
                        self.logger.info(f"Worker {self.worker_id} ({self.short_addr}): Discovered new challenge {api_challenge['challenge_id']}")

                # Find an unsolved challenge for this wallet
                challenge = self.challenge_tracker.get_unsolved_challenge(self.address)

                if not challenge:
                    self.update_status(current_challenge='Waiting...', attempts=0, hash_rate=0)
                    time.sleep(60)
                    continue

                challenge_id = challenge["challenge_id"]

                # Check deadline
                deadline = datetime.fromisoformat(challenge["latest_submission"].replace('Z', '+00:00'))
                time_left = (deadline - datetime.now(timezone.utc)).total_seconds()

                if time_left <= 0:
                    self.challenge_tracker.mark_solved(challenge_id, self.address)
                    self.logger.info(f"Worker {self.worker_id} ({self.short_addr}): Challenge {challenge_id} expired")
                    self.update_status(current_challenge='Expired')
                    time.sleep(5)
                    continue

                # Get or build ROM for this challenge (NATIVE RUST)
                no_pre_mine = challenge["no_pre_mine"]
                if no_pre_mine not in rom_cache:
                    self.update_status(current_challenge=f'Building ROM (native)')
                    self.logger.info(f"Worker {self.worker_id} ({self.short_addr}): Building ROM for challenge {challenge_id}")
                    # Use TwoStep for speed (matches WASM parameters)
                    rom_cache[no_pre_mine] = ashmaize_py.build_rom_twostep(
                        key=no_pre_mine,
                        size=1073741824,
                        pre_size=16777216,
                        mixing_numbers=4
                    )

                rom = rom_cache[no_pre_mine]

                # Determine if this challenge will be mined for developer
                mining_for_developer = False
                if self.donation_enabled and random.random() < DONATION_RATE:
                    mining_for_developer = True
                    mining_address = DEVELOPER_ADDRESS
                    self.update_status(address='developer (thank you!)')
                    self.logger.info(f"Worker {self.worker_id} ({self.short_addr}): Mining challenge {challenge_id} for DEVELOPER (donation)")
                else:
                    mining_address = None
                    self.update_status(address=self.address)

                if not mining_for_developer:
                    self.logger.info(f"Worker {self.worker_id} ({self.short_addr}): Starting work on challenge {challenge_id} (time left: {time_left/3600:.1f}h)")

                # Mine the challenge with NATIVE RUST
                max_mine_time = min(time_left * 0.8, 3600)
                nonce = self.mine_challenge_native(challenge, rom, max_time=max_mine_time, mining_address=mining_address)

                if nonce:
                    if mining_for_developer:
                        self.logger.info(f"Worker {self.worker_id} ({self.short_addr}): Found solution for challenge {challenge_id} (DEVELOPER DONATION), submitting...")
                    else:
                        self.logger.info(f"Worker {self.worker_id} ({self.short_addr}): Found solution for challenge {challenge_id}, submitting...")
                    self.update_status(current_challenge='Submitting solution...')
                    success, should_mark_solved = self.submit_solution(challenge, nonce, mining_address=mining_address)

                    if success:
                        self.challenge_tracker.mark_solved(challenge_id, self.address)
                        self.update_statistics()
                        self.update_status(current_challenge='Solution accepted!')
                        time.sleep(5)
                    elif should_mark_solved:
                        self.challenge_tracker.mark_solved(challenge_id, self.address)
                        self.update_status(current_challenge='Solution rejected - moving on')
                        time.sleep(5)
                    else:
                        self.update_status(current_challenge='Submission error - will retry')
                        time.sleep(30)

                    if mining_for_developer:
                        self.update_status(address=self.address)
                else:
                    self.challenge_tracker.mark_solved(challenge_id, self.address)
                    self.logger.info(f"Worker {self.worker_id} ({self.short_addr}): No solution found for challenge {challenge_id} within time limit")
                    self.update_status(current_challenge='No solution found')

                    if mining_for_developer:
                        self.update_status(address=self.address)

                    time.sleep(5)

            except KeyboardInterrupt:
                self.logger.info(f"Worker {self.worker_id} ({self.short_addr}): Received stop signal")
                break
            except Exception as e:
                self.logger.error(f"Worker {self.worker_id} ({self.short_addr}): Error - {e}")
                self.update_status(current_challenge=f'Error: {str(e)[:30]}')
                time.sleep(60)


def worker_process(wallet_data, worker_id, status_dict, challenges_file, donation_enabled=True):
    """Process entry point for worker"""
    try:
        setup_logging()
        challenge_tracker = ChallengeTracker(challenges_file)
        worker = MinerWorker(wallet_data, worker_id, status_dict, challenge_tracker, donation_enabled=donation_enabled)
        worker.run()
    except Exception as e:
        logger = logging.getLogger('midnight_miner')
        logger.error(f"Worker {worker_id}: Fatal error - {e}")
        import traceback
        traceback.print_exc()

RESET = "\033[0m"
BOLD = "\033[1m"
CYAN = "\033[36m"
GREEN = "\033[32m"


def color_text(text, color):
    return f"{color}{text}{RESET}"

def display_dashboard(status_dict, num_workers, stats_update_interval=600):
    """Display live dashboard"""
    last_stats_update = 0

    while True:
        try:
            time.sleep(5)

            current_time = time.time()
            if current_time - last_stats_update > stats_update_interval:
                last_stats_update = current_time

            os.system('clear' if os.name == 'posix' else 'cls')

            print("="*110)
            print(f"{BOLD}{CYAN}{'MIDNIGHT MINER - NATIVE RUST OPTIMIZED':^110}{RESET}")
            print("="*110)
            print(f"{BOLD}Active Workers: {num_workers} | Last Update: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{RESET}")
            print("="*110)
            print()

            header = f"{'ID':<4} {'Address':<44} {'Challenge':<20} {'Attempts':<10} {'H/s':<8} {'Completed':<10} {'NIGHT':<10}"
            print(color_text(header, CYAN))
            print("-"*110)

            total_hashrate = 0
            total_completed = 0
            total_night = 0
            session_completed = 0

            for worker_id in range(num_workers):
                if worker_id not in status_dict:
                    row = f"{worker_id:<4} {'Starting...':<44} {'N/A':<20} {0:<10} {0:<8} {0:<10} {0:<10}"
                    print(row)
                    continue

                status = status_dict[worker_id]
                address = status.get('address', 'N/A')
                if len(address) > 42:
                    address = address[:39] + "..."

                challenge = status.get('current_challenge')
                if challenge is None:
                    challenge_display = "Waiting"
                elif len(str(challenge)) > 18:
                    challenge_display = str(challenge)[:15] + "..."
                else:
                    challenge_display = str(challenge)

                challenge_display_padded = f"{challenge_display:<20}"

                attempts = status.get('attempts', 0) or 0
                hash_rate = status.get('hash_rate', 0) or 0
                completed = status.get('completed_challenges', 0) or 0
                initial_completed = status.get('initial_completed_challenges', 0) or 0
                night_alloc = status.get('night_allocation', 0) or 0

                delta_completed = completed - initial_completed

                if delta_completed > 0:
                    completed_display = f"{completed} (+{delta_completed})"
                else:
                    completed_display = str(completed)

                night_display = color_text(str(round(night_alloc, 2)), GREEN)

                total_hashrate += hash_rate
                total_completed += completed
                total_night += night_alloc
                session_completed += delta_completed

                print(f"{worker_id:<4} {address:<44} {challenge_display_padded} {attempts:<10,} {hash_rate:<8.0f} {completed_display:<10} {night_display:<10}")

            completed_str = f"{total_completed} (+{session_completed})" if session_completed > 0 else str(total_completed)
            totals_row = f"{'TOTAL':<4} {'':<44} {'':<20} {'':<10} {total_hashrate:<8.0f} {completed_str:<10} {round(total_night, 2):<10}"
            print(color_text("-"*110, CYAN))
            print(color_text(totals_row, CYAN))
            print("="*110)
            print("\nPress Ctrl+C to stop all miners")

        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"Error: {e}")
            time.sleep(5)


def main():
    """Main entry point"""
    logger = setup_logging()

    print("="*70)
    print("MIDNIGHT MINER - NATIVE RUST OPTIMIZED")
    print("="*70)
    print()

    logger.info("="*70)
    logger.info("Midnight Miner starting up (NATIVE RUST VERSION)")
    logger.info("="*70)

    num_workers = 1
    wallets_file = "wallets.json"
    challenges_file = "challenges.json"
    donation_enabled = True

    for i, arg in enumerate(sys.argv):
        if arg == '--workers' and i + 1 < len(sys.argv):
            num_workers = int(sys.argv[i + 1])
        elif arg == '--wallets-file' and i + 1 < len(sys.argv):
            wallets_file = sys.argv[i + 1]
        elif arg == '--challenges-file' and i + 1 < len(sys.argv):
            challenges_file = sys.argv[i + 1]
        elif arg == '--no-donation':
            donation_enabled = False

    if num_workers < 1:
        print("Error: --workers must be at least 1")
        return 1

    print(f"Configuration:")
    print(f"  Workers: {num_workers}")
    print(f"  Wallets file: {wallets_file}")
    print(f"  Challenges file: {challenges_file}")
    print(f"  Developer donations: {'Enabled (5%)' if donation_enabled else 'Disabled'}")
    print(f"  Engine: NATIVE RUST (10-100x faster than WASM)")
    print()

    logger.info(f"Configuration: workers={num_workers}, engine=NATIVE_RUST")

    wallet_manager = WalletManager(wallets_file)
    api_base = "https://scavenger.prod.gd.midnighttge.io/"
    wallets = wallet_manager.load_or_create_wallets(num_workers, api_base, donation_enabled)
    logger.info(f"Loaded/created {num_workers} wallets")

    print()
    print("="*70)
    print("STARTING MINERS")
    print("="*70)
    print()

    manager = Manager()
    status_dict = manager.dict()

    processes = []
    for i, wallet in enumerate(wallets):
        p = Process(target=worker_process, args=(wallet, i, status_dict, challenges_file, donation_enabled))
        p.start()
        processes.append(p)
        logger.info(f"Started worker process {i} for wallet {wallet['address'][:20]}...")
        time.sleep(1)

    print("\n" + "="*70)
    print("All workers started. Starting dashboard...")
    print("="*70)
    logger.info(f"All {num_workers} workers started successfully")

    try:
        display_dashboard(status_dict, num_workers)
    except KeyboardInterrupt:
        print("\n\nStopping all miners...")
        logger.info("Received shutdown signal, stopping all workers...")

    for p in processes:
        p.terminate()

    for p in processes:
        p.join(timeout=5)

    print("\n✓ All miners stopped")
    logger.info("All workers stopped")

    session_total_completed = 0

    for worker_id in range(num_workers):
        if worker_id in status_dict:
            status = status_dict[worker_id]
            completed = status.get('completed_challenges', 0) or 0
            initial_completed = status.get('initial_completed_challenges', 0) or 0

            session_total_completed += (completed - initial_completed)

    print(f"\nSession Statistics:")
    print(f"  New challenges solved: {session_total_completed}")

    logger.info(f"Session statistics: {session_total_completed} new challenges solved")
    logger.info("Midnight Miner shutdown complete")

    return 0


if __name__ == "__main__":
    sys.exit(main())
