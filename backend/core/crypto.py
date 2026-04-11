import os
import hashlib
import logging
from cryptography.fernet import Fernet
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

class CryptoManager:
    def __init__(self):
        # AES-256 (Fernet) setup for Data-at-Rest
        key = os.environ.get("ENCRYPTION_KEY")
        if not key:
            # Dynamically generate fallback key if none provided (Note: in production this should be strictly pulled from secret manager)
            key = Fernet.generate_key().decode('utf-8')
            logger.warning("No ENCRYPTION_KEY found in .env! Generated ephemeral key for session. Data written with this key will not be readable upon restart.")
            
        try:
            self._fernet = Fernet(key.encode('utf-8'))
        except Exception as e:
            logger.error(f"Failed to initialize AES Cipher. Invalid ENCRYPTION_KEY format: {e}")
            raise
            
    def encrypt_text(self, plaintext: str) -> str:
        """Encrypts strings using AES-256 (Fernet) to prevent Database breaches from exposing AI prompts."""
        if not plaintext:
            return plaintext
        return self._fernet.encrypt(plaintext.encode('utf-8')).decode('utf-8')

    def decrypt_text(self, ciphertext: str) -> str:
        """Decrypts AES-256 (Fernet) encrypted strings back to plaintext."""
        if not ciphertext:
            return ciphertext
        try:
            return self._fernet.decrypt(ciphertext.encode('utf-8')).decode('utf-8')
        except Exception:
            return "[DECRYPTION FAILED - INVALID KEY]"

    @staticmethod
    def hash_api_key(api_key: str) -> str:
        """One-way hashes an agent's API key using SHA-256 to prevent plain-text token exposure in DB."""
        if not api_key:
            return ""
        return hashlib.sha256(api_key.encode('utf-8')).hexdigest()

crypto_manager = CryptoManager()
