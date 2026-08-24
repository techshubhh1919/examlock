import os
import base64
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

class CryptoEngine:
    def __init__(self):
        # Generate Authority RSA Key Pair for Digital Signatures
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()

    def generate_aes_key(self) -> bytes:
        """Generates a 256-bit AES key."""
        return AESGCM.generate_key(bit_length=256)

    def encrypt_paper(self, plaintext: str, key: bytes) -> dict:
        """Encrypts question paper using AES-256-GCM."""
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)  # 96-bit nonce
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
        
        return {
            "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
            "nonce": base64.b64encode(nonce).decode('utf-8')
        }

    def decrypt_paper(self, ciphertext_b64: str, nonce_b64: str, key: bytes) -> str:
        """Decrypts question paper using AES-256-GCM."""
        aesgcm = AESGCM(key)
        ciphertext = base64.b64decode(ciphertext_b64)
        nonce = base64.b64decode(nonce_b64)
        decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        return decrypted_bytes.decode('utf-8')

    def sign_data(self, data: str) -> str:
        """Signs payload using Authority RSA Private Key."""
        signature = self.private_key.sign(
            data.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode('utf-8')

    def verify_signature(self, data: str, signature_b64: str) -> bool:
        """Verifies payload signature against RSA Public Key."""
        try:
            signature = base64.b64decode(signature_b64)
            self.public_key.verify(
                signature,
                data.encode('utf-8'),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False

    @staticmethod
    def calculate_sha256(data: str) -> str:
        """Calculates SHA-256 hash."""
        return hashlib.sha256(data.encode('utf-8')).hexdigest()

crypto_service = CryptoEngine()