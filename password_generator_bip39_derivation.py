import logging
from typing import Optional
from embit import bip32, bip39

"""
  TLDR;

  pip install embit
  python password_generator_bip39_derivation.py
"""

# Configure logging to provide clear, informative error messages
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)


class PasswordGenerator:
    """
    Deterministic password generator using BIP32 key derivation.

    Provides a secure method to generate reproducible passwords
    based on a BIP39 mnemonic seed and derivation index.
    """

    def __init__(self, mnemonic: str, passphrase: str = ""):
        """
        Initialize the password generator with a seed phrase.

        Args:
            mnemonic (str): BIP39 compatible mnemonic seed phrase
            passphrase (str, optional): Additional security passphrase

        Raises:
            ValueError: If mnemonic validation fails
        """
        # Validate mnemonic before storing
        if not bip39.mnemonic_is_valid(mnemonic):
            raise ValueError("Invalid BIP39 mnemonic phrase")

        # Store mnemonic and passphrase securely
        self._mnemonic = mnemonic
        self._passphrase = passphrase

    def _generate_master_key(self) -> bip32.HDKey:
        """
        Generate the master key from mnemonic and passphrase.

        Returns:
            HDKey: BIP32 hierarchical deterministic master key

        Raises:
            RuntimeError: If seed generation fails
        """
        try:
            # Convert mnemonic to seed using optional passphrase
            seed = bip39.mnemonic_to_seed(self._mnemonic, self._passphrase)

            # Create master key from seed
            return bip32.HDKey.from_seed(seed)

        except Exception as e:
            # Log detailed error for debugging
            logger.error(f"Master key generation failed: {e}")
            raise RuntimeError("Failed to generate master key")

    def generate_password(
        self,
        index: int,
        length: Optional[int] = 32
    ) -> str:
        """
        Generate a deterministic password via BIP32 key derivation.

        Args:
            index (int): Unique derivation index
            length (int, optional): Desired password length. Defaults to 32.

        Returns:
            str: Raw hexadecimal password

        Raises:
            ValueError: For invalid index or length parameters
        """
        # Validate input parameters
        if index < 0:
            raise ValueError("Password index must be non-negative")

        if length < 8 or length > 64:
            raise ValueError(
                "Password length must be between 8 and 64 characters")

        # Generate master key
        master_key = self._generate_master_key()

        # Define BIP85-style derivation path with hardened indices
        path = f"m/83696968'/39'/0'/{index}'"

        try:
            # Derive specific key using the path
            derived_key = master_key.derive(path)

            # Extract and serialize private key as entropy source
            entropy = derived_key.key.serialize()

            # Convert to hexadecimal and truncate to desired length
            return entropy.hex()[:length]

        except Exception as e:
            # Log and re-raise any derivation errors
            logger.error(f"Password generation failed: {e}")
            raise RuntimeError("Failed to generate deterministic password")


def main():
    """
    Demonstrate password generation with error handling.
    Provides a safe example of using the PasswordGenerator.
    """
    # Test mnemonic
    mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

    # Configuration parameters
    # index (int): Unique index for password generation: start in 0
    # length (int, optional): Desired password length (default: 32 characters)
    # passphrase (str, optional): Additional security passphrase (default: empty)
    index, length = 0, 21
    passphrase = ""

    try:
        # Initialize password generator
        pwd_gen = PasswordGenerator(mnemonic, passphrase)

        # Generate password
        password = pwd_gen.generate_password(index, length)

        # Display generation details
        print("<< Deterministic Password Generated >>")
        print(f"Index: {index} Password: {password}")

    except (ValueError, RuntimeError) as e:
        # Graceful error handling and logging
        logger.error(f"Password generation error: {e}")


if __name__ == "__main__":
    main()
