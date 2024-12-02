from binascii import hexlify
from embit import bip39, bip32
from embit.networks import NETWORKS
from typing import Optional, List

"""
TLDR:
    pip install embit
    python fingerprint_calculator_bit39_en.py
"""


# Function to generate a fingerprint from a mnemonic seed
def generate_fingerprint(
    mnemonic: str,
    password: Optional[str] = "",
    wordlist: List[str] = bip39.WORDLIST
) -> str:
    """
    Generates the fingerprint of a BIP32 seed from a mnemonic phrase.

    Args:
        mnemonic (str): The mnemonic words separated by spaces.
        password (str, optional): Optional additional passphrase for security.
        wordlist (List[str], optional): Custom BIP39 wordlist (default is English).

    Returns:
        str: Seed fingerprint in hexadecimal format.

    Raises:
        ValueError: If the mnemonic is invalid.
    """
    # Generate seed bytes with secure handling
    try:
        seed_bytes = bip39.mnemonic_to_seed(
            mnemonic=mnemonic,
            password=password,
            wordlist=wordlist
        )
    except Exception as e:
        raise ValueError(f"Error generating seed bytes: {e}")

    # Create root key using the main network (Bitcoin)
    try:
        root = bip32.HDKey.from_seed(
            seed_bytes,
            version=NETWORKS["main"]["xprv"]  # Use mainnet version for xprv
        )
    except Exception as e:
        raise ValueError(f"Error creating root key: {e}")

    # Derive the fingerprint from the first child key (depth 0)
    # Return fingerprint as hexadecimal (8 characters)
    return hexlify(root.child(0).fingerprint).decode('utf-8')


def main():
    mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    passphrase = ""

    try:
        fingerprint_result = generate_fingerprint(mnemonic, passphrase)
        print(f"Mnemonic: {mnemonic}")
        print(f"Fingerprint: {fingerprint_result}")
    except ValueError as e:
        print(e)


if __name__ == "__main__":
    main()

# >> Mnemonic: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
# >> Fingerprint: 73c5da0a
