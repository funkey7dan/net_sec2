# Merkle Tree + RSA Encryption
This is a Python implementation of a Merkle Tree and RSA encryption.

The Merkle Tree implementation includes functions for adding a new leaf to the tree, calculating the root of the tree, providing proof of inclusion for a specific leaf, and checking a given proof of inclusion. The tree is built by recursively concatenating the SHA256 hashes of the left and right nodes and creating a new node with the resulting hash.

The RSA encryption implementation includes functions for generating a RSA key pair (public and private key), creating a special signature using the private key, and verifying the signature using the public key. The RSA encryption uses the cryptography library for the implementation of RSA encryption, and the key pair is serialized to be written to files.

The implementation also includes helper functions for hashing strings using SHA256 and for parsing user input to obtain keys.
