# How Tessera protects your data

## The master password never becomes a key directly
Argon2id is a password hashing function: it takes the master password together with a random salt and derives a key from them. It is deliberately slow, and it deliberately consumes 64 MiB of memory per attempt. The memory cost is the important part — an attacker cannot run thousands of guesses in parallel on a GPU, because each one would need its own 64 MiB.

## Two keys, not one
The KEK is derived from the master password, and its only job is to encrypt the DEK. The DEK is a single random key shared by every entry in the vault, and it never changes. This is why changing the master password only rewrites the wrapped DEK, instead of re-encrypting every entry.

## There is no password check
No password hash and no password is stored anywhere. Instead, the KEK is derived from the entered password and used to unwrap the DEK. If the unwrap succeeds, the password was correct; if it fails, it was not. Using the key *is* the check.

## The same password twice looks different
The nonce is a 24-byte random number, generated fresh for every encryption. The same plaintext encrypted twice produces two completely different ciphertexts, so an observer cannot tell that two entries hold the same password. The nonce is stored in the clear next to the ciphertext, because it is needed for decryption and is not itself a secret.

## Entries cannot be swapped
Encryption alone proves that a record is intact and was produced with the right key — but not that it belongs where it was found. An attacker with write access to the sync storage could therefore swap two entries' encrypted records without breaking anything: both are genuine, and both would decrypt successfully. Your bank entry would silently hand out a forum password.

The AAD prevents this. Each record is bound to its own identity — vault ID, entry ID and format version — and that binding is covered by the authentication tag. If a record turns up under a different identity, decryption fails instead of quietly returning the wrong secret.