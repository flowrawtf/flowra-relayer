No keys are kept in this repository. Generate your own and keep them outside the repo:

  solana-keygen new --no-bip39-passphrase -o /path/to/relayer-identity.json
  openssl genrsa -traditional -out /path/to/relayer-signing.pem 2048
  openssl rsa -in /path/to/relayer-signing.pem -pubout -out /path/to/relayer-verifying.pem

For docker-compose, place the two PEM files in config/keys/ (ignored by git).
