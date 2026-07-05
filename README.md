# CryptoVault PHPUnit Project (Question 5 live demo)

## Setup (run once, on your own machine, before recording)
```bash
composer install
```

## Run the live test suite (this is the command to run ON CAMERA)
```bash
./vendor/bin/phpunit --testdox tests/CryptoVaultTest.php
```

Expected output (verified against real PHP 8.3 + OpenSSL in a sandbox — see chat):
```
PHPUnit 10.5.x by Sebastian Bergmann and contributors.

Crypto Vault
 ✔ Encrypt decrypt round trip succeeds
 ✔ Tampered ciphertext throws authentication exception
 ✔ Credential hash integrity matches

OK (3 tests, 4 assertions)
```
