<?php
declare(strict_types=1);
require_once __DIR__ . '/vendor/autoload.php';
use Dotenv\Dotenv;
 
Dotenv::createImmutable(__DIR__)->load(); // loads VAULT_MASTER_KEY from .env
 
function getVaultKey(): string {
    $key = base64_decode($_ENV['VAULT_MASTER_KEY'] ?? '', true);
    if ($key === false || strlen($key) !== 32) {
        throw new RuntimeException('Vault key misconfiguration: expected 32-byte AES-256 key.');
    }
    return $key;
}
 
function encryptVault(string $plaintext, string $key): string {
    $iv  = random_bytes(12);           // fresh 96-bit IV per call (NIST SP 800-38D)
    $tag = '';
    $ciphertext = openssl_encrypt($plaintext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag, '', 16);
    if ($ciphertext === false) {
        throw new RuntimeException('Encryption operation failed.');
    }
    return base64_encode($iv . $tag . $ciphertext); // IV(12) || TAG(16) || CIPHERTEXT
}
 
function decryptVault(string $envelopeB64, string $key): string {
    $raw = base64_decode($envelopeB64, true);
    if ($raw === false || strlen($raw) < 28) {
        throw new RuntimeException('Malformed cryptographic envelope.');
    }
    $iv         = substr($raw, 0, 12);
    $tag        = substr($raw, 12, 16);
    $ciphertext = substr($raw, 28);
 
    $plaintext = openssl_decrypt($ciphertext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
    if ($plaintext === false) {
        throw new RuntimeException('Authentication tag verification failed: payload rejected.');
    }
    return $plaintext;
}
 
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        $key = getVaultKey();
        $envelope = encryptVault($_POST['payload'] ?? '', $key);
        echo json_encode(['status' => 'vaulted', 'data' => $envelope]);
    } catch (\RuntimeException $e) {
        error_log('crypto_vault.php: ' . $e->getMessage());
        http_response_code(500);
        echo json_encode(['status' => 'error', 'message' => 'Cryptographic operation failed.']);
    }
}
?>