<?php
declare(strict_types=1);

function encryptVault(string $plaintext, string $key): string {
    $iv  = random_bytes(12);
    $tag = '';
    $ciphertext = openssl_encrypt($plaintext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag, '', 16);
    if ($ciphertext === false) {
        throw new RuntimeException('Encryption operation failed.');
    }
    return base64_encode($iv . $tag . $ciphertext);
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
