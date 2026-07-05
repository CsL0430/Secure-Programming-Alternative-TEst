<?php
declare(strict_types=1);

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../src/CryptoVault.php';

final class CryptoVaultTest extends TestCase
{
    private string $key;

    protected function setUp(): void
    {
        $this->key = random_bytes(32); // ephemeral 256-bit test key
    }

    /** State 1: untampered cryptographic lifecycle */
    public function testEncryptDecryptRoundTripSucceeds(): void
    {
        $plaintext = 'DIAGNOSIS: Stage-2 Carcinoma.';
        $envelope  = encryptVault($plaintext, $this->key);
        $decrypted = decryptVault($envelope, $this->key);
        $this->assertSame($plaintext, $decrypted);
    }

    /** State 2: tampered ciphertext must throw an AEAD authentication exception */
    public function testTamperedCiphertextThrowsAuthenticationException(): void
    {
        $envelope = encryptVault('DIAGNOSIS: Acute Type-2 Diabetes.', $this->key);
        $raw = base64_decode($envelope, true);
        $raw[28] = chr(ord($raw[28]) ^ 0xFF); // flip one ciphertext byte
        $tampered = base64_encode($raw);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Authentication tag verification failed');
        decryptVault($tampered, $this->key);
    }

    /** State 3: credential hash integrity (Argon2id) */
    public function testCredentialHashIntegrityMatches(): void
    {
        $plainKey = 'S3cur3-Clinician-Key!';
        $hash = password_hash($plainKey, PASSWORD_ARGON2ID);
        $this->assertTrue(password_verify($plainKey, $hash));
        $this->assertFalse(password_verify('wrong-key', $hash));
    }
}
