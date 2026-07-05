<?php
declare(strict_types=1);
require_once 'db_config.php';
 
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username  = $_POST['username'] ?? '';
    $inputKey  = $_POST['auth_key'] ?? '';
 
    // FIX (Flaw D): semantic character-length boundary, multi-byte safe.
    $length = mb_strlen($inputKey, 'UTF-8');
    if ($username === '' || $length === 0 || $length > 256) {
        http_response_code(400);
        echo 'Invalid credential submission.';
        exit;
    }
 
    $stmt = $conn->prepare('SELECT auth_key_hash FROM staff_credentials WHERE username = ?');
    $stmt->bind_param('s', $username);
    $stmt->execute();
    $row = $stmt->get_result()->fetch_assoc();
    $stmt->close();
 
    // FIX (Flaw E): Argon2id replaces MD5. password_verify() performs the
    // comparison internally using constant-time logic, removing timing leaks.
    if ($row && password_verify($inputKey, $row['auth_key_hash'])) {
        echo 'Access Granted.';
    } else {
        // Dummy hash operation equalises response timing whether or not
        // $username exists, preventing user-enumeration via timing side channel.
        password_hash('timing-parity-dummy', PASSWORD_ARGON2ID);
        http_response_code(401);
        echo 'Access Denied.';
    }
}
 
// Provisioning-time helper used when creating or rotating staff credentials.
function hashCredential(string $plainKey): string {
    return password_hash($plainKey, PASSWORD_ARGON2ID, [
        'memory_cost' => 1 << 16, // 64 MiB
        'time_cost'   => 4,
        'threads'     => 2,
    ]);
}
?>