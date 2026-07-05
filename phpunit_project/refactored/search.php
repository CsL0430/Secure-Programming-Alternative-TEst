<?php
declare(strict_types=1);
require_once 'db_config.php'; // returns a mysqli connection using a least-privilege app account
 
if (!isset($_GET['keyword']) || trim($_GET['keyword']) === '') {
    http_response_code(400);
    echo 'Missing or empty search parameter.';
    exit;
}
 
$keyword = trim($_GET['keyword']);
 
// Defensive length boundary (character-length, not byte-length — see Chapter 2.2.1)
if (mb_strlen($keyword, 'UTF-8') > 100) {
    http_response_code(400);
    echo 'Search term is too long.';
    exit;
}
 
try {
    // FIX (Flaw A): parameterised query — data and command are transmitted
    // on separate channels; no attacker-controlled string is ever re-parsed as SQL.
    $stmt = $conn->prepare(
        'SELECT id, name, illness_history FROM patient_records WHERE name LIKE CONCAT("%", ?, "%")'
    );
    $stmt->bind_param('s', $keyword);
    $stmt->execute();
    $result = $stmt->get_result();
 
    // FIX (Flaws B & C): every value that crosses into the HTML response is
    // passed through htmlspecialchars() at the point of output — including
    // the zero-results branch that the original code left unencoded.
    $safeKeyword = htmlspecialchars($keyword, ENT_QUOTES, 'UTF-8');
if ($result->num_rows > 0) {
        echo '<div>Result found for keyword: ' . $safeKeyword . '</div><br>';
        while ($row = $result->fetch_assoc()) {
            $safeName    = htmlspecialchars($row['name'], ENT_QUOTES, 'UTF-8');
            $safeHistory = htmlspecialchars($row['illness_history'], ENT_QUOTES, 'UTF-8');
            echo '<div>Patient: ' . $safeName . ' | History: ' . $safeHistory . '</div><hr>';
        }
    } else {
        echo 'No records found for: ' . $safeKeyword;
    }
    $stmt->close();
} catch (\mysqli_sql_exception $e) {
    error_log('search.php DB error: ' . $e->getMessage());
    http_response_code(500);
    echo 'An internal error occurred. Please try again later.';
}
?>