<?php

require_once '../src/SecureShield.php';

use SecureShield\SecureShield;

$db = new PDO('mysql:host=localhost;dbname=test', 'root', 'password');
$config = [
    'csrf_token_lifetime' => 3600,
    'allowed_redirect_hosts' => ['trusted.com'],
];

$shield = SecureShield::init($db, $config);

// Защита от XSS
$userInput = '<script>alert("XSS!")</script>';
echo "Оригинал: $userInput\n";
echo "Защищённый вывод: " . $shield->escapeHTML($userInput);

// CSRF
$csrfToken = $shield->generateCSRFToken();
echo "<form method='POST'><input type='hidden' name='csrf_token' value='$csrfToken'></form>";
