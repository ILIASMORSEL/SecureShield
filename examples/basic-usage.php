<?php

require_once '../src/SecureShield.php';

use SecureShield\SecureShield;

$db = new PDO('mysql:host=localhost;dbname=test', 'root', 'password');
$config = [
    'csrf_token_lifetime' => 3600,
    'allowed_redirect_hosts' => ['trusted.com', 'example.com'],
];

$shield = SecureShield::init($db, $config);

$query = "SELECT * FROM users WHERE username = :username";
$params = ['username' => 'admin'];
$result = $shield->dbQuery($query, $params)->fetchAll();

print_r($result);
