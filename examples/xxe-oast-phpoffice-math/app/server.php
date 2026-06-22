<?php
// Vulnerable phpoffice/math MathML reader.
// POST /import/mathml reaches loadXML().
// OAST proves external subset fetch.
//
// PHP built-in server router.
//   php -S 127.0.0.1:8087 server.php

require __DIR__ . '/vendor/autoload.php';

use PhpOffice\Math\Reader\MathML;

// Hide parser warnings; XXE still fires.
ini_set('display_errors', '0');
error_reporting(0);
libxml_use_internal_errors(true);

$method = $_SERVER['REQUEST_METHOD'];
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

header('Content-Type: application/json');

if ($method === 'POST' && $path === '/import/mathml') {
    $body = file_get_contents('php://input');
    try {
        // External fetch precedes parse failure.
        (new MathML())->read($body);
        echo json_encode(['ok' => true, 'imported' => true]);
    } catch (\Throwable $e) {
        echo json_encode(['ok' => false, 'error' => $e->getMessage()]);
    }
    return true;
}

if ($path === '/') {
    echo json_encode(['service' => 'phpoffice-math MathML import', 'endpoint' => 'POST /import/mathml']);
    return true;
}

http_response_code(404);
echo json_encode(['ok' => false, 'error' => 'not found']);
return true;
