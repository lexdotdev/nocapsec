<?php
// Thin HTTP harness around the REAL vulnerable phpoffice/math 0.2.0 MathML reader.
// POST /import/mathml with a MathML XML body -> the body is handed verbatim to
// PhpOffice\Math\Reader\MathML::read(), which calls
// DOMDocument::loadXML($content, LIBXML_DTDLOAD) (src/Math/Reader/MathML.php:38).
// LIBXML_DTDLOAD loads the external DTD subset, so a DOCTYPE with an http(s)://
// SYSTEM URL is fetched out-of-band -- classic XXE (CVE-2025-48882).
//
// Run with the PHP built-in server using this file as the router:
//   php -S 127.0.0.1:8087 server.php

require __DIR__ . '/vendor/autoload.php';

use PhpOffice\Math\Reader\MathML;

// Keep libxml's "external subset content error" warnings out of the response
// body; the external-entity fetch (the XXE) still fires regardless.
ini_set('display_errors', '0');
error_reporting(0);
libxml_use_internal_errors(true);

$method = $_SERVER['REQUEST_METHOD'];
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

header('Content-Type: application/json');

if ($method === 'POST' && $path === '/import/mathml') {
    $body = file_get_contents('php://input');
    try {
        // The XXE fires inside read() at loadXML(); parsing the result into the
        // Math model may still fail on a non-MathML payload, which is fine --
        // the external entity has already been fetched by then.
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
