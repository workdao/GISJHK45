<?php
// Убираем CORS-заголовки для безопасности (будем вызывать с того же домена)

// ========== ВАЛИДАЦИЯ ДОМЕНА ===========
$allowedDomain = 'gosuslugi.ru';
$url = isset($_GET['url']) ? $_GET['url'] : '';

if (empty($url)) {
    http_response_code(400);
    echo json_encode(['error' => 'URL parameter is required']);
    exit;
}

$parsedUrl = parse_url($url);
if (!$parsedUrl || !isset($parsedUrl['host'])) {
    http_response_code(400);
    echo json_encode(['error' => 'Invalid URL format']);
    exit;
}

$host = strtolower($parsedUrl['host']);
// Проверяем что домен заканчивается на .gosuslugi.ru или точно gosuslugi.ru
if ($host !== $allowedDomain && !str_ends_with($host, '.' . $allowedDomain)) {
    http_response_code(403);
    echo json_encode(['error' => 'Access denied: domain not allowed']);
    exit;
}

// ========== ОГРАНИЧЕНИЕ МЕТОДОВ ===========
$method = $_SERVER['REQUEST_METHOD'];
$allowedMethods = ['GET', 'POST'];
if (!in_array($method, $allowedMethods)) {
    http_response_code(405);
    echo json_encode(['error' => 'Method not allowed']);
    exit;
}

$body = file_get_contents('php://input');

$options = [
    'http' => [
        'method' => $method,
        'header' => "Content-Type: application/json\r\n",
        'content' => $body,
        'ignore_errors' => true
    ]
];

$context = stream_context_create($options);
$response = file_get_contents($url, false, $context);

// Прокидываем статус ответа
if (isset($http_response_header)) {
    foreach ($http_response_header as $header) {
        if (strpos($header, 'HTTP/') === 0) {
            header($header);
        }
    }
}

echo $response;
?>