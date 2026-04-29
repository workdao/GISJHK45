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

// ========== ЗАЩИТА ОТ SSRF (ПРОВЕРКА НА ПРИВАТНЫЕ IP) ===========
$ip = gethostbyname($host);
if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
    http_response_code(403);
    echo json_encode(['error' => 'Access denied: private or reserved IP address']);
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

// ========== ОГРАНИЧЕНИЕ РАЗМЕРА ТЕЛА ЗАПРОСА (1MB) ===========
$contentLength = isset($_SERVER['CONTENT_LENGTH']) ? (int)$_SERVER['CONTENT_LENGTH'] : 0;
if ($contentLength > 1048576) { // 1MB = 1048576 bytes
    http_response_code(413);
    echo json_encode(['error' => 'Request body too large']);
    exit;
}

$body = file_get_contents('php://input');

// ========== НАСТРОЙКА КОНТЕКСТА С ТАЙМАУТОМ ===========
$options = [
    'http' => [
        'method' => $method,
        'header' => "Content-Type: application/json\r\n",
        'content' => $body,
        'ignore_errors' => true,
        'timeout' => 30 // 30 секунд таймаут
    ]
];

$context = stream_context_create($options);
$response = file_get_contents($url, false, $context);

if ($response === false) {
    http_response_code(502);
    echo json_encode(['error' => 'Failed to fetch remote resource']);
    exit;
}

// Прокидываем только безопасные заголовки ответа
if (isset($http_response_header)) {
    $safeHeaders = ['Content-Type', 'Content-Length', 'Cache-Control', 'ETag', 'Last-Modified'];
    foreach ($http_response_header as $header) {
        if (strpos($header, 'HTTP/') === 0) {
            header($header);
        } else {
            foreach ($safeHeaders as $safeHeader) {
                if (stripos($header, $safeHeader . ':') === 0) {
                    header($header);
                    break;
                }
            }
        }
    }
}

echo $response;
?>