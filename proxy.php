<?php
// Убираем CORS-заголовки для безопасности (будем вызывать с того же домена)
$url = $_GET['url'];
$method = $_SERVER['REQUEST_METHOD'];
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