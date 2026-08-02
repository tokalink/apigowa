<?php

$url = 'http://localhost:7900/api/send-button';

$data = [
    "token" => "111", // Sesuai dengan token yang baru saja login di log terminal
    "phone" => "6285649073770",
    "options" => [
        "title" => "Axera API Cloud",
        "text" => "Halo! Ini adalah uji coba template Interactive Buttons",
        "footer" => "Support By Axera",
        "buttons" => [
            [
                "id" => "btn-1",
                "text" => "Setuju",
                "type" => "reply"
            ],
            [
                "id" => "btn-2",
                "text" => "Buka Axera",
                "type" => "cta_url",
                "url" => "https://app.axera.id/"
            ],
            [
                "id" => "btn-3",
                "text" => "Copy OTP",
                "type" => "cta_copy",
                "copy_code" => "12345"
            ]
        ]
    ]
];

$apiKey = 'your-api-key-here'; // Sesuaikan dengan nilai APIKEY di file .env kamu

$ch = curl_init($url);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_HTTPHEADER, [
    'Content-Type: application/json',
    'apikey: ' . $apiKey
]);
curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));

echo "Mengirim request ke {$url}...\n\n";

$response = curl_exec($ch);
if (curl_errno($ch)) {
    echo "Error: " . curl_error($ch) . "\n";
} else {
    echo "Response:\n";
    // Tampilkan response dengan rapi
    $decoded = json_decode($response, true);
    if ($decoded) {
        echo json_encode($decoded, JSON_PRETTY_PRINT) . "\n";
    } else {
        echo $response . "\n";
    }
}
curl_close($ch);
