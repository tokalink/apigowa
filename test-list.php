<?php

$url = 'http://localhost:7900/api/send-list';

$data = [
    "token" => "111", // Sesuaikan token
    "phone" => "085232843165",
    "options" => [
        "title" => "Menu Layanan Axera",
        "text" => "Silakan pilih layanan yang Anda butuhkan dari menu di bawah ini:",
        "footer" => "Pusat Bantuan Tokalink",
        "buttonText" => "Lihat Menu",
        "sections" => [
            [
                "title" => "Layanan Cloud",
                "rows" => [
                    [
                        "id" => "menu_api",
                        "title" => "API WhatsApp",
                        "description" => "Layanan gateway API WhatsApp untuk notifikasi"
                    ],
                    [
                        "id" => "menu_bot",
                        "title" => "Chatbot Custom",
                        "description" => "Pembuatan Chatbot AI atau statis"
                    ]
                ]
            ],
            [
                "title" => "Layanan Lainnya",
                "rows" => [
                    [
                        "id" => "menu_cs",
                        "title" => "Hubungi CS",
                        "description" => "Berbicara dengan tim dukungan kami"
                    ]
                ]
            ]
        ]
    ]
];

$apiKey = 'your-api-key-here'; // Sesuaikan APIKEY .env

$ch = curl_init($url);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_HTTPHEADER, [
    'Content-Type: application/json',
    'apikey: ' . $apiKey
]);
curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));

echo "Mengirim List Message (Select Menu)...\n";
$response = curl_exec($ch);
curl_close($ch);

echo json_encode(json_decode($response), JSON_PRETTY_PRINT) . "\n";
