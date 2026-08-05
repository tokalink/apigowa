<?php

// 1. Generate MP3 (Menggunakan Google Translate TTS Bahasa Indonesia, suara wanita)
$text = "  Halo Mas, Apa Kabar bisa kita ketemu nanti malam ?";
$url_encode = urlencode($text);
$tts_url = "https://translate.google.com/translate_tts?ie=UTF-8&client=tw-ob&tl=id&q={$url_encode}";
$mp3_file = __DIR__ . '/otp.mp3';

echo "Mengunduh audio TTS...\n";
$audio = file_get_contents($tts_url);
if ($audio !== false) {
    file_put_contents($mp3_file, $audio);
    echo "Berhasil membuat file: {$mp3_file}\n\n";
} else {
    die("Gagal mengunduh audio TTS\n");
}

// 2. Hit API Outbound Call apiwago
$url = 'http://localhost:7900/api/call';

$data = [
    "token" => "111", // Sesuaikan dengan token pengirim
    "to" => "6285232843165", // Ganti dengan nomor tujuan
    "call_audio_file" => $mp3_file // Menggunakan absolute path
];

$apiKey = 'your-api-key-here'; // Sesuaikan dengan APIKEY di .env

$ch = curl_init($url);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_HTTPHEADER, [
    'Content-Type: application/json',
    'apikey: ' . $apiKey
]);
curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));

echo "Mengirim request panggilan keluar ke {$url}...\n";
echo "Data: " . json_encode($data) . "\n\n";

$response = curl_exec($ch);
if (curl_errno($ch)) {
    echo "Error: " . curl_error($ch) . "\n";
} else {
    echo "Response:\n";
    $decoded = json_decode($response, true);
    if ($decoded) {
        echo json_encode($decoded, JSON_PRETTY_PRINT) . "\n";
    } else {
        echo $response . "\n";
    }
}
curl_close($ch);

