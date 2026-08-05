# Dokumentasi Integrasi WebSocket Call Center APIWAGO

Dokumen ini ditujukan untuk **Tim Frontend / Tim AI** yang akan menghubungkan *Dashboard CS* atau *AI Engine* ke dalam fitur panggilan suara WhatsApp di `apiwago`.

## 1. Konsep Arsitektur
`apiwago` mengekspos saluran *streaming* berbasis **WebSocket**.
Setiap koneksi WebSocket bersifat dua arah (*bi-directional*):
- **Terima dari WebSocket (Incoming):** Suara dari penelepon WhatsApp (dikirim dari `apiwago` ke *Frontend*).
- **Kirim ke WebSocket (Outgoing):** Suara CS/AI (dikirim dari *Frontend* ke `apiwago` untuk didengar oleh penelepon).

## 2. Format Data Audio (Wajib Diikuti)
Pion WebRTC (di dalam `apiwago`) hanya menerima dan mengirimkan raw PCM dengan spesifikasi baku berikut:
- **Sample Rate:** `16000 Hz` (16 kHz)
- **Channel:** `Mono` (1 channel)
- **Bit Depth:** `16-bit` (s16le / int16 little endian)

> [!IMPORTANT]
> Pastikan data yang Anda kirimkan lewat WebSocket adalah pesan bertipe **Binary (ArrayBuffer/Blob)** yang berisi PCM 16-bit. Format lain (seperti Float32, MP3, WAV Header) akan menyebabkan audio menjadi rusak (*noise/kresek*).

## 3. Alur Koneksi (Workflow)
1. CS menekan tombol "Call" (untuk memanggil keluar) melalui API: `POST /api/call`.
2. API merespons dengan: `{"status": true, "call_id": "ABC12345"}`
3. Frontend segera membuka koneksi ke:
   `ws://domain-apiwago/api/call/stream?call_id=ABC12345`
4. Mulai kirim dan terima data biner!

*(Berlaku hal yang sama untuk Incoming Call. `apiwago` akan mengeluarkan webhook/event saat ada panggilan masuk dengan membawa `call_id`).*

---

## 4. Contoh Kode Javascript Frontend (Browser)
Di browser, untuk menangkap mikrofon 16kHz dan mengirimnya ke WebSocket, kita menggunakan `AudioContext` dan `ScriptProcessorNode` (atau `AudioWorklet`).

Berikut adalah contoh Script murni (*Vanilla JS*):

```javascript
let ws;
let audioContext;
let mediaStream;

async function connectToCall(callId) {
    // 1. Buka Koneksi WebSocket
    ws = new WebSocket(`ws://localhost:3000/api/call/stream?call_id=${callId}`);
    ws.binaryType = 'arraybuffer'; // Pastikan menerima binary

    ws.onopen = async () => {
        console.log("WebSocket terhubung!");
        await startMicrophoneStream();
    };

    ws.onmessage = (event) => {
        // Menerima Suara Penelepon WhatsApp dari apiwago
        const pcm16Data = new Int16Array(event.data);
        // Putar array pcm16Data ini ke Speaker CS...
        // (Anda bisa menggunakan AudioContext.createBuffer() untuk memutarnya)
    };
}

async function startMicrophoneStream() {
    // 2. Minta Izin Mikrofon (Set 16kHz Mono)
    mediaStream = await navigator.mediaDevices.getUserMedia({ audio: true });
    audioContext = new AudioContext({ sampleRate: 16000 }); // Wajib 16000
    
    const source = audioContext.createMediaStreamSource(mediaStream);
    const processor = audioContext.createScriptProcessor(2048, 1, 1); // 1 Channel (Mono)

    processor.onaudioprocess = (e) => {
        const inputData = e.inputBuffer.getChannelData(0); // Float32Array (-1.0 to 1.0)
        
        // Convert Float32Array ke Int16Array (PCM 16-bit)
        const pcm16 = new Int16Array(inputData.length);
        for (let i = 0; i < inputData.length; i++) {
            let s = Math.max(-1, Math.min(1, inputData[i]));
            pcm16[i] = s < 0 ? s * 0x8000 : s * 0x7FFF;
        }

        // 3. Kirim ke apiwago
        if (ws.readyState === WebSocket.OPEN) {
            ws.send(pcm16.buffer);
        }
    };

    source.connect(processor);
    processor.connect(audioContext.destination);
}

// Cara Penggunaan:
// connectToCall("ABC12345");
```

> [!TIP]
> Jika Anda menggunakan NodeJS (bukan browser) untuk menghubungkannya ke OpenAI Realtime API, Anda cukup mem-*pipe* `ws` dari `apiwago` ke `ws` milik OpenAI, karena OpenAI Realtime API juga menggunakan PCM 16kHz!
