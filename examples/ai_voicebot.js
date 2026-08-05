const express = require('express');
const WebSocket = require('ws');

const app = express();
app.use(express.json());

// Konfigurasi apiwago
const APIWAGO_WS_URL = 'ws://localhost:7900/api/call/stream';
const PORT = 4000;

console.log("Menjalankan AI Voicebot Bridge di port " + PORT);

app.post('/webhook', (req, res) => {
    const payload = req.body;

    // Ketika ada event Inbound Call dari apiwago
    if (payload.event === 'incoming_call') {
        const callId = payload.call_id;
        const from = payload.from;

        console.log(`\n📞 [INCOMING CALL] Ada telepon masuk dari ${from}`);
        console.log(`⏳ Menunggu 3 detik sebelum menjawab...`);

        // 1. Buka koneksi ke Server AI (Menggunakan samplerate=48000 agar otomatis di-resample oleh Python)
        const aiSocket = new WebSocket('ws://192.168.10.40:8181/ws/audio?samplerate=48000');

        setTimeout(() => {
            console.log(`✅ Menjawab panggilan sekarang!`);
            // 2. Buka koneksi ke APIWA untuk menjawab telepon
            const apiwaSocket = new WebSocket(`${APIWAGO_WS_URL}?call_id=${callId}&mode=mic&action=answer`);

            aiSocket.on('open', () => {
                console.log("✅ Bot WA berhasil terhubung ke Voice Agent AI!");
            });

            apiwaSocket.on('open', () => {
                console.log("✅ Terhubung ke APIWA WebRTC streaming!");
            });

            // 3. KETIKA ADA SUARA MASUK DARI PENELEPON:
            apiwaSocket.on('message', (data) => {
                if (Buffer.isBuffer(data)) {
                    // Tampilkan ukuran byte untuk memastikan bukan file OPUS
                    console.log(`DEBUG: Menerima ${data.length} bytes dari APIWA`);

                    if (aiSocket.readyState === WebSocket.OPEN) {
                        aiSocket.send(data);
                    }
                } else {
                    console.log("Data Teks dari APIWA:", data.toString());
                }
            });

            // 4. KETIKA AI MENJAWAB (TTS):
            aiSocket.on('message', (message) => {
                if (Buffer.isBuffer(message)) {
                    if (apiwaSocket.readyState === WebSocket.OPEN) {
                        apiwaSocket.send(message);
                    }
                } else {
                    try {
                        const log = JSON.parse(message.toString());
                        console.log("Log AI:", log);
                    } catch (e) {
                        console.log("Teks dari AI:", message.toString());
                    }
                }
            });

            // 5. Handling saat panggilan ditutup
            apiwaSocket.on('close', () => {
                console.log('❌ Panggilan WA berakhir.');
                if (aiSocket.readyState === WebSocket.OPEN) aiSocket.close();
            });

            aiSocket.on('close', () => {
                console.log('❌ Koneksi AI Server terputus.');
                if (apiwaSocket.readyState === WebSocket.OPEN) apiwaSocket.close();
            });
        }, 3000);
    }

    res.status(200).send("OK");
});

app.listen(PORT, () => {
    console.log(`🚀 Bridge Server berjalan. Arahkan webhook apiwago ke http://localhost:${PORT}/webhook`);
    console.log(`Jangan lupa aktifkan Inbound Call via POST /api/start dengan parameter {"token":"111", "call_behavior":"forward"}`);
});
