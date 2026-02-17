const express = require('express');
const axios = require('axios');
const cheerio = require('cheerio');
const rateLimit = require('express-rate-limit');
const app = express();

// Rate Limit: Mencegah spam (10 req / menit)
const limiter = rateLimit({
    windowMs: 60 * 1000,
    max: 10,
    message: "Terlalu banyak permintaan, coba lagi nanti."
});

app.use(limiter);
app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));

// Halaman Utama
app.get('/', (req, res) => {
    res.render('index', { result: null });
});

// Logika Scanning
app.post('/scan', async (req, res) => {
    let targetUrl = req.body.url;
    if (!targetUrl.startsWith('http')) targetUrl = 'http://' + targetUrl;

    try {
        const startTime = Date.now();
        const response = await axios.get(targetUrl, { 
            timeout: 10000, // Maksimal 10 detik
            validateStatus: null 
        });
        
        const html = response.data;
        const $ = cheerio.load(html);
        const duration = Date.now() - startTime;

        let findings = [];
        let riskScore = 0;

        // Analisis Sederhana
        if (!targetUrl.startsWith('https')) {
            riskScore += 2;
            findings.push("Koneksi tidak aman (HTTP).");
        }
        if ($('input[type="password"]').length > 0) {
            riskScore += 3;
            findings.push("Halaman memiliki input password (waspada phishing).");
        }
        if (html.includes('eval(') || html.includes('atob(')) {
            riskScore += 2;
            findings.push("Ditemukan script terenkripsi/mencurigakan.");
        }

        const result = {
            url: targetUrl,
            status: response.status,
            speed: duration + "ms",
            risk: riskScore >= 5 ? "BAHAYA" : (riskScore >= 2 ? "PERINGATAN" : "AMAN"),
            findings
        };

        res.render('index', { result });
    } catch (error) {
        res.render('index', { result: { error: "Gagal mengakses link: " + error.message } });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server aktif di port ${PORT}`);
});

