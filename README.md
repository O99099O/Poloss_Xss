
---

Poloss XSS v3.2 — Advanced XSS Scanner

<img src="assets/screenshot.png" width="800">
---

✨ Fitur Utama (V3.2 Upgrade)

Advanced parameter mining terlengkap
(URL, form, header, cookie, JSON, file upload)

Smart reflection context detector (HTML/JS/URL/Attribute)

Ultra-rich payload database 2000+ payload

Payload mutation engine (context-aware + auto WAF bypass)

DOM XSS Analyzer (full sink detection)

Blind XSS Engine (callback + auto data exfil)

CSP bypass payload set

Mutation XSS detector

Prototype pollution payload injector

WAF detection (Cloudflare, AWS WAF, ModSecurity, F5, dll)

Polyglot payload support

No-WAF mode

Automatic JSON report generator

Multi-threaded executor (ThreadPoolExecutor)

Real request execution (bukan simulasi)

Platform detection (Termux, WSL, Kali, Linux, macOS)



---

📦 Instalasi

git clone https://github.com/O99099O/Poloss_Xss -b O99099O-Update-V3.2
cd Poloss_Xss
pip install -r requirements.txt

requirements.txt:

requests
beautifulsoup4
colorama
urllib3
lxml


---

🚀 Cara Menjalankan

Scan Komprehensif

python3 "Xss_main V3.2.py" -u http://target.com

DOM Focus Mode

python3 "Xss_main V3.2.py" -u http://target.com --mode dom

Fast Scan (Cepat)

python3 "Xss_main V3.2.py" -u http://target.com --mode fast

Blind XSS Mode

python3 "Xss_main V3.2.py" -u http://target.com --blind-callback http://your-callback.net

Skip WAF Detection

python3 "Xss_main V3.2.py" -u http://target.com --no-waf

Custom Header

python3 "Xss_main V3.2.py" -u http://target.com -H "Cookie:abc; User-Agent:Poloss"

Custom Threads

python3 "Xss_main V3.2.py" -u http://target.com --threads 20


---

📊 Output Laporan

Setiap scan menghasilkan folder berisi:

xss_scan_YYYYMMDD_HHMMSS.log
xss_report_XXXXXXXX.json

Isi laporan:

Statistik scan

Parameter ditemukan

Payload yang dipicu

Bypass payload

WAF detection

DOM sink result

Blind XSS hit

Exploit example lengkap



---

🧠 Mode Scanning (V3.2)

Mode	Deskripsi

fast	Scan cepat (URL + form)
dom	Fokus DOM & client-side sink
blind	Blind XSS full callback
comprehensive	Semua parameter + payload lengkap (default)



---

📡 Fitur Tambahan

Auto crawling internal link

Payload generator cerdas berbasis konteks

Auto verification untuk menekan false positive

Realistic request injection (tidak ada dummy/simulasi)

Auto platform detection (Termux/WSL/Kali)



---

🔒 Catatan Legal

Gunakan hanya untuk pengujian yang memiliki izin resmi.
Segala penyalahgunaan berada di luar tanggung jawab pembuat.


---

🖋️ Watermark

BY POLOSS


---
