# **Poloss XSS v2 — Advanced XSS Scanner**

**White Hat Cyber International Grade | BY POLOSS**

<img src="assets/screenshot.png" width="800">

## **✨ Fitur Utama**

* Advanced parameter mining (URL, form, header, cookie, JSON, file)
* Smart reflection context detector
* Payload mutation engine (context-aware + WAF bypass)
* Polyglot payloads
* DOM XSS analyzer
* Blind XSS support (callback)
* Concurrency engine (ThreadPoolExecutor)
* WAF detection (Cloudflare, AWS WAF, ModSecurity, dll)
* Automatic JSON report generator
* Real request execution (bukan simulasi)

---

## **📦 Instalasi**

```bash
git clone https://github.com/O99099O/Poloss_Xss
cd Poloss_Xss
pip install -r requirements.txt
```

---

## **🚀 Cara Menjalankan**

### **Scan Komprehensif**

```bash
python3 xss_fuzzer_v2.py -u http://target.com
```

### **DOM Mode**

```bash
python3 xss_fuzzer_v2.py -u http://target.com -m dom
```

### **Fast Scan**

```bash
python3 xss_fuzzer_v2.py -u http://target.com -m fast
```

### **Blind XSS**

```bash
python3 xss_fuzzer_v2.py -u http://target.com -m blind -c http://your-callback.net
```

### **Custom Header**

```bash
python3 xss_fuzzer_v2.py -u http://target.com -H "Cookie:abc,User-Agent:Poloss"
```

---

## **📊 Output Laporan**

Hasil scan otomatis tersimpan sebagai:

```
xss_scan_XXXXXXXX.json
```

Isi:

* Statistik
* Parameter diuji
* Payload terpicu
* WAF detection
* Vulnerability detail + exploit example

---

## **🧠 Mode Scanning**

| Mode            | Deskripsi                     |
| --------------- | ----------------------------- |
| `fast`          | Fokus URL + form, cepat       |
| `comprehensive` | Semua parameter, semua metode |
| `dom`           | DOM XSS focus                 |
| `blind`         | Blind callback XSS            |

---

## **📡 Fitur Tambahan**

* Auto crawling internal link
* Context-aware payload selection
* Auto verification (anti false positive)
* Realistic request injection
* Multi-threaded payload executor

---

## **🔒 Catatan Legal**

Gunakan hanya untuk **pengujian legal / izin resmi**.
Segala penyalahgunaan di luar tanggung jawab kamu sendiri.

---

## **🖋️ Watermark**

**BY POLOSS**

---

