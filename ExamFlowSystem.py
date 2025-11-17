#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Güvenli Sınav Dosya Toplama Sunusu (v3.1)
- KRİTİK HATA DÜZELTMESİ (BAT Script v3.1):
    - BAT scripti artik 'netsh wlan show interfaces' kullanarak
      aktif Wi-Fi adaptörünün adini DINAMIK olarak bulur.
    - 'Hard-coding' (name="Wi-Fi") sorunu %100 cozuldu.
    - Dogrulama metodu (netsh show address) artik sadece bulunan adaptoru
      kontrol eder, 'ipconfig' karmasasi giderildi.
- GÜNCELLEME: Ikinci DNS (8.8.8.8) tum script'lerden kaldirildi.
- YENİ: Opsiyonel Veyon Setup (.exe) indirme butonu eklendi (Adim 4).
- YENİ: Ayni ogrenci numarali tum kayitlar sari ile isaretlenir.
- YENİ: HTML Log siralamasi degisti (Ilk yukleyen = #1).
- YENİ: Gelişmiş Mükerrer Tespiti (Ilk dosya da kirmizi olur).
- YENİ: Esnek IP Atama (192.168.1-3.x) ve Dinamik Gateway (.1).
- OPTİMİZASYON: Sunucu başlarken eski kayıtları HTML log'dan okuma
- Threading ile çoklu bağlantı desteği
- SHA256 checksum kaydı
- IP başına Rate Limiting
"""

# --- Gerekli Kütüphaneler ---
from http.server import HTTPServer, BaseHTTPRequestHandler, ThreadingHTTPServer
import os
import cgi
from datetime import datetime, timedelta
import json
import tkinter as tk
from tkinter import filedialog
import sys
import socket
import socketserver
import hashlib
import html  # Hata düzeltmesi
import re  # Log okuma
from urllib.parse import urlparse, parse_qs  # IP script
from collections import Counter # Ogrenci no sayimi icin
import subprocess  # YENİ: Hostname tespiti için
import platform  # YENİ: İşletim sistemi tespiti için
import threading  # YENİ: Thread-safe log yazma için
import time  # YENİ: DDoS tespiti için
import webbrowser  # YENİ: Otomatik tarayıcı açma için

# --- YENİ: Excel okumak için ---
try:
    import pandas as pd
except ImportError:
    print("\n" + "="*70)
    print("❌ HATA: Gerekli 'pandas' kütüphanesi bulunamadı.")
    print("Bu yeni özelliği kullanmak için lütfen terminale şunu yazın:")
    print("pip install pandas openpyxl")
    print("="*70 + "\n")
    sys.exit(1)

# --- YENİ: Ağ taraması için Scapy ---
try:
    from scapy.all import ARP, Ether, srp
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("\n" + "="*70)
    print("⚠️  UYARI: 'scapy' kütüphanesi bulunamadı.")
    print("Dashboard özelliği için lütfen terminale şunu yazın:")
    print("pip install scapy")
    print("="*70 + "\n")


# --- Global Değişkenler ---
PEM_FILE_PATH = None
UPLOAD_DIR = None
EXCEL_DATA_HTML = None
VEYON_SETUP_PATH = None # YENİ
VEYON_SETUP_FILENAME = None # YENİ
REFERENCE_EXAM_HASH = None # YENİ: Boş sınav tespiti için referans hash
REFERENCE_EXAM_FILENAME = None # YENİ: Referans dosya adı
PORT = 80
UPLOAD_COUNT = 0
PEM_DOWNLOAD_COUNT = 0
VEYON_DOWNLOAD_COUNT = 0  # YENİ: Veyon Setup indirme sayısı
UPLOADED_IPS = {}
ALL_UPLOADS = [] 
SEEN_HASHES_MAP = {}
NETWORK_CLIENTS = [] # YENİ: Ağdaki cihazlar (IP, MAC, Hostname)
PEM_DOWNLOADS = []  # YENİ: PEM indirme logları
VEYON_DOWNLOADS = []  # YENİ: Veyon Setup indirme logları
REQUEST_LOGS = {}  # YENİ: DDoS/DoS tespiti için IP bazlı istek logları
TERMINAL_LOG_FILE = None  # YENİ: Terminal log dosyası yolu

def get_local_ip():
    """Bilgisayarın yerel IP adresini otomatik bul"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return "127.0.0.1"

# YENİ: Terminal log yazma fonksiyonu (thread-safe)
_log_lock = threading.Lock()

def write_terminal_log(message, end='\n'):
    """Terminal çıktısını hem ekrana hem de log dosyasına yazar"""
    global TERMINAL_LOG_FILE
    print(message, end=end, flush=True)
    
    if TERMINAL_LOG_FILE:
        try:
            with _log_lock:
                with open(TERMINAL_LOG_FILE, 'a', encoding='utf-8') as f:
                    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    f.write(f"[{timestamp}] {message}{end}")
        except Exception as e:
            # Log yazma hatası terminali bozmasın
            pass

# YENİ: Dosya boyutu formatlama
def format_file_size(size_bytes):
    """Byte'ı okunabilir formata çevirir"""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.2f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.2f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"

# YENİ: Gelişmiş hostname tespiti
def get_hostname(ip_address):
    """IP adresinden hostname'i bulmaya çalışır (birden fazla yöntem dener)"""
    hostname = None
    
    # Yöntem 1: socket.gethostbyaddr() (DNS reverse lookup)
    try:
        hostname = socket.gethostbyaddr(ip_address)[0]
        if hostname:
            return hostname
    except (socket.herror, socket.gaierror, socket.timeout):
        pass
    
    # Yöntem 2: Windows'ta nbtstat komutu (NetBIOS)
    if platform.system().lower() == 'windows':
        try:
            # nbtstat -A IP komutunu çalıştır
            result = subprocess.run(
                ['nbtstat', '-A', ip_address],
                capture_output=True,
                text=True,
                timeout=3,
                encoding='utf-8',
                errors='ignore'
            )
            
            if result.returncode == 0:
                # Çıktıyı parse et - "UNIQUE" satırından hostname'i bul
                # Örnek: "ROOT            <00>  UNIQUE      Registered"
                lines = result.stdout.split('\n')
                in_table = False
                
                for line in lines:
                    # Tablo başlığını bul
                    if 'Name' in line and 'Type' in line:
                        in_table = True
                        continue
                    
                    if in_table and ('UNIQUE' in line or 'GROUP' in line):
                        # Satırı parse et - ilk kelime hostname olabilir
                        # Örnek: "ROOT            <00>  UNIQUE      Registered"
                        parts = line.split()
                        if len(parts) >= 2:
                            potential_hostname = parts[0].strip()
                            # Geçerli hostname kontrolü
                            # - Boş değil
                            # - IP adresi değil
                            # - Özel karakterler içermiyor (sadece alfanumerik, tire, alt çizgi)
                            if (potential_hostname and 
                                not potential_hostname.replace('.', '').isdigit() and
                                len(potential_hostname) <= 15 and  # NetBIOS hostname max 15 karakter
                                potential_hostname.replace('-', '').replace('_', '').isalnum()):
                                # <00> ile biten UNIQUE kayıt genellikle ana hostname'dir
                                if '<00>' in line and 'UNIQUE' in line:
                                    hostname = potential_hostname
                                    break
                                # Eğer <00> bulunamazsa, ilk geçerli UNIQUE kaydı al
                                elif not hostname and 'UNIQUE' in line:
                                    hostname = potential_hostname
        except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError):
            pass
    
    # Yöntem 3: Linux'ta nmblookup (Samba/NetBIOS)
    elif platform.system().lower() == 'linux':
        try:
            result = subprocess.run(
                ['nmblookup', '-A', ip_address],
                capture_output=True,
                text=True,
                timeout=3
            )
            
            if result.returncode == 0:
                # Çıktıyı parse et
                for line in result.stdout.split('\n'):
                    if '<00>' in line or '<20>' in line:
                        parts = line.split()
                        if len(parts) > 0:
                            potential_hostname = parts[0].strip()
                            if potential_hostname and not potential_hostname.replace('.', '').isdigit():
                                hostname = potential_hostname
                                break
        except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError):
            pass
    
    return hostname

# YENİ: Ağ taraması fonksiyonu (Scapy ile)
def scan_network():
    """Ağdaki cihazları tarar ve IP, MAC, Hostname bilgilerini döner"""
    if not SCAPY_AVAILABLE:
        raise Exception("Scapy kütüphanesi yüklü değil")
    
    clients = []
    local_ip = get_local_ip()
    
    # IP'nin subnet'ini bul (örn: 192.168.1.5 -> 192.168.1.0/24)
    ip_parts = local_ip.split('.')
    if len(ip_parts) != 4:
        raise Exception(f"Geçersiz IP adresi: {local_ip}")
    
    subnet = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
    
    write_terminal_log(f"🔍 Ağ taranıyor: {subnet}")
    
    try:
        # ARP isteği oluştur
        arp_request = ARP(pdst=subnet)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        
        # Paketleri gönder ve yanıtları al (timeout: 2 saniye)
        answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]
        
        for element in answered_list:
            client_ip = element[1].psrc
            client_mac = element[1].hwsrc
            
            # Gelişmiş hostname tespiti (birden fazla yöntem dener)
            write_terminal_log(f"   • {client_ip} - Hostname aranıyor...", end=' ')
            hostname = get_hostname(client_ip)
            if hostname:
                write_terminal_log(f"✅ {hostname}")
            else:
                write_terminal_log("❌ Bulunamadı")
            
            clients.append({
                'ip': client_ip,
                'mac': client_mac,
                'hostname': hostname
            })
        
        # IP'ye göre sırala
        clients.sort(key=lambda x: socket.inet_aton(x['ip']))
        
        write_terminal_log(f"✅ {len(clients)} cihaz bulundu")
        return clients
        
    except Exception as e:
        write_terminal_log(f"❌ Tarama hatası: {str(e)}")
        raise

# HTML Log için CSS Stilleri
def get_html_log_style():
    """HTML log dosyası için CSS stillerini döndürür"""
    return """
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #333;
            margin: 0;
            padding: 25px 20px;
            min-height: 100vh;
        }
        
        .container {
            max-width: 1500px;
            margin: 0 auto;
            background: white;
            border-radius: 12px;
            box-shadow: 0 8px 25px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        
        .header {
            padding: 30px;
            background: white;
            color: #333;
            border-bottom: 5px solid #5a67d8;
        }
        
        .header h1 {
            margin: 0;
            font-size: 28px;
            color: #333;
        }
        
        .header p {
            margin: 5px 0 0;
            font-size: 16px;
            color: #666;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            background: white;
        }
        
        th, td {
            padding: 18px 22px;
            text-align: left;
            border-bottom: 1px solid rgba(224, 224, 224, 0.5);
            vertical-align: middle;
        }
        
        th {
            background: linear-gradient(135deg, #f9fafb 0%, #f0f2f5 100%);
            font-weight: 700;
            color: #444;
            font-size: 13px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            position: sticky;
            top: 0;
            z-index: 10;
            box-shadow: 0 2px 8px rgba(0,0,0,0.05);
        }
        
        tbody tr:nth-child(even) {
            background-color: rgba(252, 252, 252, 0.8);
        }
        
        tbody tr:hover {
            background-color: #f0f4ff;
        }
        
        td {
            font-size: 15px;
            color: #555;
        }
        
        td.hash {
            font-family: "Courier New", Courier, monospace;
            font-size: 13px;
            color: #666;
            cursor: pointer;
            word-break: break-all;
            max-width: 400px;
            transition: all 0.3s ease;
            padding: 12px 18px;
        }
        
        td.hash:hover {
            color: #667eea;
        }
        
        /* Mükerrer hash'li satır için stil (KIRMIZI - Kopya) */
        .duplicate-row, .duplicate-row td {
            background-color: #ffebee !important;
            color: #c00 !important;
            font-weight: 600;
        }
        
        .duplicate-row:hover, .duplicate-row:hover td {
            background-color: #ffcdd2 !important;
        }
        
        /* Mükerrer öğrenci no'lu satır için stil (SARI - Tekrar Yükleme) */
        .duplicate-number-row, .duplicate-number-row td {
            background-color: #fffde7 !important;
            color: #795548 !important;
        }
        
        .duplicate-number-row:hover, .duplicate-number-row:hover td {
            background-color: #fff9c4 !important;
        }
        
        /* Boş sınav dosyası için stil (MOR - Referansla Aynı) */
        .empty-exam-row, .empty-exam-row td {
            background-color: #f3e5f5 !important;
            color: #6a1b9a !important;
            font-weight: 600;
        }
        
        .empty-exam-row:hover, .empty-exam-row:hover td {
            background-color: #e1bee7 !important;
        }
    </style>
    """

# GÜNCELLENDİ: Sıralama ve Sarı Vurgu eklendi
def update_html_log(log_file_path, uploads):
    """Verilen yükleme listesine göre HTML log dosyasını oluşturur/günceller"""
    style = get_html_log_style()
    
    header = f"""
    <!DOCTYPE html>
    <html lang="tr">
    <head>
        <meta charset="UTF-8">
        <meta http-equiv="refresh" content="30"> <title>Sınav Yükleme Kayıtları</title>
        {style}
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🎓 Sınav Yükleme Kayıtları</h1>
                <p>Toplam Yükleme: <strong>{len(uploads)}</strong> | Son Güncelleme: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>#</th>
                        <th>Zaman</th>
                        <th>Ad Soyad</th>
                        <th>Numara</th>
                        <th>Dosya Adı</th>
                        <th>Boyut</th>
                        <th>IP Adresi</th>
                        <th>SHA256 Hash</th>
                    </tr>
                </thead>
                <tbody>
    """
    
    # --- YENİ: Sarı vurgu için öğrenci numaralarını say ---
    student_number_counts = Counter(entry['number'] for entry in uploads)
    duplicate_numbers = {num for num, count in student_number_counts.items() if count > 1}
    # --- Bitti ---
    
    rows = ""
    # GÜNCELLENDİ: `reversed()` kaldırıldı (İlk yükleyen #1 olacak)
    for i, entry in enumerate(uploads, 1):
        # HTML injection'ı önlemek için html.escape kullan
        safe_name = html.escape(entry['name'])
        safe_number = html.escape(entry['number'])
        safe_filename = html.escape(entry['filename'])
        
        # GÜNCELLENDİ: Vurgu sınıflandırması (Kırmızı > Mor > Sarı öncelikli)
        is_duplicate_hash = entry.get('is_duplicate_hash', False)
        matches_reference_exam = entry.get('matches_reference_exam', False)
        is_duplicate_num = entry['number'] in duplicate_numbers
        
        row_classes = []
        if is_duplicate_hash:
            row_classes.append('duplicate-row') # Kırmızı (Kopya)
        elif matches_reference_exam:
            row_classes.append('empty-exam-row') # Mor (Boş Sınav)
        elif is_duplicate_num:
            row_classes.append('duplicate-number-row') # Sarı (Tekrar Yükleme)
            
        row_class_attr = f' class="{" ".join(row_classes)}"' if row_classes else ''
        # --- Bitti ---
        
        # Dosya boyutu formatla
        file_size_str = entry.get('file_size_formatted', '-')
        if not file_size_str or file_size_str == '-':
            file_size_bytes = entry.get('file_size', 0)
            if file_size_bytes:
                file_size_str = format_file_size(file_size_bytes)
        
        rows += f"""
        <tr{row_class_attr}>
            <td>{i}</td>
            <td>{entry['time']}</td>
            <td>{safe_name}</td>
            <td>{safe_number}</td>
            <td>{safe_filename}</td>
            <td>{file_size_str}</td>
            <td>{entry['ip']}</td>
            <td class="hash" title="SHA256 Hash (Tamamı)">{entry['sha256']}</td>
        </tr>
        """
    
    footer = """
                </tbody>
            </table>
        </div>
    </body>
    </html>
    """
    
    try:
        with open(log_file_path, 'w', encoding='utf-8') as f:
            f.write(header + rows + footer)
    except Exception as e:
        print(f"❌ HTML log dosyası yazılırken hata oluştu: {e}")


# Sunucu başladığında eski kayıtları HTML log'dan okur
def load_previous_uploads(upload_dir):
    """HTML log dosyasını okuyarak ALL_UPLOADS ve SEEN_HASHES_MAP'i doldurur."""
    global ALL_UPLOADS, SEEN_HASHES_MAP, UPLOAD_COUNT
    log_file_html = os.path.join(upload_dir, '_yukleme_kayitlari.html')
    
    if not os.path.exists(log_file_html):
        write_terminal_log("ℹ️ Önceki yükleme kaydı (.html) bulunamadı, yeni bir log başlatılıyor.")
        return

    write_terminal_log(f"ℹ️ Önceki kayıtlar şuradan okunuyor: {log_file_html}")
    
    try:
        with open(log_file_html, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # HTML'i parse etmek için regex
        entry_pattern = re.compile(
            r'<tr(.*?)>.*?<td>.*?</td>.*?<td>(.*?)</td>.*?<td>(.*?)</td>.*?<td>(.*?)</td>.*?<td>(.*?)</td>.*?<td>(.*?)</td>.*?<td.*?title="(.*?)">.*?</tr>', 
            re.DOTALL
        )
        
        matches = list(entry_pattern.finditer(content))
        
        # GÜNCELLENDİ: Artık ters çevirmiyoruz, log'daki sıra neyse o (1, 2, 3...)
        
        count = 0
        current_index = 0
        for match in matches:
            row_class, time, name, num, fname, ip, hash_val = match.groups()
            
            name = html.unescape(name)
            num = html.unescape(num)
            fname = html.unescape(fname)
            
            # Mükerrer tespiti (ilk dosya için)
            is_duplicate = False
            if hash_val in SEEN_HASHES_MAP:
                is_duplicate = True
                # Bu hash'i ilk görenin de duplicate flag'ini True yap
                original_index = SEEN_HASHES_MAP[hash_val]
                ALL_UPLOADS[original_index]['is_duplicate_hash'] = True
            else:
                SEEN_HASHES_MAP[hash_val] = current_index
            
            # Boş sınav tespiti (referans hash ile karşılaştır)
            matches_reference = False
            if REFERENCE_EXAM_HASH and hash_val == REFERENCE_EXAM_HASH:
                matches_reference = True
            
            log_entry = {
                'time': time,
                'name': name,
                'number': num,
                'filename': fname,
                'ip': ip,
                'sha256': hash_val,
                'file_size': 0,  # Eski kayıtlarda dosya boyutu yok
                'file_size_formatted': '-',  # Eski kayıtlarda formatlanmış boyut yok
                'is_duplicate_hash': is_duplicate, # Bu dosyanın durumu
                'matches_reference_exam': matches_reference # Boş sınav kontrolü
            }
            
            ALL_UPLOADS.append(log_entry)
            count += 1
            current_index += 1
            
        write_terminal_log(f"✅ {count} adet önceki kayıt hafızaya yüklendi.")
        UPLOAD_COUNT = len(ALL_UPLOADS)
        
        # HTML'i her zaman yeniden yaz
        write_terminal_log("ℹ️ Kayıtlar okundu, HTML log yeniden oluşturuluyor (vurgular için)...")
        update_html_log(log_file_html, ALL_UPLOADS)

    except Exception as e:
        write_terminal_log(f"❌ Önceki loglar okunurken HATA oluştu: {e}. (Sıfırdan devam edilecek)")
        ALL_UPLOADS = []
        SEEN_HASHES_MAP = {}


# Threading MixIn
class ThreadingServer(socketserver.ThreadingMixIn, HTTPServer):
    """Çoklu bağlantıları (thread) destekleyen sunucu"""
    pass

class SecureExamHandler(BaseHTTPRequestHandler):
    
    # YENİ: DDoS/DoS tespiti
    def check_ddos(self):
        """IP bazlı istek sayısını kontrol eder ve DDoS/DoS tespit eder"""
        global REQUEST_LOGS
        
        client_ip = self.client_address[0]
        current_time = time.time()
        
        # Localhost'tan gelen istekleri kontrol etme
        if client_ip == "127.0.0.1":
            return False
        
        # İlk istek veya eski logları temizle
        if client_ip not in REQUEST_LOGS:
            REQUEST_LOGS[client_ip] = []
        
        # Son 10 saniyedeki istekleri filtrele
        REQUEST_LOGS[client_ip] = [
            req_time for req_time in REQUEST_LOGS[client_ip]
            if current_time - req_time < 10
        ]
        
        # Yeni isteği ekle
        REQUEST_LOGS[client_ip].append(current_time)
        
        # Eğer 10 saniyede 50'den fazla istek varsa DDoS/DoS olabilir
        if len(REQUEST_LOGS[client_ip]) > 50:
            write_terminal_log(f"🚨 DDoS/DoS TESPİT EDİLDİ! IP: {client_ip}, 10 saniyede {len(REQUEST_LOGS[client_ip])} istek")
            return True
        
        return False
    
    def do_GET(self):
        """GET isteklerini güvenli şekilde işle"""
        # YENİ: DDoS/DoS kontrolü
        if self.check_ddos():
            self.send_error(429, "Too Many Requests - DDoS/DoS tespit edildi!")
            return
        
        # Rotalar
        if self.path == '/' or self.path == '/index.html':
            self.serve_homepage()
        elif self.path == '/upload':
            self.serve_upload_page()
        elif self.path == '/download-pem':
            self.serve_pem_file()
        elif self.path == '/download-veyon': # YENİ
            self.serve_veyon_setup()
        elif self.path == '/ip-atama': # YENİ
            self.serve_ip_config_page()
        elif self.path.startswith('/generate-script'): # YENİ
            self.handle_script_generation()
        elif self.path == '/admin/clients': # YENİ: Dashboard (sadece 127.0.0.1)
            self.serve_admin_dashboard()
        elif self.path == '/admin/data': # YENİ: Dashboard verileri (JSON)
            self.serve_admin_data()
        elif self.path == '/admin/scan': # YENİ: Manuel tarama endpoint'i
            self.handle_network_scan()
        else:
            self.send_error(403, "Access Denied")
    
    def serve_homepage(self):
        """Ana sayfayı göster - 4 buton"""
        global VEYON_SETUP_PATH
        
        self.send_response(200)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.end_headers()
        
        # --- YENİ: Veyon butonu için sunucu taraflı koşul ---
        veyon_btn_class = "btn-info"
        veyon_btn_href = "/download-veyon"
        veyon_btn_attributes = 'id="veyonBtn" download'
        
        if VEYON_SETUP_PATH is None:
            veyon_btn_class = "btn-disabled" # Gri/Devre dışı
            veyon_btn_href = "#"
            veyon_btn_attributes = 'id="veyonBtn" disabled' # Tıklanmasın
        # --- Bitti ---
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Sınav Sistemi</title>
            <style>
                * {{
                    margin: 0;
                    padding: 0;
                    box-sizing: border-box;
                }}
                
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    padding: 20px;
                }}
                
                .container {{
                    background: white;
                    padding: 50px 40px;
                    border-radius: 20px;
                    box-shadow: 0 20px 60px rgba(0,0,0,0.3);
                    max-width: 550px;
                    width: 100%;
                    text-align: center;
                }}
                
                h1 {{
                    color: #333;
                    margin-bottom: 15px;
                    font-size: 36px;
                    font-weight: 600;
                }}
                
                .subtitle {{
                    color: #666;
                    margin-bottom: 45px;
                    font-size: 16px;
                    font-weight: 400;
                    opacity: 0.9;
                }}
                
                .button-container {{
                    display: flex;
                    flex-direction: column;
                    gap: 18px;
                }}
                
                .btn {{
                    padding: 18px 25px;
                    font-size: 17px;
                    font-weight: 600;
                    border: none;
                    border-radius: 12px;
                    cursor: pointer;
                    transition: all 0.2s ease;
                    text-decoration: none;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    gap: 10px;
                    box-shadow: 0 4px 12px rgba(0,0,0,0.15);
                }}
                
                .btn-primary {{
                    background: #4CAF50;
                    color: white;
                }}
                
                .btn-primary:hover {{
                    background: #45a049;
                    transform: translateY(-2px);
                    box-shadow: 0 6px 16px rgba(76, 175, 80, 0.3);
                }}
                
                .btn-secondary {{
                    background: #2196F3;
                    color: white;
                }}
                
                .btn-secondary:hover {{
                    background: #0b7dda;
                    transform: translateY(-2px);
                    box-shadow: 0 6px 16px rgba(33, 150, 243, 0.3);
                }}
                
                .btn-warning {{
                    background: #f39c12;
                    color: white;
                }}
                
                .btn-warning:hover {{
                    background: #e67e22;
                    transform: translateY(-2px);
                    box-shadow: 0 6px 16px rgba(243, 156, 18, 0.3);
                }}
                
                .btn-info {{
                    background: #00bcd4;
                    color: white;
                }}
                
                .btn-info:hover {{
                    background: #0097a7;
                    transform: translateY(-2px);
                    box-shadow: 0 6px 16px rgba(0, 188, 212, 0.3);
                }}
                
                .icon {{
                    font-size: 24px;
                    filter: drop-shadow(0 2px 4px rgba(0,0,0,0.2));
                }}
                
                .info-box {{
                    background: #f0f7ff;
                    padding: 18px;
                    border-radius: 10px;
                    margin-top: 30px;
                    color: #1976d2;
                    font-size: 14px;
                    border-left: 4px solid #2196F3;
                }}
                
                .btn.btn-disabled {{
                    background: #cccccc;
                    color: #888;
                    cursor: not-allowed;
                    opacity: 0.7;
                    pointer-events: none;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🎓 Sınav Sistemi</h1>
                <p class="subtitle">Lütfen yapmak istediğiniz işlemi seçin</p>
                
                <div class="button-container">
                    
                    <a href="{veyon_btn_href}" class="btn {veyon_btn_class}" {veyon_btn_attributes}>
                        <span class="icon">🖥️</span>
                        <span id="veyonBtnText">Veyon Setup Dosyasını İndir</span>
                    </a>

                    <a href="/download-pem" class="btn btn-secondary" id="pemBtn" download>
                        <span class="icon">🔑</span>
                        <span id="pemBtnText">Veyon PEM Anahtarını İndir</span>
                    </a>
                    
                    <a href="/ip-atama" class="btn btn-warning">
                        <span class="icon">📡</span>
                        <span>Sınav IP'si Ata</span>
                    </a>
                    
                    <a href="/upload" class="btn btn-primary">
                        <span class="icon">📤</span>
                        <span>Sınav Dosyası Yükle</span>
                    </a>
                </div>
                
                <div class="info-box">
                    <strong>ℹ️ Önemli:</strong><br>
                    (Gerekirse) Veyon Setup ve IP atamayı kullanın.<br>
                    Sonra PEM anahtarını indirip Veyon'a yükleyin.<br>
                    Sınavınızı bitirince dosya yükleme bölümünü kullanın.
                </div>
            </div>
            
            <script>
                // PEM Butonu
                document.getElementById('pemBtn').addEventListener('click', () => {{
                    const btn = document.getElementById('pemBtn');
                    const btnText = document.getElementById('pemBtnText');
                    btn.classList.add('btn-disabled');
                    btnText.textContent = '✅ İndirildi';
                }});
                
                // YENİ: Veyon Butonu
                const veyonBtn = document.getElementById('veyonBtn');
                if (veyonBtn && !veyonBtn.hasAttribute('disabled')) {{
                    veyonBtn.addEventListener('click', () => {{
                        const btnText = document.getElementById('veyonBtnText');
                        veyonBtn.classList.add('btn-disabled');
                        btnText.textContent = '✅ İndirildi';
                    }});
                }}
            </script>
        </body>
        </html>
        """
        self.wfile.write(html.encode('utf-8'))
    
    def serve_upload_page(self):
        """Dosya yükleme sayfasını göster"""
        self.send_response(200)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.end_headers()
        
        # Progress bar HTML, XHR ve doğrulama
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Dosya Yükle</title>
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
                
                body {
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    padding: 20px;
                }
                
                .container {
                    background: white;
                    padding: 40px;
                    border-radius: 20px;
                    box-shadow: 0 20px 60px rgba(0,0,0,0.3);
                    max-width: 600px;
                    width: 100%;
                }
                
                h1 {
                    color: #333;
                    text-align: center;
                    margin-bottom: 30px;
                    font-size: 28px;
                    font-weight: 600;
                }
                
                .form-group { margin-bottom: 28px; }
                
                label {
                    display: block;
                    margin-bottom: 10px;
                    font-weight: 600;
                    color: #444;
                    font-size: 15px;
                }
                
                input[type="text"], input[type="number"] {
                    width: 100%;
                    padding: 12px 15px;
                    border: 2px solid #e0e0e0;
                    border-radius: 8px;
                    font-size: 16px;
                    transition: border-color 0.2s ease;
                }
                
                input[type="text"]:focus, input[type="number"]:focus {
                    outline: none;
                    border-color: #667eea;
                }
                
                .file-input-wrapper { 
                    position: relative; 
                    margin: 30px 0; 
                }
                
                input[type="file"] {
                    width: 100%;
                    padding: 15px;
                    border: 3px dashed #4CAF50;
                    border-radius: 10px;
                    cursor: pointer;
                    background: #f9fff9;
                    font-size: 15px;
                    transition: border-color 0.2s ease;
                }
                
                input[type="file"]:hover {
                    background: #f0fff0;
                    border-color: #45a049;
                }
                
                button {
                    width: 100%;
                    padding: 15px;
                    background: #4CAF50;
                    color: white;
                    border: none;
                    border-radius: 10px;
                    font-size: 18px;
                    font-weight: 600;
                    cursor: pointer;
                    transition: all 0.2s ease;
                    margin-top: 10px;
                    box-shadow: 0 4px 12px rgba(76, 175, 80, 0.3);
                }
                
                button:hover:not(:disabled) {
                    background: #45a049;
                    transform: translateY(-2px);
                    box-shadow: 0 6px 16px rgba(76, 175, 80, 0.4);
                }
                
                button:disabled {
                    background: #cccccc;
                    cursor: not-allowed;
                }
                
                .back-link {
                    display: block;
                    text-align: center;
                    margin-top: 20px;
                    color: #667eea;
                    text-decoration: none;
                    font-weight: 600;
                }
                
                .back-link:hover {
                    text-decoration: underline;
                }
                
                .status-message {
                    padding: 15px;
                    border-radius: 8px;
                    margin-top: 20px;
                    font-weight: 600;
                }
                
                .success {
                    background: #d4edda;
                    color: #155724;
                    border-left: 4px solid #28a745;
                }
                
                .error {
                    background: #f8d7da;
                    color: #721c24;
                    border-left: 4px solid #dc3545;
                }
                
                .info {
                    background: #e3f2fd;
                    padding: 15px;
                    border-radius: 8px;
                    margin-bottom: 25px;
                    color: #1976d2;
                    border-left: 4px solid #2196F3;
                }
                
                .required {
                    color: #dc3545;
                    font-weight: 700;
                }
                
                #progress-container {
                    display: none;
                    width: 100%;
                    background: linear-gradient(135deg, #e0e0e0 0%, #f5f5f5 100%);
                    border-radius: 15px;
                    margin: 25px 0 15px 0;
                    overflow: hidden;
                    box-shadow: inset 0 2px 5px rgba(0,0,0,0.1);
                    height: 30px;
                }
                
                #progress-bar {
                    width: 0%;
                    height: 100%;
                    background: #4CAF50;
                    text-align: center;
                    line-height: 30px;
                    color: white;
                    font-weight: 600;
                    transition: width 0.3s ease;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>📤 Sınav Dosyası Yükle</h1>
                
                <div class="info">
                    <strong>ℹ️ Dikkat:</strong><br>
                    • Sadece .pka uzantılı dosyalar yüklenebilir<br>
                    • Numaranız 10 haneli olmalıdır<br>
                    • Dosya yüklendikten sonra onay mesajı göreceksiniz
                </div>
                
                <form id="uploadForm" enctype="multipart/form-data">
                    <div class="form-group">
                        <label for="student_name">
                            Adınız Soyadınız <span class="required">*</span>
                        </label>
                        <input type="text" 
                               id="student_name" 
                               name="student_name" 
                               required 
                               placeholder="Örn: Ahmet Yılmaz"
                               autocomplete="off">
                    </div>
                    
                    <div class="form-group">
                        <label for="student_number">
                            Öğrenci Numaranız (10 Hane) <span class="required">*</span>
                        </label>
                        <input type="text" 
                               id="student_number" 
                               name="student_number" 
                               required 
                               placeholder="Örn: 2312903033"
                               autocomplete="off"
                               pattern="[0-9]{10}"
                               title="Sadece 10 haneli rakam girebilirsiniz">
                    </div>
                    
                    <div class="file-input-wrapper">
                        <label for="file">
                            Sınav Dosyanızı Seçin (.pka) <span class="required">*</span>
                        </label>
                        <input type="file" 
                               id="file" 
                               name="file" 
                               accept=".pka" 
                               required>
                    </div>
                    
                    <button type="submit" id="submitBtn">📤 Dosyayı Yükle</button>
                </form>
                
                <div id="progress-container">
                    <div id="progress-bar">0%</div>
                </div>
                
                <div id="status"></div>
                
                <a href="/" class="back-link">← Ana Sayfaya Dön</a>
            </div>
            
            <script>
                document.getElementById('uploadForm').addEventListener('submit', (e) => {
                    e.preventDefault();
                    
                    const submitBtn = document.getElementById('submitBtn');
                    const status = document.getElementById('status');
                    const form = e.target;
                    const formData = new FormData(form);
                    
                    const studentName = document.getElementById('student_name').value.trim();
                    const studentNumber = document.getElementById('student_number').value;
                    const file = document.getElementById('file').files[0];
                    
                    status.innerHTML = ''; // Önceki mesajları temizle
                    
                    // Ad Soyad doğrulaması
                    if (studentName.split(' ').length < 2) {
                        status.innerHTML = '<div class="status-message error">❌ Lütfen hem adınızı hem de soyadınızı girin!</div>';
                        return;
                    }
                    
                    // Öğrenci Numarası doğrulaması (10 hane rakam)
                    const numberPattern = /^[0-9]{10}$/;
                    if (!numberPattern.test(studentNumber)) {
                        status.innerHTML = '<div class="status-message error">❌ Öğrenci numarası tam 10 rakamdan oluşmalıdır!</div>';
                        return;
                    }

                    if (!file) {
                        status.innerHTML = '<div class="status-message error">❌ Lütfen bir dosya seçin!</div>';
                        return;
                    }
                    
                    if (!file.name.toLowerCase().endsWith('.pka')) {
                        status.innerHTML = '<div class="status-message error">❌ Sadece .pka dosyası yükleyebilirsiniz!</div>';
                        return;
                    }
                    
                    if (file.size > 50 * 1024 * 1024) { // 50MB max
                        status.innerHTML = '<div class="status-message error">❌ Dosya çok büyük! Maksimum 50MB olmalıdır.</div>';
                        return;
                    }
                    
                    submitBtn.disabled = true;
                    submitBtn.textContent = '⏳ Yükleniyor, lütfen bekleyin...';
                    
                    // Progress Bar'ı göster
                    const progressContainer = document.getElementById('progress-container');
                    const progressBar = document.getElementById('progress-bar');
                    progressContainer.style.display = 'block';
                    progressBar.style.width = '0%';
                    progressBar.textContent = '0%';

                    // XMLHttpRequest (Progress Bar için)
                    const xhr = new XMLHttpRequest();
                    
                    xhr.upload.onprogress = (event) => {
                        if (event.lengthComputable) {
                            const percentComplete = Math.round((event.loaded / event.total) * 100);
                            progressBar.style.width = percentComplete + '%';
                            progressBar.textContent = percentComplete + '%';
                        }
                    };
                    
                    xhr.onload = () => {
                        progressContainer.style.display = 'none'; // Tamamlanınca gizle
                        let result;
                        try {
                            result = JSON.parse(xhr.responseText);
                        } catch (err) {
                            status.innerHTML = '<div class="status-message error">❌ Sunucudan geçersiz yanıt alındı!</div>';
                            submitBtn.disabled = false;
                            submitBtn.textContent = '📤 Dosyayı Yükle';
                            return;
                        }

                        if (xhr.status === 200) {
                            status.innerHTML = '<div class="status-message success">✅ ' + result.message + '<br><br>Dosyanız başarıyla yüklendi. Bu sayfayı kapatabilirsiniz.</div>';
                            form.reset();
                            // Başarı durumunda buton metnini güncelle (zaten disabled)
                            submitBtn.textContent = '✅ Başarıyla Yüklendi';
                        } else {
                            status.innerHTML = '<div class="status-message error">❌ ' + (result.error || 'Bilinmeyen sunucu hatası') + '</div>';
                            submitBtn.disabled = false;
                            submitBtn.textContent = '📤 Dosyayı Yükle';
                        }
                    };
                    
                    xhr.onerror = () => {
                        progressContainer.style.display = 'none';
                        status.innerHTML = '<div class="status-message error">❌ Yükleme hatası: Sunucuya bağlanılamadı!</div>';
                        submitBtn.disabled = false;
                        submitBtn.textContent = '📤 Dosyayı Yükle';
                    };
                    
                    xhr.open('POST', '/upload', true);
                    xhr.send(formData);
                });
                
                // Enter tuşuyla form gönderimini engelle (kazara gönderim)
                document.getElementById('student_name').addEventListener('keypress', (e) => {
                    if (e.key === 'Enter') e.preventDefault();
                });
                document.getElementById('student_number').addEventListener('keypress', (e) => {
                    if (e.key === 'Enter') e.preventDefault();
                });
            </script>
        </body>
        </html>
        """
        self.wfile.write(html.encode('utf-8'))

    # GÜNCELLENDİ: IP yapılandırma sayfası (Aranabilir tabloyu entegre eder)
    def serve_ip_config_page(self):
        """
        IP yapılandırma sayfasını sunar.
        Eğer global EXCEL_DATA_HTML doluysa, formun üstünde aranabilir
        bir tablo gösterir.
        """
        global EXCEL_DATA_HTML
        
        self.send_response(200)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.end_headers()

        # --- Python'da Koşullu HTML ve JS Oluşturma ---
        html_excel_section = ""
        html_excel_script = ""

        if EXCEL_DATA_HTML:
            # 1. Gosterilecek HTML (Arama kutusu ve Tablo)
            html_excel_section = f"""
            <div class="form-group">
                <label for="searchBox">🔎 Hızlı IP Bul (Listede Ara):</label>
                <input type="text" id="searchBox" placeholder="Ad, Numara veya IP arayın..."
                       style="border-color: #f39c12; margin-bottom: 10px;">
            </div>
            <div class="table-container">
                {EXCEL_DATA_HTML}
            </div>
            <hr style="border:0; border-top: 2px solid #eee; margin: 25px 0;">
            """
            
            # 2. Bu HTML'i calistiracak JS (Arama ve Vurgulama)
            html_excel_script = """
            <script>
            const searchBox = document.getElementById('searchBox');
            const table = document.querySelector('.excel-table');
            if (table) {
                const rows = table.querySelectorAll('tbody tr');
                searchBox.addEventListener('keyup', function() {
                    const searchText = searchBox.value.toLowerCase();
                    rows.forEach(row => {
                        // Vurguyu kaldir
                        row.classList.remove('highlight');
                        
                        if (searchText === "") {
                            row.style.display = ""; // Tumunu goster
                        } else {
                            const rowText = row.textContent.toLowerCase();
                            if (rowText.includes(searchText)) {
                                row.style.display = ""; // Esleseni goster
                                row.classList.add('highlight'); // Vurgula
                            } else {
                                row.style.display = "none"; // Gizle
                            }
                        }
                    });
                });
            }
            </script>
            """
        # --- Ana HTML Şablonu ---
        # (Excel yüklü olmasa bile form her zaman görünür)
        html_template = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Sınav IP'si Ata</title>
            <style>
                * {{ margin: 0; padding: 0; box-sizing: border-box; }}
                
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    padding: 20px;
                }}
                
                .container {{
                    background: white;
                    padding: 40px;
                    border-radius: 20px;
                    box-shadow: 0 20px 60px rgba(0,0,0,0.3);
                    max-width: 800px;
                    width: 100%;
                }}
                
                h1 {{
                    color: #333;
                    text-align: center;
                    margin-bottom: 30px;
                    font-size: 28px;
                    font-weight: 600;
                }}
                
                .form-group {{ margin-bottom: 28px; }}
                
                label {{
                    display: block;
                    margin-bottom: 10px;
                    font-weight: 600;
                    color: #444;
                    font-size: 15px;
                }}
                
                input[type="text"] {{
                    width: 100%;
                    padding: 12px 15px;
                    border: 2px solid #e0e0e0;
                    border-radius: 8px;
                    font-size: 16px;
                    transition: border-color 0.2s ease;
                }}
                
                input[type="text"]:focus {{
                    outline: none;
                    border-color: #667eea;
                }}
                
                .button-grid {{
                    display: grid;
                    grid-template-columns: repeat(3, 1fr);
                    gap: 18px;
                    margin-top: 25px;
                }}
                
                button {{
                    padding: 15px;
                    background: #007bff;
                    color: white;
                    border: none;
                    border-radius: 10px;
                    font-size: 16px;
                    font-weight: 600;
                    cursor: pointer;
                    transition: all 0.2s ease;
                    box-shadow: 0 4px 12px rgba(0,123,255, 0.3);
                }}
                
                button:hover:not(:disabled) {{
                    background: #0056b3;
                    transform: translateY(-2px);
                    box-shadow: 0 6px 16px rgba(0,123,255, 0.4);
                }}
                
                button.linux {{
                    background: #f39c12;
                    box-shadow: 0 4px 12px rgba(243,156,18, 0.3);
                }}
                
                button.linux:hover:not(:disabled) {{
                    background: #e67e22;
                    box-shadow: 0 6px 16px rgba(243,156,18, 0.4);
                }}
                
                button.macos {{
                    background: #343a40;
                    box-shadow: 0 4px 12px rgba(52,58,64, 0.3);
                }}
                
                button.macos:hover:not(:disabled) {{
                    background: #23272b;
                    box-shadow: 0 6px 16px rgba(52,58,64, 0.4);
                }}
                
                .back-link {{
                    display: block;
                    text-align: center;
                    margin-top: 25px;
                    color: #667eea;
                    text-decoration: none;
                    font-weight: 600;
                }}
                
                .back-link:hover {{
                    text-decoration: underline;
                }}
                
                .info {{
                    background: #e3f2fd;
                    padding: 15px;
                    border-radius: 8px;
                    margin-bottom: 25px;
                    color: #1976d2;
                    border-left: 4px solid #2196F3;
                }}
                
                .status-message {{
                    padding: 15px;
                    border-radius: 8px;
                    margin-top: 20px;
                    font-weight: 600;
                    display: none;
                }}
                
                .success {{
                    background: #d4edda;
                    color: #155724;
                    border-left: 4px solid #28a745;
                }}
                
                .error {{
                    background: #f8d7da;
                    color: #721c24;
                    border-left: 4px solid #dc3545;
                }}
                
                .table-container {{
                    max-height: 300px;
                    overflow-y: auto;
                    border: 1px solid #ddd;
                    border-radius: 8px;
                    margin-bottom: 20px;
                }}
                
                table.excel-table {{
                    width: 100%;
                    border-collapse: collapse;
                }}
                
                table.excel-table th, table.excel-table td {{
                    padding: 10px 12px;
                    border: 1px solid #e0e0e0;
                    text-align: left;
                    font-size: 14px;
                }}
                
                table.excel-table th {{
                    background-color: #f9fafb;
                    position: sticky;
                    top: 0;
                    font-weight: 600;
                    color: #555;
                }}
                
                table.excel-table tbody tr:nth-child(even) {{
                    background-color: #fcfcfc;
                }}
                
                table.excel-table tbody tr:hover {{
                    background-color: #f0f4ff;
                }}
                
                table.excel-table tr.highlight {{
                    background-color: #fffb8f !important;
                    font-weight: 600;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>📡 Sınav Ağı IP Yapılandırma</h1>
                
                {html_excel_section}
                
                <div class="info">
                    <strong>ℹ️ Script Nasıl Kullanılır:</strong><br>
                    1. (Varsa) listeden IP'nizi bulun ve kopyalayın.<br>
                    2. IP'yi aşağıdaki forma yapıştırın.<br>
                    3. İşletim sisteminize uygun butona basın.<br>
                    4. İndirilen dosyayı <strong>Yönetici (Admin)</strong> olarak çalıştırın.
                </div>
                
                <form id="ipForm" action="/generate-script" method="GET" target="_blank">
                    <div class="form-group">
                        <label for="ip_address">Atanacak IP Adresiniz:</label>
                        <input type="text" 
                               id="ip_address" 
                               name="ip" 
                               required 
                               placeholder="Örn: 192.168.1.5"
                               autocomplete="off"
                               pattern="^192\\.168\\.[1-3]\\.(?!0$|1$|255$)\\d{{1,3}}$"
                               title="IP Adresi 192.168.1.X, 2.X veya 3.X formatında olmalı (X, 2-254 arası bir sayı)">
                    </div>
                    
                    <div class="button-grid">
                        <button type="submit" name="os" value="win" id="winBtn">
                            💾 Windows (.bat)
                        </button>
                        <button type="submit" name="os" value="linux" class="linux" id="linuxBtn">
                            🐧 Linux (.sh)
                        </button>
                        <button type="submit" name="os" value="macos" class="macos" id="macosBtn">
                            💻 macOS (.sh)
                        </button>
                    </div>
                </form>
                
                <div id="status" class="status-message success">
                    ✅ Script indiriliyor...<br>
                    Lütfen indirilen dosyayı <strong>Yönetici olarak</strong> çalıştırın!
                </div>
                
                <a href="/" class="back-link">← Ana Sayfaya Dön</a>
            </div>
            
            <script>
                const ipInput = document.getElementById('ip_address');
                const winBtn = document.getElementById('winBtn');
                const linuxBtn = document.getElementById('linuxBtn');
                const macosBtn = document.getElementById('macosBtn');
                const status = document.getElementById('status');
                
                const ipPattern = /^192\\.168\\.[1-3]\\.\\d{{1,3}}$/;
                
                function validateAndShowSuccess(e) {{
                    if (ipPattern.test(ipInput.value)) {{
                        const parts = ipInput.value.split('.');
                        const lastOctet = parseInt(parts[3], 10);
                        if (lastOctet >= 2 && lastOctet <= 254) {{
                            status.style.display = 'block';
                            return; // Form gönderimine izin ver
                        }}
                    }}
                    // Geçerli değilse
                    e.preventDefault(); // Formu göndermeyi engelle
                    status.style.display = 'none';
                    ipInput.focus();
                    alert("Lütfen geçerli bir IP adresi girin (Örn: 192.168.1.5). 192.168.1.X, 2.X veya 3.X olmalı (X, 2-254 arası).");
                }}

                winBtn.addEventListener('click', validateAndShowSuccess);
                linuxBtn.addEventListener('click', validateAndShowSuccess);
                macosBtn.addEventListener('click', validateAndShowSuccess);
            </script>
            
            {html_excel_script}
            
        </body>
        </html>
        """
        self.wfile.write(html_template.encode('utf-8'))
    
    # GÜNCELLENDİ: v3.1 BAT Scripti (Dinamik Tespit)
    def handle_script_generation(self):
        """Kullanıcının IP ve OS seçimine göre config script'i oluşturur ve gönderir."""
        
        try:
            parsed_path = urlparse(self.path)
            query = parse_qs(parsed_path.query)
            
            ip_address = query.get('ip', [None])[0]
            os_type = query.get('os', [None])[0]

            # Güvenlik ve Doğrulama
            if not ip_address or not os_type:
                self.send_error(400, "Eksik parametre (ip veya os)")
                return
            
            ip_match = re.match(r"^192\.168\.([1-3])\.(\d{1,3})$", ip_address)
            if not ip_match:
                self.send_error(400, "Geçersiz IP formatı. Sadece 192.168.[1-3].X kullanılabilir.")
                return
                
            last_octet = int(ip_match.group(2)) # Grup 2 artık son oktet
            if not (2 <= last_octet <= 254):
                 self.send_error(400, "Geçersiz IP adresi. IP, .2 ile .254 arasında olmalıdır.")
                 return

            if os_type not in ['win', 'linux', 'macos']:
                self.send_error(400, "Geçersiz işletim sistemi tipi.")
                return

            script_content = ""
            filename = ""
            mime_type = "text/plain" # Hata olmaması için varsayılan
            
            # Ağ Ayarları
            SUBNET = "255.255.255.0"
            subnet_prefix = f"192.168.{ip_match.group(1)}"
            GATEWAY = f"{subnet_prefix}.1"
            DNS = f"{subnet_prefix}.1"

            if os_type == 'win':
                filename = f"ayarla_IP_{ip_address}.bat"
                mime_type = "application/bat"
                # GÜNCELLENDİ: v3.2 Script (Geliştirilmiş Hata Yönetimi ve Adaptör Tespiti)
                # Windows 10 ve 11'de çalışacak şekilde optimize edildi
                script_content = f"""@echo off
setlocal enabledelayedexpansion
color 0A
title IP Ataniyor...

echo    =================================================================
echo.
echo      _______ ___ ___ _______ _______      ___ ___ _______ _______ 
echo     ^|   _   ^|   Y   ^|   _   ^|   _   ^|    ^|   Y   ^|   _   ^|   _   ^|
echo     ^|.  ^|   ^|.  ^|   ^|.  1___^|.  1___^|    ^|.  ^|   ^|.  1___^|.  ^|   ^|
echo     ^|.  ^|   ^|.  ^|   ^|.  ^|___^|.  ^|___     ^|.  ^|   ^|.  ^|___^|.  ^|   ^|
echo     ^|:  1   ^|:  1   ^|:  1   ^|:  1   ^|    ^|:  1   ^|:  1   ^|:  1   ^|
echo     ^|::.. . ^|::.. . ^|::.. . ^|::.. . ^|    ^|::.. . ^|::.. . ^|::.. . ^|
echo     `-------'`-------'`-------'`-------'    `-------'`-------'`-------'
echo.
echo                    Sinav Agi IP Yapilandirmasi
echo    =================================================================
echo.
echo    Bu script, ag ayarlarini yonetici olarak yapilandiracaktir.
echo.

rem --- YONETICI YETKISI KONTROLU ---
net session >nul 2>&1
if %errorlevel% neq 0 (
    color 0C
    echo    ==================================================
    echo     HATA: Bu script YONETICI yetkisi gerektirir!
    echo.
    echo     Lutfen dosyaya sag tiklayip
    echo     "Yonetici olarak calistir" secenegini secin.
    echo    ==================================================
    pause
    exit /b 1
)

echo    Yonetici yetkisi kontrol edildi: OK
echo.
echo    Aktif ag arayuzu algilaniyor...
echo.

rem --- GELISTIRILMIS ARAYUZ TESPITI ---
set "IF_NAME="
set "IF_FOUND=0"

rem Oncelik 1: Wi-Fi adaptorunu bul
for /f "tokens=2 delims=:" %%a in ('netsh wlan show interfaces 2^>nul ^| findstr /C:"Name"') do (
    set "TEMP_NAME=%%a"
    set "TEMP_NAME=!TEMP_NAME:~1!"
    if not "!TEMP_NAME!"=="" (
        set "IF_NAME=!TEMP_NAME!"
        set "IF_FOUND=1"
        goto :ArayuzBulundu
    )
)

rem Oncelik 2: Ethernet adaptorunu bul
if !IF_FOUND! equ 0 (
    for /f "skip=3 tokens=1,4*" %%a in ('netsh interface show interface') do (
        if "%%a"=="Enabled" (
            set "IF_NAME=%%c"
            if not "!IF_NAME!"=="" (
                set "IF_FOUND=1"
                goto :ArayuzBulundu
            )
        )
    )
)

rem Oncelik 3: Basit yontemle herhangi bir bagli arayuz
if !IF_FOUND! equ 0 (
    for /f "tokens=*" %%a in ('netsh interface show interface ^| findstr /I "Connected Bagli"') do (
        for /f "tokens=4*" %%b in ("%%a") do (
            set "IF_NAME=%%b"
            if not "!IF_NAME!"=="" (
                set "IF_FOUND=1"
                goto :ArayuzBulundu
            )
        )
    )
)

:ArayuzBulundu
if !IF_FOUND! equ 0 (
    color 0C
    echo    ==================================================
    echo     HATA: Aktif bir ag arayuzu bulunamadi!
    echo.
    echo     Mevcut arayuzler:
    netsh interface show interface
    echo.
    echo     Lutfen ag baglantinizin acik oldugundan emin olun.
    echo    ==================================================
    pause
    exit /b 1
)

echo    Bulunan Arayuz: "!IF_NAME!"
echo    --------------------------------------------------
echo.
echo    IP Adresi: {ip_address}
echo    Alt Ag Maskesi: {SUBNET}
echo    Ag Gecidi: {GATEWAY}
echo    DNS Sunucu: {DNS}
echo.
echo    Ayarlar uygulanacak, lutfen bekleyin...
echo.

rem --- IP ADRESI ATAMA ---
echo    [1/2] IP adresi ve ag gecidi ayarlaniyor...
netsh interface ip set address name="!IF_NAME!" static {ip_address} {SUBNET} {GATEWAY} 1 >nul 2>&1

rem Alternatif yontem de dene
netsh interface ipv4 set address name="!IF_NAME!" source=static address={ip_address} mask={SUBNET} gateway={GATEWAY} >nul 2>&1

echo    IP adresi atandi.

rem --- DNS AYARLAMA ---
echo    [2/2] DNS sunucu ayarlaniyor...
netsh interface ip set dns name="!IF_NAME!" static {DNS} primary >nul 2>&1
if !errorlevel! neq 0 (
    netsh interface ipv4 set dnsservers name="!IF_NAME!" static {DNS} primary >nul 2>&1
)

echo    DNS ayarlandi.
echo.
echo    IP ayarlarinin sisteme kaydedilmesi bekleniyor...
timeout /t 3 /nobreak >nul
echo.

rem --- BASARILI (IP atama hata vermedigine gore basarili) ---
color 0A
echo    ==================================================
echo     BASARILI: IP ayarlari uygulandı!
echo.
echo     Arayuz: !IF_NAME!
echo     IP Adresi: {ip_address}
echo     Alt Ag Maskesi: {SUBNET}
echo     Ag Gecidi: {GATEWAY}
echo     DNS Sunucu: {DNS}
echo.
echo     Dogrulama yapiliyor...
echo    ==================================================
echo.

rem Gercek IP adresini goster
echo    Mevcut IP Ayarlari:
netsh interface ip show address name="!IF_NAME!"
echo.
echo    ===================================================
echo.

set "IP_ATANDI=EVET"

if "!IP_ATANDI!"=="EVET" (
    color 0A
    echo    Islem tamamlandi!
    echo    Bu pencere 10 saniye icinde kapanacak...
    timeout /t 10 /nobreak >nul
    exit /b 0
) else (
    goto :HataDurumu
)

:HataDurumu
color 0C
echo    ==================================================
echo     HATA: IP adresi ATANAMADI!
echo.
echo     Denenen Arayuz: "!IF_NAME!"
echo.
echo     Olasi Nedenler:
echo     - Arayuz adi yanlis olabilir
echo     - Arayuz devre disi olabilir
echo     - Ag kartinda sorun olabilir
echo.
echo     Manuel Cozum:
echo     1. Windows tusu + R ye basin
echo     2. "ncpa.cpl" yazin ve Enter'a basin
echo     3. Ilgili arayuze sag tiklayin
echo     4. "Ozellikler" secenegini secin
echo     5. "Internet Protokolu Versiyon 4 (TCP/IPv4)" secin
echo     6. Manuel olarak IP ayarlarini girin
echo.
echo     Ag Baglantilari aciliyor...
echo    ==================================================
start ncpa.cpl
pause
exit /b 1
"""
            elif os_type == 'linux':
                filename = f"ayarla_IP_{ip_address}.sh"
                mime_type = "application/x-sh"
                script_content = f"""#!/bin/bash
INTERFACE="wlan0" # DIKKAT: Arayuz adiniz farkliysa (orn: wlp2s0) burayi duzenleyin!

echo "=========================================================="
echo " Sinav Agi IP Yapilandirmasi (Linux)"
echo "=========================================================="
echo ""
echo "  Hedef Arayuz: $INTERFACE"
echo "  IP Adresi:    {ip_address}/24"
echo "  Ag Gecidi:    {GATEWAY}"
echo "  DNS Sunucusu: {DNS}"
echo ""
echo "  Not: Bu script 'sudo' ile (root) calistirilmalidir."
echo "=========================================================="
echo ""

if [ "$EUID" -ne 0 ]; then 
  echo "Lutfen bu scripti sudo ile calistirin!"
  exit 1
fi

echo "Mevcut IP adresleri temizleniyor ($INTERFACE)..."
ip addr flush dev $INTERFACE

echo "Yeni IP adresi ekleniyor..."
ip addr add {ip_address}/24 dev $INTERFACE

echo "Arayuz aktiflestiriliyor..."
ip link set dev $INTERFACE up

echo "Varsayilan Ag Gecidi (Gateway) ayarlaniyor..."
# Mevcut default'u sil (varsa)
ip route del default 2>/dev/null
ip route add default via {GATEWAY}

echo "DNS Sunucusu (/etc/resolv.conf) ayarlaniyor..."
echo "nameserver {DNS}" > /etc/resolv.conf

echo ""
echo "Islem tamamlandi. Guncel yapilandirma:"
echo "----------------------------------------------------------"
ip addr show $INTERFACE | grep 'inet '
ip route | grep 'default'
cat /etc/resolv.conf
echo "=========================================================="
echo "Basariyla IP adresiniz atanmistir = {ip_address}"
"""
            elif os_type == 'macos':
                filename = f"ayarla_IP_{ip_address}.sh"
                mime_type = "application/x-sh"
                script_content = f"""#!/bin/bash
INTERFACE="Wi-Fi" # DIKKAT: Arayuz adiniz "Ethernet" ise burayi duzenleyin.

echo "=========================================================="
echo " Sinav Agi IP Yapilandirmasi (macOS)"
echo "=========================================================="
echo ""
echo "  Hedef Arayuz: $INTERFACE"
echo "  IP Adresi:    {ip_address}"
echo "  Alt Ag Mask:  {SUBNET}"
echo "  Ag Gecidi:  {GATEWAY}"
echo "  DNS Sunucusu: {DNS}"
echo ""
echo "  Not: Bu script 'sudo' ile (yonetici) calistirilmalidir."
echo "=========================================================="
echo ""

if [ "$EUID" -ne 0 ]; then 
  echo "Lutfen bu scripti sudo ile calistirin (sudo ./dosya_adi.sh)"
  exit 1
fi

echo "IP adresi, Subnet ve Gateway ayarlaniyor..."
networksetup -setmanual "$INTERFACE" {ip_address} {SUBNET} {GATEWAY}

echo "DNS Sunuculari ayarlaniyor..."
networksetup -setdnsservers "$INTERFACE" {DNS}

echo ""
echo "Islem tamamlandi. Guncel yapilandirma:"
echo "----------------------------------------------------------"
networksetup -getinfo "$INTERFACE"
echo "=========================================================="
echo "Basariyla IP adresiniz atanmistir = {ip_address}"
"""

            # Dosyayı kullanıcıya gönder
            # GÜNCELLENDİ: .bat dosyaları için 'cp1254' encoding kullan
            file_encoding = 'utf-8'
            if os_type == 'win':
                file_encoding = 'cp1254' # Windows Turkish Code Page
                
            encoded_content = script_content.encode(file_encoding, errors='replace')
            
            self.send_response(200)
            self.send_header('Content-Type', f'{mime_type}; charset={file_encoding}')
            self.send_header('Content-Disposition', f'attachment; filename="{filename}"')
            self.send_header('Content-Length', str(len(encoded_content)))
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.end_headers()
            self.wfile.write(encoded_content)

        except Exception as e:
            print(f"❌ Script oluşturma hatası: {str(e)}")
            self.send_error(500, "Sunucu Hatası: Script oluşturulamadı.")
    
    def serve_pem_file(self):
        """PEM dosyasını güvenli şekilde sun"""
        global PEM_FILE_PATH, PEM_DOWNLOAD_COUNT, PEM_DOWNLOADS
        
        try:
            if not PEM_FILE_PATH or not os.path.isfile(PEM_FILE_PATH):
                self.send_error(404, "File Not Found")
                return
            
            if not PEM_FILE_PATH.lower().endswith('.pem'):
                self.send_error(403, "Invalid File Type")
                return
            
            with open(PEM_FILE_PATH, 'rb') as f:
                content = f.read()
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/x-pem-file')
            self.send_header('Content-Disposition', f'attachment; filename="public.pem"')
            self.send_header('Content-Length', str(len(content)))
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.end_headers()
            self.wfile.write(content)
            
            PEM_DOWNLOAD_COUNT += 1
            
            # YENİ: İndirme loguna ekle
            download_time = datetime.now()
            PEM_DOWNLOADS.append({
                'ip': self.client_address[0],
                'time': download_time.strftime('%Y-%m-%d %H:%M:%S')
            })
            
            write_terminal_log("="*70)
            write_terminal_log(f"✅ PEM dosyası indirildi: {self.client_address[0]}")
            write_terminal_log(f"📊 Toplam PEM dosyası indirenler: {PEM_DOWNLOAD_COUNT}")
            write_terminal_log("="*70 + "\n")
            
        except Exception as e:
            write_terminal_log(f"❌ PEM dosyası hatası: {str(e)}")
            self.send_error(500, "Internal Server Error")

    # YENİ: Veyon Setup dosyasını sunar
    def serve_veyon_setup(self):
        """Veyon Setup (.exe) dosyasını güvenli şekilde sun"""
        global VEYON_SETUP_PATH, VEYON_SETUP_FILENAME, VEYON_DOWNLOAD_COUNT, VEYON_DOWNLOADS
        
        try:
            if not VEYON_SETUP_PATH or not os.path.isfile(VEYON_SETUP_PATH):
                self.send_error(404, "File Not Found (Veyon Setup)")
                return
            
            with open(VEYON_SETUP_PATH, 'rb') as f:
                content = f.read()
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/octet-stream')
            self.send_header('Content-Disposition', f'attachment; filename="{VEYON_SETUP_FILENAME}"')
            self.send_header('Content-Length', str(len(content)))
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.end_headers()
            self.wfile.write(content)
            
            VEYON_DOWNLOAD_COUNT += 1
            
            # YENİ: İndirme loguna ekle
            download_time = datetime.now()
            VEYON_DOWNLOADS.append({
                'ip': self.client_address[0],
                'time': download_time.strftime('%Y-%m-%d %H:%M:%S')
            })
            
            write_terminal_log("="*70)
            write_terminal_log(f"✅ Veyon Setup indirildi: {self.client_address[0]}")
            write_terminal_log(f"📊 Toplam Veyon Setup indirenler: {VEYON_DOWNLOAD_COUNT}")
            write_terminal_log("="*70 + "\n")
            
        except Exception as e:
            write_terminal_log(f"❌ Veyon Setup dosyası hatası: {str(e)}")
            self.send_error(500, "Internal Server Error")
    
    # YENİ: Admin Dashboard (sadece 127.0.0.1) - GENİŞLETİLMİŞ VERSİYON
    def serve_admin_dashboard(self):
        """Tüm aktiviteleri gösteren kapsamlı admin dashboard'u (sadece localhost)"""
        # Güvenlik: Sadece 127.0.0.1'den erişilebilir
        if self.client_address[0] != "127.0.0.1":
            self.send_error(403, "Access Denied - Bu sayfa sadece localhost'tan erişilebilir")
            return
        
        global SCAPY_AVAILABLE
        
        self.send_response(200)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.end_headers()
        
        # Scapy kontrolü
        scapy_status = "✅ Hazır" if SCAPY_AVAILABLE else "❌ Scapy yüklü değil (pip install scapy)"
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <meta http-equiv="refresh" content="5">
            <title>Admin Dashboard - Tüm Aktiviteler</title>
            <style>
                * {{ margin: 0; padding: 0; box-sizing: border-box; }}
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    min-height: 100vh;
                    padding: 20px;
                }}
                .container {{
                    max-width: 1800px;
                    margin: 0 auto;
                    background: white;
                    padding: 40px;
                    border-radius: 20px;
                    box-shadow: 0 20px 60px rgba(0,0,0,0.3);
                }}
                h1 {{
                    color: #333;
                    margin-bottom: 10px;
                    font-size: 32px;
                }}
                .subtitle {{
                    color: #666;
                    margin-bottom: 25px;
                    font-size: 14px;
                }}
                .stats-grid {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
                    gap: 20px;
                    margin-bottom: 35px;
                }}
                .stat-card {{
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    padding: 25px 20px;
                    border-radius: 15px;
                    text-align: center;
                    box-shadow: 0 6px 20px rgba(0,0,0,0.15);
                    transition: transform 0.3s ease, box-shadow 0.3s ease;
                }}
                .stat-card:hover {{
                    transform: translateY(-5px);
                    box-shadow: 0 10px 30px rgba(0,0,0,0.2);
                }}
                .stat-card h3 {{
                    font-size: 13px;
                    opacity: 0.95;
                    margin-bottom: 12px;
                    font-weight: 500;
                }}
                .stat-card .number {{
                    font-size: 38px;
                    font-weight: 700;
                    margin-bottom: 8px;
                }}
                .section {{
                    margin-bottom: 45px;
                    background: #fafafa;
                    padding: 25px;
                    border-radius: 12px;
                    border: 1px solid #e0e0e0;
                }}
                .section-title {{
                    font-size: 24px;
                    color: #333;
                    margin-bottom: 20px;
                    padding-bottom: 12px;
                    border-bottom: 3px solid #667eea;
                    font-weight: 600;
                }}
                .status-box {{
                    background: #f0f7ff;
                    padding: 15px;
                    border-radius: 8px;
                    margin-bottom: 20px;
                    border-left: 4px solid #2196F3;
                }}
                .scan-button {{
                    padding: 12px 25px;
                    background: linear-gradient(135deg, #4CAF50, #45a049);
                    color: white;
                    border: none;
                    border-radius: 10px;
                    font-size: 16px;
                    font-weight: 600;
                    cursor: pointer;
                    transition: all 0.3s;
                    margin-bottom: 15px;
                }}
                .scan-button:hover:not(:disabled) {{
                    transform: translateY(-2px);
                    box-shadow: 0 5px 15px rgba(76, 175, 80, 0.4);
                }}
                .scan-button:disabled {{
                    background: #cccccc;
                    cursor: not-allowed;
                }}
                .table-container {{
                    overflow-x: auto;
                    margin-top: 15px;
                }}
                table {{
                    width: 100%;
                    border-collapse: collapse;
                    font-size: 14px;
                }}
                th, td {{
                    padding: 12px 15px;
                    text-align: left;
                    border-bottom: 1px solid #e0e0e0;
                }}
                th {{
                    background-color: #f9fafb;
                    font-weight: 600;
                    color: #555;
                    font-size: 13px;
                    text-transform: uppercase;
                    position: sticky;
                    top: 0;
                }}
                tbody tr:nth-child(even) {{
                    background-color: #fcfcfc;
                }}
                tbody tr:hover {{
                    background-color: #f0f4ff;
                }}
                .badge {{
                    display: inline-block;
                    padding: 4px 10px;
                    border-radius: 12px;
                    font-size: 11px;
                    font-weight: 600;
                }}
                .badge-red {{
                    background: #ffebee;
                    color: #c00;
                }}
                .badge-purple {{
                    background: #f3e5f5;
                    color: #6a1b9a;
                }}
                .badge-yellow {{
                    background: #fffde7;
                    color: #795548;
                }}
                .duplicate-number-row {{
                    background-color: #fffde7 !important;
                }}
                .duplicate-number-row:hover {{
                    background-color: #fff9c4 !important;
                }}
                .no-data {{
                    text-align: center;
                    padding: 40px;
                    color: #999;
                    font-style: italic;
                }}
                .back-link {{
                    display: inline-block;
                    margin-top: 20px;
                    color: #667eea;
                    text-decoration: none;
                    font-weight: 600;
                }}
                .back-link:hover {{
                    text-decoration: underline;
                }}
                .refresh-info {{
                    text-align: right;
                    color: #999;
                    font-size: 12px;
                    margin-bottom: 20px;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>📊 Admin Dashboard - Tüm Aktiviteler</h1>
                <p class="subtitle">Sınav sistemi aktivite takibi ve ağ cihazları</p>
                <p class="refresh-info">🔄 Sayfa otomatik olarak 5 saniyede bir yenilenir</p>
                
                <div id="alertBox" style="display:none; background:#ffebee; color:#c00; padding:15px; border-radius:8px; margin-bottom:20px; border-left:4px solid #c00; font-weight:600;">
                    🚨 <span id="alertText"></span>
                </div>
                
                <div class="stats-grid" id="statsGrid" style="grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));">
                    <div class="stat-card" style="background: linear-gradient(135deg, #4CAF50 0%, #45a049 100%);">
                        <h3>📤 Toplam Yükleme</h3>
                        <div class="number" id="totalUploads">0</div>
                        <div style="font-size:12px; opacity:0.8; margin-top:5px;">Benzersiz: <span id="uniqueUploaders">0</span></div>
                    </div>
                    <div class="stat-card" style="background: linear-gradient(135deg, #2196F3 0%, #0b7dda 100%);">
                        <h3>🔑 PEM İndirme</h3>
                        <div class="number" id="totalPemDownloads">0</div>
                        <div style="font-size:12px; opacity:0.8; margin-top:5px;">Benzersiz: <span id="uniquePemDownloaders">0</span></div>
                    </div>
                    <div class="stat-card" style="background: linear-gradient(135deg, #00bcd4 0%, #0097a7 100%);">
                        <h3>🖥️ Veyon İndirme</h3>
                        <div class="number" id="totalVeyonDownloads">0</div>
                    </div>
                    <div class="stat-card" style="background: linear-gradient(135deg, #f44336 0%, #d32f2f 100%);">
                        <h3>🔴 Kopya Dosya</h3>
                        <div class="number" id="duplicateFiles">0</div>
                        <div style="font-size:20px; margin-top:5px;" id="duplicateBadge">⚠️</div>
                    </div>
                    <div class="stat-card" style="background: linear-gradient(135deg, #9c27b0 0%, #7b1fa2 100%);">
                        <h3>🟣 Boş Sınav</h3>
                        <div class="number" id="emptyExamFiles">0</div>
                        <div style="font-size:20px; margin-top:5px;" id="emptyExamBadge">⚠️</div>
                    </div>
                </div>
                
                <div class="section">
                    <h2 class="section-title">📤 Dosya Yükleyenler (Son 50)</h2>
                    <div class="table-container">
                        <table id="uploadsTable">
                            <thead>
                                <tr>
                                    <th>#</th>
                                    <th>Zaman</th>
                                    <th>Ad Soyad</th>
                                    <th>Numara</th>
                                    <th>Dosya</th>
                                    <th>Boyut</th>
                                    <th>IP</th>
                                    <th>SHA256 Hash</th>
                                    <th>Durum</th>
                                </tr>
                            </thead>
                            <tbody id="uploadsBody">
                                <tr><td colspan="9" class="no-data">Yükleniyor...</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>
                
                <div class="section">
                    <h2 class="section-title">🔑 PEM Dosyası İndirenler (Son 50)</h2>
                    <div class="table-container">
                        <table id="pemTable">
                            <thead>
                                <tr>
                                    <th>#</th>
                                    <th>Zaman</th>
                                    <th>IP Adresi</th>
                                    <th>Hostname</th>
                                </tr>
                            </thead>
                            <tbody id="pemBody">
                                <tr><td colspan="4" class="no-data">Yükleniyor...</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>
                
                <div class="section">
                    <h2 class="section-title">🖥️ Veyon Setup İndirenler (Son 50)</h2>
                    <div class="table-container">
                        <table id="veyonTable">
                            <thead>
                                <tr>
                                    <th>#</th>
                                    <th>Zaman</th>
                                    <th>IP Adresi</th>
                                    <th>Hostname</th>
                                </tr>
                            </thead>
                            <tbody id="veyonBody">
                                <tr><td colspan="4" class="no-data">Yükleniyor...</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>
                
                <div class="section">
                    <h2 class="section-title">🖥️ Ağ Cihazları</h2>
                    <div class="status-box">
                        <strong>Durum:</strong> {scapy_status}<br>
                        <strong>Son Tarama:</strong> <span id="lastScan">Henüz tarama yapılmadı</span><br>
                        <strong>Bulunan Cihaz:</strong> <span id="deviceCount">0</span>
                    </div>
                    <button class="scan-button" id="scanBtn" onclick="scanNetwork()">
                        🔍 Ağı Tara
                    </button>
                    <div class="table-container">
                        <table id="clientsTable">
                            <thead>
                                <tr>
                                    <th>#</th>
                                    <th>IP Adresi</th>
                                    <th>MAC Adresi</th>
                                    <th>Hostname</th>
                                </tr>
                            </thead>
                            <tbody id="clientsBody">
                                <tr>
                                    <td colspan="4" class="no-data">Henüz tarama yapılmadı. "Ağı Tara" butonuna tıklayın.</td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>
                
                <a href="/" class="back-link">← Ana Sayfaya Dön</a>
            </div>
            
            <script>
                function loadDashboardData() {{
                    fetch('/admin/data')
                        .then(response => response.json())
                        .then(data => {{
                            // İstatistikler
                            document.getElementById('totalUploads').textContent = data.stats.total_uploads;
                            document.getElementById('totalPemDownloads').textContent = data.stats.total_pem_downloads;
                            document.getElementById('totalVeyonDownloads').textContent = data.stats.total_veyon_downloads;
                            document.getElementById('uniqueUploaders').textContent = data.stats.unique_uploaders || 0;
                            document.getElementById('uniquePemDownloaders').textContent = data.stats.unique_pem_downloaders || 0;
                            document.getElementById('duplicateFiles').textContent = data.stats.duplicate_files || 0;
                            document.getElementById('emptyExamFiles').textContent = data.stats.empty_exam_files || 0;
                            
                            // Kopya dosya badge'leri
                            const duplicateBadge = document.getElementById('duplicateBadge');
                            const emptyExamBadge = document.getElementById('emptyExamBadge');
                            if (data.stats.duplicate_files > 0) {{
                                duplicateBadge.innerHTML = '⚠️'.repeat(Math.min(data.stats.duplicate_files, 5));
                            }} else {{
                                duplicateBadge.innerHTML = '';
                            }}
                            if (data.stats.empty_exam_files > 0) {{
                                emptyExamBadge.innerHTML = '⚠️'.repeat(Math.min(data.stats.empty_exam_files, 5));
                            }} else {{
                                emptyExamBadge.innerHTML = '';
                            }}
                            
                            // Alert'leri topla
                            const alertBox = document.getElementById('alertBox');
                            const alertText = document.getElementById('alertText');
                            let alerts = [];
                            
                            // DDoS/DoS Alert
                            if (data.ddos_alerts && data.ddos_alerts.length > 0) {{
                                data.ddos_alerts.forEach(alert => {{
                                    alerts.push(`🚨 DDoS/DoS TESPİT EDİLDİ! IP: ${{alert.ip}} - 10 saniyede ${{alert.count}} istek`);
                                }});
                            }}
                            
                            // Kopya dosya alert'i
                            if (data.stats.duplicate_files > 0) {{
                                alerts.push(`🔴 UYARI: ${{data.stats.duplicate_files}} adet kopya dosya tespit edildi!`);
                            }}
                            
                            // Boş sınav alert'i
                            if (data.stats.empty_exam_files > 0) {{
                                alerts.push(`🟣 UYARI: ${{data.stats.empty_exam_files}} adet boş sınav dosyası tespit edildi!`);
                            }}
                            
                            // Aynı numara ile tekrar yükleme alert'i
                            const numberCounts = {{}};
                            data.uploads.forEach(upload => {{
                                const num = upload.number || '';
                                numberCounts[num] = (numberCounts[num] || 0) + 1;
                            }});
                            const duplicateNumbers = Object.keys(numberCounts).filter(num => numberCounts[num] > 1);
                            if (duplicateNumbers.length > 0) {{
                                alerts.push(`🟡 UYARI: ${{duplicateNumbers.length}} öğrenci numarası ile birden fazla yükleme yapıldı!`);
                            }}
                            
                            // Aynı IP'den tekrar yükleme alert'i
                            const ipCounts = {{}};
                            data.uploads.forEach(upload => {{
                                const ip = upload.ip || '';
                                ipCounts[ip] = (ipCounts[ip] || 0) + 1;
                            }});
                            const duplicateIPs = Object.keys(ipCounts).filter(ip => ipCounts[ip] > 1);
                            if (duplicateIPs.length > 0) {{
                                alerts.push(`🟡 UYARI: ${{duplicateIPs.length}} IP adresinden birden fazla yükleme yapıldı!`);
                            }}
                            
                            if (alerts.length > 0) {{
                                alertText.innerHTML = alerts.join('<br>');
                                alertBox.style.display = 'block';
                            }} else {{
                                alertBox.style.display = 'none';
                            }}
                            
                            // Yüklemeler
                            const uploadsBody = document.getElementById('uploadsBody');
                            if (data.uploads.length === 0) {{
                                uploadsBody.innerHTML = '<tr><td colspan="9" class="no-data">Henüz yükleme yapılmadı.</td></tr>';
                            }} else {{
                                // Aynı numara ve aynı IP kontrolü için sayım
                                const numberCounts = {{}};
                                const ipCounts = {{}};
                                data.uploads.forEach(upload => {{
                                    const num = upload.number || '';
                                    const ip = upload.ip || '';
                                    numberCounts[num] = (numberCounts[num] || 0) + 1;
                                    ipCounts[ip] = (ipCounts[ip] || 0) + 1;
                                }});
                                
                                let html = '';
                                data.uploads.forEach((upload, index) => {{
                                    let badges = '';
                                    let rowClass = '';
                                    
                                    if (upload.is_duplicate_hash) {{
                                        badges += '<span class="badge badge-red">🔴 Kopya</span> ';
                                    }}
                                    if (upload.matches_reference_exam) {{
                                        badges += '<span class="badge badge-purple">🟣 Boş Sınav</span> ';
                                    }}
                                    
                                    // Aynı numara kontrolü (sarı işaretleme)
                                    const num = upload.number || '';
                                    if (numberCounts[num] > 1) {{
                                        rowClass = 'duplicate-number-row';
                                        badges += '<span class="badge badge-yellow">🟡 Tekrar Yükleme</span> ';
                                    }}
                                    
                                    // Aynı IP kontrolü (sarı işaretleme)
                                    const ip = upload.ip || '';
                                    if (ipCounts[ip] > 1) {{
                                        rowClass = 'duplicate-number-row';
                                        badges += '<span class="badge badge-yellow">🟡 Aynı IP</span> ';
                                    }}
                                    
                                    const fileSize = upload.file_size_formatted || (upload.file_size ? formatBytes(upload.file_size) : '-');
                                    const sha256 = upload.sha256 || '-';
                                    html += `
                                        <tr class="${{rowClass}}">
                                            <td>${{index + 1}}</td>
                                            <td>${{upload.time}}</td>
                                            <td>${{upload.name}}</td>
                                            <td>${{upload.number}}</td>
                                            <td>${{upload.filename}}</td>
                                            <td>${{fileSize}}</td>
                                            <td>${{upload.ip}}</td>
                                            <td style="font-family: monospace; font-size: 11px; word-break: break-all; max-width: 200px;">${{sha256}}</td>
                                            <td>${{badges || '-'}}</td>
                                        </tr>
                                    `;
                                }});
                                uploadsBody.innerHTML = html;
                            }}
                            
                            // PEM İndirmeler
                            const pemBody = document.getElementById('pemBody');
                            if (data.pem_downloads.length === 0) {{
                                pemBody.innerHTML = '<tr><td colspan="4" class="no-data">Henüz PEM indirilmedi.</td></tr>';
                            }} else {{
                                let html = '';
                                data.pem_downloads.forEach((dl, index) => {{
                                    // Hostname'i network_clients'ten bul
                                    let hostname = 'Bilinmiyor';
                                    if (data.network_clients && data.network_clients.length > 0) {{
                                        const client = data.network_clients.find(c => c.ip === dl.ip);
                                        if (client) {{
                                            hostname = client.hostname || 'Bilinmiyor';
                                        }}
                                    }}
                                    html += `
                                        <tr>
                                            <td>${{index + 1}}</td>
                                            <td>${{dl.time}}</td>
                                            <td>${{dl.ip}}</td>
                                            <td>${{hostname}}</td>
                                        </tr>
                                    `;
                                }});
                                pemBody.innerHTML = html;
                            }}
                            
                            // Veyon İndirmeler
                            const veyonBody = document.getElementById('veyonBody');
                            if (data.veyon_downloads.length === 0) {{
                                veyonBody.innerHTML = '<tr><td colspan="4" class="no-data">Henüz Veyon Setup indirilmedi.</td></tr>';
                            }} else {{
                                let html = '';
                                data.veyon_downloads.forEach((dl, index) => {{
                                    // Hostname'i network_clients'ten bul
                                    let hostname = 'Bilinmiyor';
                                    if (data.network_clients && data.network_clients.length > 0) {{
                                        const client = data.network_clients.find(c => c.ip === dl.ip);
                                        if (client) {{
                                            hostname = client.hostname || 'Bilinmiyor';
                                        }}
                                    }}
                                    html += `
                                        <tr>
                                            <td>${{index + 1}}</td>
                                            <td>${{dl.time}}</td>
                                            <td>${{dl.ip}}</td>
                                            <td>${{hostname}}</td>
                                        </tr>
                                    `;
                                }});
                                veyonBody.innerHTML = html;
                            }}
                            
                            // Ağ Cihazları
                            if (data.network_clients && data.network_clients.length > 0) {{
                                document.getElementById('deviceCount').textContent = data.network_clients.length;
                                const clientsBody = document.getElementById('clientsBody');
                                let html = '';
                                data.network_clients.forEach((client, index) => {{
                                    html += `
                                        <tr>
                                            <td>${{index + 1}}</td>
                                            <td>${{client.ip}}</td>
                                            <td>${{client.mac || 'Bilinmiyor'}}</td>
                                            <td>${{client.hostname || 'Bilinmiyor'}}</td>
                                        </tr>
                                    `;
                                }});
                                clientsBody.innerHTML = html;
                            }}
                        }})
                        .catch(error => {{
                            console.error('Dashboard verisi yüklenirken hata:', error);
                        }});
                }}
                
                function scanNetwork() {{
                    const btn = document.getElementById('scanBtn');
                    const body = document.getElementById('clientsBody');
                    
                    btn.disabled = true;
                    body.innerHTML = '<tr><td colspan="4" class="no-data">⏳ Tarama yapılıyor...</td></tr>';
                    
                    fetch('/admin/scan')
                        .then(response => response.json())
                        .then(data => {{
                            btn.disabled = false;
                            
                            if (data.error) {{
                                body.innerHTML = `<tr><td colspan="4" class="no-data">❌ Hata: ${{data.error}}</td></tr>`;
                                return;
                            }}
                            
                            document.getElementById('lastScan').textContent = new Date().toLocaleString('tr-TR');
                            document.getElementById('deviceCount').textContent = data.clients.length;
                            
                            if (data.clients.length === 0) {{
                                body.innerHTML = '<tr><td colspan="4" class="no-data">Cihaz bulunamadı.</td></tr>';
                                return;
                            }}
                            
                            let html = '';
                            data.clients.forEach((client, index) => {{
                                html += `
                                    <tr>
                                        <td>${{index + 1}}</td>
                                        <td>${{client.ip}}</td>
                                        <td>${{client.mac || 'Bilinmiyor'}}</td>
                                        <td>${{client.hostname || 'Bilinmiyor'}}</td>
                                    </tr>
                                `;
                            }});
                            body.innerHTML = html;
                            // Tarama sonrası dashboard'u yenile
                            loadDashboardData();
                        }})
                        .catch(error => {{
                            btn.disabled = false;
                            body.innerHTML = `<tr><td colspan="4" class="no-data">❌ Hata: ${{error.message}}</td></tr>`;
                        }});
                }}
                
                // Dosya boyutu formatlama fonksiyonu
                function formatBytes(bytes) {{
                    if (!bytes) return '-';
                    if (bytes < 1024) return bytes + ' B';
                    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(2) + ' KB';
                    if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
                    return (bytes / (1024 * 1024 * 1024)).toFixed(2) + ' GB';
                }}
                
                // Sayfa yüklendiğinde ve her 5 saniyede bir verileri yükle
                loadDashboardData();
                setInterval(loadDashboardData, 5000);
            </script>
        </body>
        </html>
        """
        self.wfile.write(html.encode('utf-8'))
    
    # YENİ: Dashboard verileri endpoint'i (sadece 127.0.0.1)
    def serve_admin_data(self):
        """Dashboard için tüm verileri JSON olarak döner (sadece localhost)"""
        # Güvenlik: Sadece 127.0.0.1'den erişilebilir
        if self.client_address[0] != "127.0.0.1":
            self.send_json_response(403, {'error': 'Access Denied - Bu endpoint sadece localhost\'tan erişilebilir'})
            return
        
        global UPLOAD_COUNT, PEM_DOWNLOAD_COUNT, VEYON_DOWNLOAD_COUNT
        global ALL_UPLOADS, PEM_DOWNLOADS, VEYON_DOWNLOADS, NETWORK_CLIENTS, REQUEST_LOGS
        
        # Upload'ları ters sırada gönder (en yeni en üstte)
        uploads_sorted = sorted(ALL_UPLOADS, key=lambda x: x.get('time', ''), reverse=True)
        
        # PEM ve Veyon indirmelerini sırala (en yeni en üstte) - sadece 'time' string'ini kullan
        pem_downloads_sorted = sorted(PEM_DOWNLOADS, key=lambda x: x.get('time', ''), reverse=True)[:50]
        veyon_downloads_sorted = sorted(VEYON_DOWNLOADS, key=lambda x: x.get('time', ''), reverse=True)[:50]
        
        # YENİ: Kopya dosya sayısını hesapla
        duplicate_count = sum(1 for upload in ALL_UPLOADS if upload.get('is_duplicate_hash', False))
        empty_exam_count = sum(1 for upload in ALL_UPLOADS if upload.get('matches_reference_exam', False))
        
        # YENİ: Benzersiz yükleyen sayısı (IP bazlı)
        unique_uploaders = len(set(upload.get('ip', '') for upload in ALL_UPLOADS))
        unique_pem_downloaders = len(set(dl.get('ip', '') for dl in PEM_DOWNLOADS))
        
        # YENİ: DDoS/DoS tespiti - Son 10 saniyede 50'den fazla istek yapan IP'ler
        current_time = time.time()
        ddos_ips = []
        for ip, req_times in REQUEST_LOGS.items():
            recent_requests = [t for t in req_times if current_time - t < 10]
            if len(recent_requests) > 50:
                ddos_ips.append({'ip': ip, 'count': len(recent_requests)})
        
        self.send_json_response(200, {
            'stats': {
                'total_uploads': UPLOAD_COUNT,
                'total_pem_downloads': PEM_DOWNLOAD_COUNT,
                'total_veyon_downloads': VEYON_DOWNLOAD_COUNT,
                'unique_uploaders': unique_uploaders,
                'unique_pem_downloaders': unique_pem_downloaders,
                'duplicate_files': duplicate_count,
                'empty_exam_files': empty_exam_count
            },
            'uploads': uploads_sorted[:50],  # Son 50 yükleme
            'pem_downloads': pem_downloads_sorted,
            'veyon_downloads': veyon_downloads_sorted,
            'network_clients': NETWORK_CLIENTS,
            'ddos_alerts': ddos_ips  # YENİ: DDoS/DoS uyarıları
        })
    
    # YENİ: Ağ taraması endpoint'i (sadece 127.0.0.1)
    def handle_network_scan(self):
        """Ağ taraması yapar ve JSON döner (sadece localhost)"""
        # Güvenlik: Sadece 127.0.0.1'den erişilebilir
        if self.client_address[0] != "127.0.0.1":
            self.send_json_response(403, {'error': 'Access Denied - Bu endpoint sadece localhost\'tan erişilebilir'})
            return
        
        global NETWORK_CLIENTS, SCAPY_AVAILABLE
        
        if not SCAPY_AVAILABLE:
            self.send_json_response(500, {'error': 'Scapy kütüphanesi yüklü değil. Lütfen "pip install scapy" komutunu çalıştırın.'})
            return
        
        try:
            clients = scan_network()
            NETWORK_CLIENTS = clients
            self.send_json_response(200, {'clients': clients, 'count': len(clients)})
        except (ConnectionAbortedError, BrokenPipeError, OSError) as e:
            # Client bağlantıyı kapattı, normal bir durum
            write_terminal_log(f"ℹ️  Client bağlantıyı kapattı: {str(e)}")
            return  # Hata mesajı göndermeye gerek yok
        except Exception as e:
            write_terminal_log(f"❌ Ağ taraması hatası: {str(e)}")
            try:
                self.send_json_response(500, {'error': f'Tarama hatası: {str(e)}'})
            except (ConnectionAbortedError, BrokenPipeError, OSError):
                return  # Client bağlantıyı kapattı
    
    def do_POST(self):
        """POST isteklerini güvenli şekilde işle - Sadece upload"""
        # YENİ: DDoS/DoS kontrolü
        if self.check_ddos():
            self.send_error(429, "Too Many Requests - DDoS/DoS tespit edildi!")
            return
        
        # GÜNCELLENDİ: Mükerrer tespiti için SEEN_HASHES_MAP kullanılıyor
        global UPLOAD_COUNT, UPLOADED_IPS, ALL_UPLOADS, SEEN_HASHES_MAP
        
        # Sadece /upload yoluna izin ver
        if self.path != '/upload':
            self.send_error(403, "Access Denied")
            return
            
        try:
            client_ip = self.client_address[0]

            # Rate Limiting
            now = datetime.now()
            if client_ip in UPLOADED_IPS:
                recent_uploads = [t['time'] for t in UPLOADED_IPS[client_ip] 
                                  if t['time'] > (now - timedelta(minutes=10))]
                if len(recent_uploads) >= 5:
                    self.send_json_response(429, {'error': 'Çok fazla deneme! Lütfen 10 dakika sonra tekrar deneyin.'})
                    print(f"⚠️ Rate Limit Aşıldı: {client_ip}")
                    return

            content_type = self.headers.get('Content-Type', '')
            if 'multipart/form-data' not in content_type:
                self.send_json_response(400, {'error': 'Geçersiz içerik tipi'})
                return
            
            form = cgi.FieldStorage(
                fp=self.rfile,
                headers=self.headers,
                environ={'REQUEST_METHOD': 'POST'}
            )
            
            if 'file' not in form or 'student_name' not in form or 'student_number' not in form:
                self.send_json_response(400, {'error': 'Eksik bilgi! Tüm alanları doldurun.'})
                return
            
            student_name = form['student_name'].value.strip()
            student_number = form['student_number'].value.strip()
            file_item = form['file']
            
            # YENİ: Ad Soyad'ı büyük harfe çevir
            student_name = student_name.upper()
            
            # Validasyonlar
            if not student_name or not student_number:
                self.send_json_response(400, {'error': 'İsim ve numara boş olamaz!'})
                return
            
            if len(student_name.split()) < 2:
                self.send_json_response(400, {'error': 'Lütfen hem adınızı hem de soyadınızı girin!'})
                return

            if not (student_number.isdigit() and len(student_number) == 10):
                self.send_json_response(400, {'error': 'Öğrenci numarası tam 10 rakamdan oluşmalıdır!'})
                return
            
            if len(student_name) > 100:
                self.send_json_response(400, {'error': 'İsim çok uzun!'})
                return
            
            if not file_item.filename:
                self.send_json_response(400, {'error': 'Dosya seçilmedi!'})
                return
            
            if not file_item.filename.lower().endswith('.pka'):
                self.send_json_response(400, {'error': 'Sadece .pka dosyası yükleyebilirsiniz!'})
                return
            
            file_data = file_item.file.read()
            file_size = len(file_data)
            
            if file_size > 50 * 1024 * 1024: # 50MB
                self.send_json_response(400, {'error': 'Dosya çok büyük! Maksimum 50MB.'})
                return
            
            # SHA256 Checksum
            sha256_hash = hashlib.sha256(file_data).hexdigest()
            
            # GÜNCELLENDİ: Mükerrer Hash Kontrolü (Ilk dosyayı da isaretler)
            is_duplicate_hash = False
            
            if sha256_hash in SEEN_HASHES_MAP:
                is_duplicate_hash = True
                original_index = SEEN_HASHES_MAP[sha256_hash]
                # Eger ilk dosya zaten kirmizi degilse, onu kirmizi yap
                if not ALL_UPLOADS[original_index]['is_duplicate_hash']:
                    ALL_UPLOADS[original_index]['is_duplicate_hash'] = True
            else:
                # Bu hash'i ilk kez görüyoruz. Mevcut index'i (listeye eklenmeden önceki uzunluk) kaydet.
                SEEN_HASHES_MAP[sha256_hash] = len(ALL_UPLOADS)
            
            # YENİ: Boş sınav tespiti (Referans hash ile karşılaştır)
            matches_reference_exam = False
            if REFERENCE_EXAM_HASH and sha256_hash == REFERENCE_EXAM_HASH:
                matches_reference_exam = True

            # Güvenli dosya adı oluştur
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            safe_name = "".join(c for c in student_name if c.isalnum() or c in (' ', '-', '_')).strip()
            safe_name = safe_name.replace(' ', '_')
            filename = f"{student_number}_{safe_name}_{timestamp}.pka"
            
            filename = os.path.basename(filename)
            filepath = os.path.join(UPLOAD_DIR, filename)
            
            if not os.path.abspath(filepath).startswith(os.path.abspath(UPLOAD_DIR)):
                self.send_json_response(403, {'error': 'Güvenlik ihlali tespit edildi!'})
                print(f"⚠️ Güvenlik uyarısı: Path traversal denemesi - {client_ip}")
                return
            
            with open(filepath, 'wb') as f:
                f.write(file_data)
            
            UPLOAD_COUNT += 1
            
            upload_time_obj = datetime.now()
            
            if client_ip not in UPLOADED_IPS:
                UPLOADED_IPS[client_ip] = []
            UPLOADED_IPS[client_ip].append({
                'name': student_name,
                'number': student_number,
                'time': upload_time_obj
            })
            
            # Log girdisine mükerrer bayrağını ekle
            log_entry_data = {
                'time': upload_time_obj.strftime('%Y-%m-%d %H:%M:%S'),
                'name': student_name,
                'number': student_number,
                'filename': filename,
                'ip': client_ip,
                'sha256': sha256_hash,
                'file_size': file_size,  # YENİ: Dosya boyutu (byte)
                'file_size_formatted': format_file_size(file_size),  # YENİ: Formatlanmış boyut
                'is_duplicate_hash': is_duplicate_hash, # Bu dosyanin durumu
                'matches_reference_exam': matches_reference_exam # Boş sınav kontrolü
            }
            ALL_UPLOADS.append(log_entry_data)
            
            log_file_html = os.path.join(UPLOAD_DIR, '_yukleme_kayitlari.html')
            # Her zaman HTML'i guncelle, bu hem kirmizi hem sari vurgulari
            # (ve siralamayi) aninda uygular.
            update_html_log(log_file_html, ALL_UPLOADS)
            
            self.send_json_response(200, {
                'message': f'Dosyanız başarıyla kaydedildi!\n{student_name} ({student_number})',
                'filename': filename
            })
            
            # CANLI LOG
            write_terminal_log("\n" + "="*70)
            upload_time_str = upload_time_obj.strftime('%H:%M %d.%m.%Y')
            upload_count_from_ip = len(UPLOADED_IPS[client_ip])
            
            if upload_count_from_ip > 1:
                write_terminal_log(f"⚠️  {student_name} sınavını yükledi - {upload_time_str} [{client_ip}]")
                write_terminal_log(f"❗ UYARI: Bu öğrenci dosyasını {upload_count_from_ip} kez yükledi!")
            else:
                write_terminal_log(f"✅ {student_name} sınavını yükledi - {upload_time_str} [{client_ip}]")
            
            write_terminal_log(f"   • Dosya: {filename}")
            write_terminal_log(f"   • Boyut: {format_file_size(file_size)}")
            write_terminal_log(f"   • Hash: {sha256_hash}")
            
            # Mükerrer dosya için terminal uyarısı
            if is_duplicate_hash:
                write_terminal_log(f"🔴 UYARI: Bu dosya, içerik olarak daha önce yüklenmiş bir dosyanın aynısı!")
            
            # YENİ: Boş sınav dosyası için terminal uyarısı
            if matches_reference_exam:
                write_terminal_log(f"🟣 UYARI: Bu dosya, referans boş sınav dosyası ile aynı! (Boş sınav tespit edildi)")
                
            write_terminal_log(f"📊 Toplam sınav yüklenen: {UPLOAD_COUNT}")
            write_terminal_log("="*70 + "\n")
            
        except Exception as e:
            write_terminal_log(f"❌ Upload hatası: {str(e)}")
            try:
                self.send_json_response(500, {'error': 'Sunucu hatası! Lütfen hocaya bildirin.'})
            except (ConnectionAbortedError, BrokenPipeError, OSError):
                return
    
    def send_json_response(self, status_code, data):
        """JSON yanıt gönder"""
        try:
            self.send_response(status_code)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.end_headers()
            self.wfile.write(json.dumps(data, ensure_ascii=False).encode('utf-8'))
        except (ConnectionAbortedError, BrokenPipeError, OSError):
            # Client bağlantıyı kapattı, normal bir durum
            return
    
    def log_message(self, format, *args):
        """Sadece bizim loglarımızı göster, HTTP GET/POST loglarını sustur"""
        return

def select_pem_file():
    """PEM dosyası seçme GUI"""
    root = tk.Tk()
    root.withdraw()
    root.attributes('-topmost', True)
    print("\n🔑 Adım 1: Veyon Public Key Seçimi")
    print("=" * 60)
    file_path = filedialog.askopenfilename(
        title="Veyon Public Key (.pem) Dosyasını Seçin",
        filetypes=[("PEM Dosyaları", "*.pem"), ("Tüm Dosyalar", "*.*")]
    )
    root.destroy()
    if not file_path:
        print("❌ PEM dosyası seçilmedi! Program sonlandırılıyor.")
        sys.exit(1)
    if not os.path.isfile(file_path):
        print("❌ Seçilen dosya bulunamadı!")
        sys.exit(1)
    print(f"✅ PEM dosyası seçildi: {file_path}")
    return file_path

def select_upload_directory():
    """Upload klasörü seçme GUI"""
    root = tk.Tk()
    root.withdraw()
    root.attributes('-topmost', True)
    print("\n📁 Adım 2: Sınav Dosyalarının Kaydedileceği Klasör")
    print("=" * 60)
    directory = filedialog.askdirectory(
        title="Öğrencilerin Dosyalarını Kaydedeceğiniz Klasörü Seçin"
    )
    root.destroy()
    if not directory:
        print("❌ Klasör seçilmedi! Program sonlandırılıyor.")
        sys.exit(1)
    if not os.path.isdir(directory):
        print("❌ Seçilen klasör bulunamadı!")
        sys.exit(1)
    print(f"✅ Upload klasörü seçildi: {directory}")
    return directory

# YENİ: İsteğe bağlı Excel dosyası seçme
def select_excel_file_optional():
    """İsteğe bağlı IP Listesi (Excel) seçme GUI"""
    global EXCEL_DATA_HTML
    
    root = tk.Tk()
    root.withdraw()
    root.attributes('-topmost', True)
    print("\n📊 Adım 4: (İSTEĞE BAĞLI) Öğrenci IP Listesi (Excel)")
    print("=" * 60)
    
    file_path = filedialog.askopenfilename(
        title="İsteğe bağlı IP Atama Listesi (Excel) Seçin (İptal edebilirsiniz)",
        filetypes=[("Excel Dosyaları", "*.xlsx *.xls"), ("Tüm Dosyalar", "*.*")]
    )
    root.destroy()
    
    if not file_path:
        print("ℹ️ Excel dosyası seçilmedi. IP Atama sayfası manuel giriş moduyla çalışacak.")
        return
    
    if not os.path.isfile(file_path):
        print("❌ Seçilen Excel dosyası bulunamadı! (Atlanıyor)")
        return
        
    # Excel'i işle ve HTML'e dönüştür
    try:
        print(f"Okunuyor: {file_path}")
        # GÜNCELLENDİ: 'openpyxl' motorunu açıkça belirtmek uyumluluğu artırır
        df = pd.read_excel(file_path, engine='openpyxl')
        # Sadece HTML 'table' kısmını, class'ı ve border'ı ayarla
        EXCEL_DATA_HTML = df.to_html(classes='excel-table', border=0, index=False)
        print(f"✅ Excel dosyası başarıyla okundu ve {len(df)} satır HTML'e dönüştürüldü.")
    except Exception as e:
        print(f"❌ Excel dosyası okunurken hata oluştu: {e}")
        print("ℹ️ IP Atama sayfası manuel giriş moduyla çalışacak.")
        EXCEL_DATA_HTML = None

# YENİ: İsteğe bağlı Veyon setup dosyası seçme
def select_veyon_setup_optional():
    """İsteğe bağlı Veyon Setup (.exe) seçme GUI"""
    global VEYON_SETUP_PATH, VEYON_SETUP_FILENAME
    
    root = tk.Tk()
    root.withdraw()
    root.attributes('-topmost', True)
    print("\n🖥️ Adım 5: (İSTEĞE BAĞLI) Veyon Setup Dosyası")
    print("=" * 60)
    
    file_path = filedialog.askopenfilename(
        title="İsteğe bağlı Veyon Setup (.exe) Seçin (İptal edebilirsiniz)",
        filetypes=[("Veyon Setup", "*.exe"), ("Tüm Dosyalar", "*.*")]
    )
    root.destroy()
    
    if not file_path:
        print("ℹ️ Veyon Setup dosyası seçilmedi. İndirme butonu devre dışı olacak.")
        return
    
    if not os.path.isfile(file_path):
        print("❌ Seçilen Veyon Setup dosyası bulunamadı! (Atlanıyor)")
        return
        
    VEYON_SETUP_PATH = file_path
    VEYON_SETUP_FILENAME = os.path.basename(file_path)
    print(f"✅ Veyon Setup dosyası seçildi: {VEYON_SETUP_FILENAME}")

# YENİ: İsteğe bağlı referans sınav dosyası seçme
def select_reference_exam_file_optional():
    """İsteğe bağlı referans boş sınav dosyası (.pka) seçme GUI"""
    global REFERENCE_EXAM_HASH, REFERENCE_EXAM_FILENAME
    
    root = tk.Tk()
    root.withdraw()
    root.attributes('-topmost', True)
    print("\n📝 Adım 3: (İSTEĞE BAĞLI) Referans Boş Sınav Dosyası")
    print("=" * 60)
    
    file_path = filedialog.askopenfilename(
        title="İsteğe bağlı Referans Boş Sınav Dosyası (.pka) Seçin (İptal edebilirsiniz)",
        filetypes=[("Sınav Dosyaları", "*.pka"), ("Tüm Dosyalar", "*.*")]
    )
    root.destroy()
    
    if not file_path:
        print("ℹ️ Referans sınav dosyası seçilmedi. Boş sınav tespiti devre dışı olacak.")
        return
    
    if not os.path.isfile(file_path):
        print("❌ Seçilen referans sınav dosyası bulunamadı! (Atlanıyor)")
        return
    
    try:
        # Dosyanın hash'ini hesapla
        with open(file_path, 'rb') as f:
            file_data = f.read()
        REFERENCE_EXAM_HASH = hashlib.sha256(file_data).hexdigest()
        REFERENCE_EXAM_FILENAME = os.path.basename(file_path)
        print(f"✅ Referans sınav dosyası seçildi: {REFERENCE_EXAM_FILENAME}")
        print(f"   • SHA256 Hash: {REFERENCE_EXAM_HASH[:12]}...")
        print(f"   • Bu hash ile aynı dosyalar mor renk ile işaretlenecek (boş sınav)")
    except Exception as e:
        print(f"❌ Referans sınav dosyası okunurken hata oluştu: {e}")
        print("ℹ️ Boş sınav tespiti devre dışı olacak.")
        REFERENCE_EXAM_HASH = None
        REFERENCE_EXAM_FILENAME = None


def main():
    global PEM_FILE_PATH, UPLOAD_DIR, TERMINAL_LOG_FILE
    
    print("""
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║     🎓 GÜVENLİ SINAV DOSYA TOPLAMA SİSTEMİ (v3.1) 🎓         ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
    """)
    
    PEM_FILE_PATH = select_pem_file()
    UPLOAD_DIR = select_upload_directory()
    
    # YENİ: İsteğe bağlı referans sınav dosyasını seçtir
    select_reference_exam_file_optional()
    
    # YENİ: İsteğe bağlı Excel dosyasını seçtir
    select_excel_file_optional()
    
    # YENİ: İsteğe bağlı Veyon Setup dosyasını seçtir
    select_veyon_setup_optional()
    
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    
    # YENİ: Terminal log dosyasını başlat
    TERMINAL_LOG_FILE = os.path.join(UPLOAD_DIR, 'terminal_kayitlari.log')
    write_terminal_log(f"\n{'='*70}")
    write_terminal_log("📝 Terminal log dosyası başlatıldı")
    write_terminal_log(f"📁 Log dosyası: {TERMINAL_LOG_FILE}")
    write_terminal_log(f"{'='*70}\n")
    
    # OPTIMIZASYON: Sunucu başlarken eski kayıtları yükle
    load_previous_uploads(UPLOAD_DIR)
    
    local_ip = get_local_ip()
    
    write_terminal_log("\n" + "=" * 70)
    write_terminal_log("✅ SUNUCU HAZIRLANDI!")
    write_terminal_log("=" * 70)
    write_terminal_log(f"""
📋 SUNUCU BİLGİLERİ:
  • Server Adresi: http://{local_ip}:{PORT}
  • PEM Dosyası: {os.path.basename(PEM_FILE_PATH)}
  • Upload Klasörü: {UPLOAD_DIR}
  • Referans Sınav: {REFERENCE_EXAM_FILENAME if REFERENCE_EXAM_FILENAME else 'Seçilmedi (Boş sınav tespiti devre dışı)'}
  • IP Listesi (Excel): {'Yüklendi (Aranabilir tablo aktif)' if EXCEL_DATA_HTML else 'Yüklenmedi (Manuel mod aktif)'}
  • Veyon Setup: {VEYON_SETUP_FILENAME if VEYON_SETUP_FILENAME else 'Yüklenmedi (Buton devre dışı)'}
  • Admin Dashboard: http://127.0.0.1:{PORT}/admin/clients (Sadece localhost)
  • Terminal Log: {TERMINAL_LOG_FILE}

👨‍🎓 ÖĞRENCİLERE SÖYLEYİN:
  1. Tarayıcıda şu adrese gidin: http://{local_ip}
  2. (Gerekirse) "Veyon Setup Dosyasını İndir" butonunu kullanın.
  3. "Sınav IP'si Ata" butonunu kullanın (Listeye bakın, aratın ve scripti indirin).
  4. "Veyon PEM Anahtarını İndir" butonuna tıklayın ve Veyon'a yükleyin.
  5. Sınavı bitirince "Sınav Dosyası Yükle" butonuna tıklayın.
  6. Formu (10 haneli no) doldurup dosyayı yükleyin.

Sunucu çalışıyor... (Durdurmak için Ctrl+C)
    """)
    write_terminal_log("=" * 70)
    write_terminal_log(f"\n📊 CANLI TAKİP (HTML Log: {os.path.join(UPLOAD_DIR, '_yukleme_kayitlari.html')})\n")
    
    # ThreadingServer kullan
    server = ThreadingServer(('0.0.0.0', PORT), SecureExamHandler)
    
    # YENİ: Admin dashboard'u otomatik aç
    admin_url = f"http://127.0.0.1:{PORT}/admin/clients"
    print(f"\n🌐 Admin Dashboard otomatik olarak açılıyor: {admin_url}")
    try:
        webbrowser.open(admin_url)
    except Exception as e:
        print(f"⚠️ Tarayıcı otomatik açılamadı: {e}")
        print(f"   Lütfen manuel olarak şu adresi açın: {admin_url}")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        write_terminal_log("\n\n" + "=" * 70)
        write_terminal_log("✋ Sunucu kapatılıyor...")
        write_terminal_log("=" * 70)
        server.shutdown()
        
        write_terminal_log(f"\n📊 ÖZET RAPOR:")
        write_terminal_log(f"  • Toplam PEM indirme: {PEM_DOWNLOAD_COUNT}")
        write_terminal_log(f"  • Toplam sınav yükleme: {UPLOAD_COUNT}")
        
        if UPLOADED_IPS:
            duplicate_uploads = {ip: data for ip, data in UPLOADED_IPS.items() if len(data) > 1}
            if duplicate_uploads:
                write_terminal_log(f"\n⚠️  TEKRAR YÜKLEME YAPANLAR (Aynı IP):")
                for ip, uploads in duplicate_uploads.items():
                    write_terminal_log(f"  • {ip}: {len(uploads)} kez yükleme yapıldı")
        
        # Mükerrer hash'leri say
        duplicate_hash_count = 0
        for entry in ALL_UPLOADS:
            if entry.get('is_duplicate_hash', False):
                duplicate_hash_count += 1
        
        if duplicate_hash_count > 0:
            write_terminal_log(f"\n🔴 MÜKERRER DOSYA (Aynı İçerik):")
            write_terminal_log(f"  • Toplam {duplicate_hash_count} adet aynı içerikli (kopya) dosya yüklendi.")
            write_terminal_log(f"  • Detaylar için kırmızı satırlara bakınız: _yukleme_kayitlari.html")

        log_file = os.path.join(UPLOAD_DIR, '_yukleme_kayitlari.html')
        if os.path.exists(log_file):
            write_terminal_log(f"\n📁 Toplam kaydedilen dosya (unique isim): {len(ALL_UPLOADS)}")
        
        write_terminal_log("\n✅ Sunucu başarıyla kapatıldı.")
        write_terminal_log(f"📁 HTML Log burada: {log_file}")
        write_terminal_log(f"📁 Dosyalar burada: {UPLOAD_DIR}")
        write_terminal_log(f"📁 Terminal Log burada: {TERMINAL_LOG_FILE}")

if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print(f"\n❌ GENEL HATA: {str(e)}")
        input("\nKapatmak için Enter'a basın...")
        sys.exit(1)