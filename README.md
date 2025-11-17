# 🎓 Güvenli Sınav Dosya Toplama Sistemi (v1.1)

Modern ve güvenli bir sınav dosyası toplama ve yönetim sistemi. Öğrencilerin sınav dosyalarını yüklemesini, IP yapılandırmasını ve tüm aktivitelerin takibini sağlar.

---

## 📋 İçindekiler

- [Özellikler](#-özellikler)
- [Kurulum](#-kurulum)
- [Kullanım](#-kullanım)
- [Sayfalar ve Endpoint'ler](#-sayfalar-ve-endpointler)
- [Güvenlik Özellikleri](#-güvenlik-özellikleri)
- [Admin Dashboard](#-admin-dashboard)
- [Teknik Detaylar](#-teknik-detaylar)
- [Sorun Giderme](#-sorun-giderme)
- [Destek](#-destek)

---

## ✨ Özellikler

### 📤 Dosya Yükleme

* **Güvenli Dosya Yükleme**: Sadece `.pka` uzantılı dosyalar kabul edilir
* **SHA256 Hash Kontrolü**: Her dosya için SHA256 hash hesaplanır ve kaydedilir
* **Mükerrer Dosya Tespiti**: Aynı içeriğe sahip dosyalar otomatik tespit edilir (kırmızı işaretleme)
* **Boş Sınav Tespiti**: Referans boş sınav dosyası ile karşılaştırma yapılır (mor işaretleme)
* **Ad Soyad Otomatik Büyük Harf**: Kullanıcı girişi otomatik olarak büyük harfe çevrilir
* **Progress Bar**: Dosya yükleme sırasında gerçek zamanlı ilerleme gösterimi
* **Rate Limiting**: IP başına 10 dakikada maksimum 5 yükleme

### 📡 IP Yapılandırma

* **Dinamik IP Atama**: Windows, Linux ve macOS için otomatik script oluşturma
* **Esnek IP Desteği**: `192.168.1.x`, `192.168.2.x` ve `192.168.3.x` ağları desteklenir
* **Dinamik Gateway**: IP adresine göre otomatik gateway belirleme (`192.168.x.1`)
* **Excel Entegrasyonu**: Öğrenci listesi Excel'den yüklenebilir ve IP'ler hızlıca bulunabilir
* **IP Çakışma Kontrolü**: Aynı IP'nin birden fazla kişiye atanmasını engeller
* **IP Durumu Takibi**: Atanan IP'lerin aktif/pasif durumu ve hostname bilgisi

### 🔑 Veyon Entegrasyonu

* **PEM Anahtarı İndirme**: Veyon için gerekli PEM dosyasını indirme
* **Veyon Setup İndirme**: Veyon kurulum dosyasını indirme (opsiyonel)
* **İndirme Takibi**: Tüm indirmeler loglanır ve admin dashboard'da görüntülenir

### 📊 Admin Dashboard

* **Gerçek Zamanlı İzleme**: Tüm aktiviteler 5 saniyede bir otomatik güncellenir
* **İstatistikler**: Toplam yükleme, indirme, kopya dosya sayıları
* **Detaylı Loglar**: Tüm yüklemeler, indirmeler ve ağ cihazları listelenir
* **Hostname Gösterimi**: PEM ve Veyon indirenlerin hostname'leri gösterilir (tarama yapıldıysa)
* **SHA256 Hash Görüntüleme**: Her dosya için tam SHA256 hash'i görüntülenir
* **Sarı İşaretleme**:
    * Aynı öğrenci numarasıyla birden fazla yükleme
    * Aynı IP'den birden fazla yükleme
* **Alert Sistemi**:
    * DDoS/DoS saldırı uyarıları
    * Kopya dosya uyarıları
    * Boş sınav uyarıları
    * Tekrar yükleme arıları

### 🖥️ Ağ Taraması

* **Otomatik Cihaz Tespiti**: Scapy kullanarak ağdaki cihazları tespit eder
* **MAC Adresi**: Her cihazın MAC adresi gösterilir
* **Hostname Çözümleme**: IP adreslerinden hostname bilgisi alınır
* **Manuel Tarama**: Admin dashboard'dan manuel tarama yapılabilir

### 🔒 Güvenlik Özellikleri

* **DDoS/DoS Koruması**: 10 saniyede 50'den fazla istek yapan IP'ler engellenir
* **Rate Limiting**: IP bazlı istek sınırlaması
* **Path Traversal Koruması**: Dosya yükleme güvenliği
* **Admin Erişim Kontrolü**: Admin dashboard sadece `localhost`'tan erişilebilir
* **Thread-Safe Logging**: Çoklu bağlantı desteği ile güvenli log yazma

### 📝 Loglama ve Raporlama

* **HTML Log Dosyası**: Tüm yüklemeler HTML formatında kaydedilir
* **Terminal Logları**: Tüm aktiviteler terminal log dosyasına yazılır
* **SHA256 Hash Kayıtları**: Her dosyanın tam hash'i loglarda görüntülenir
* **Renkli İşaretleme**:
    * 🔴 Kırmızı: Kopya dosyalar
    * 🟡 Sarı: Tekrar yüklemeler (aynı numara/IP)
    * 🟣 Mor: Boş sınav dosyaları

---

## 🚀 Kurulum

### Gereksinimler

```bash
pip install pandas openpyxl
pip install scapy  # Opsiyonel: Ağ taraması için
```

### Başlatma
Python dosyasını çalıştırın:
```bash
python ExamFlowSystem.py
```

Adımları takip edin:

    Adım 1: PEM dosyasını seçin

    Adım 2: Yükleme klasörünü seçin

    Adım 3: (Opsiyonel) Referans boş sınav dosyasını seçin

    Adım 4: (Opsiyonel) Excel öğrenci listesini seçin

    Adım 5: (Opsiyonel) Veyon Setup dosyasını seçin

Sunucu otomatik olarak başlar ve IP adresini gösterir.

### 📖 Kullanım

Öğrenci Tarafı

    Ana Sayfa: Tarayıcıda sunucu IP'sine gidin

    IP Atama (Gerekirse):

        "Sınav IP'si Ata" butonuna tıklayın

        IP adresinizi girin (192.168.1.x, 2.x veya 3.x formatında)

        İşletim sisteminize uygun script'i indirin

        Script'i Yönetici olarak çalıştırın

    Veyon Kurulumu (Gerekirse):

        "Veyon Setup Dosyasını İndir" butonuna tıklayın

        İndirilen dosyayı kurun

    PEM Anahtarı:

        "Veyon PEM Anahtarını İndir" butonuna tıklayın

        PEM dosyasını Veyon'a yükleyin

    Dosya Yükleme:

        "Sınav Dosyası Yükle" butonuna tıklayın

        Adınızı, soyadınızı ve öğrenci numaranızı girin

        Sınav dosyanızı (.pka) seçin

        "Dosyayı Yükle" butonuna tıklayın

Admin Tarafı

    Admin Dashboard: http://127.0.0.1/admin/clients adresine gidin (sadece localhost)

    İstatistikleri Görüntüleme: Dashboard'da tüm istatistikler otomatik güncellenir

    Ağ Taraması: "Ağı Tara" butonuna tıklayarak ağdaki cihazları tespit edin

    Log Dosyaları:

        HTML log: _yukleme_kayitlari.html

        Terminal log: terminal_kayitlari.log

### 🌐 Sayfalar ve Endpoint'ler

Genel Erişim

    / - Ana sayfa

    /upload - Dosya yükleme sayfası

    /ip-atama - IP yapılandırma sayfası

    /download-pem - PEM dosyası indirme

    /download-veyon - Veyon Setup indirme

    /generate-script?ip=...&os=... - IP yapılandırma script'i oluşturma

Admin Erişimi (Sadece localhost)

    /admin/clients - Admin dashboard

    /admin/data - Dashboard verileri (JSON)

    /admin/scan - Ağ taraması endpoint'i

### 🔐 Güvenlik Özellikleri

DDoS/DoS Koruması

    10 saniyede 50'den fazla istek yapan IP'ler otomatik engellenir

    Terminal ve admin dashboard'da uyarı gösterilir

    HTTP 429 (Too Many Requests) yanıtı döner

Rate Limiting

    IP başına 10 dakikada maksimum 5 dosya yükleme

    Aşım durumunda 429 yanıtı ve uyarı mesajı

Dosya Güvenliği

    Sadece .pka uzantılı dosyalar kabul edilir

    Maksimum dosya boyutu: 50MB

    Path traversal saldırılarına karşı koruma

    SHA256 hash ile dosya bütünlüğü kontrolü

Admin Erişim Kontrolü

    Admin dashboard ve endpoint'leri sadece 127.0.0.1 (localhost) IP'sinden erişilebilir

    Diğer IP'lerden erişim denemeleri 403 (Forbidden) yanıtı alır

### 📊 Admin Dashboard Özellikleri

İstatistikler

    📤 Toplam Yükleme: Tüm yüklemelerin sayısı

    🔑 PEM İndirme: PEM dosyası indirme sayısı

    🖥️ Veyon İndirme: Veyon Setup indirme sayısı

    🔴 Kopya Dosya: Tespit edilen kopya dosya sayısı

    🟣 Boş Sınav: Boş sınav dosyası sayısı

Tablolar

    Dosya Yükleyenler:

        Zaman, Ad Soyad, Numara, Dosya, Boyut, IP, SHA256 Hash, Durum

        Sarı işaretleme: Aynı numara/IP ile tekrar yükleme

        Kırmızı işaretleme: Kopya dosyalar

        Mor işaretleme: Boş sınav dosyaları

    PEM İndirenler:

        Zaman, IP Adresi, Hostname (tarama yapıldıysa)

    Veyon Setup İndirenler:

        Zaman, IP Adresi, Hostname (tarama yapıldıysa)

    Ağ Cihazları:

        IP Adresi, MAC Adresi, Hostname

        Manuel tarama ile güncellenir

### Alert Sistemi

Dashboard üstünde kırmızı bir alert kutusu gösterilir:

    🚨 DDoS/DoS tespit edildiğinde

    🔴 Kopya dosya tespit edildiğinde

    🟣 Boş sınav dosyası tespit edildiğinde

    🟡 Tekrar yükleme yapıldığında (aynı numara/IP)

### 🛠️ Teknik Detaylar

IP Yapılandırma Script'leri

Windows (.bat)

    Dinamik Wi-Fi/Ethernet adaptör tespiti

    Yönetici yetkisi kontrolü

    Hata durumunda terminal açık kalır

    Detaylı hata mesajları

Linux/macOS (.sh)

    NetworkManager veya netplan kullanımı

    Yönetici yetkisi kontrolü

    Hata durumunda detaylı mesajlar

Dosya Formatları

    Yükleme Dosyaları: .pka uzantılı

    Log Dosyaları:

        HTML: _yukleme_kayitlari.html

        Terminal: terminal_kayitlari.log

        JSON: _ip_atamalari.json (IP atama kayıtları)

Veri Yapıları

    ALL_UPLOADS: Tüm yüklemelerin listesi

    PEM_DOWNLOADS: PEM indirme logları

    VEYON_DOWNLOADS: Veyon Setup indirme logları

    NETWORK_CLIENTS: Ağ cihazları (IP, MAC, Hostname)

    SEEN_HASHES_MAP: Dosya hash'leri (mükerrer tespiti için)

    REQUEST_LOGS: İstek logları (DDoS tespiti için)

Threading

    ThreadingHTTPServer kullanılarak çoklu bağlantı desteği

    Thread-safe log yazma mekanizması

    Eşzamanlı dosya yüklemeleri desteklenir

### 📝 Notlar

    Offline Çalışma: Tüm fontlar ve kaynaklar yerel, internet bağlantısı gerektirmez

    Windows 10/11 Uyumluluğu: IP atama script'leri Windows 10 ve 11'de test edilmiştir

    Ad Soyad Formatı: Kullanıcı girişi otomatik olarak büyük harfe çevrilir

    SHA256 Hash: Tüm hash'ler tam olarak gösterilir (64 karakter)

    Hostname Çözümleme: Ağ taraması yapıldıktan sonra hostname'ler gösterilir

### 🔧 Sorun Giderme

IP Atama Çalışmıyor

    Script'i Yönetici olarak çalıştırdığınızdan emin olun

    Wi-Fi/Ethernet adaptörünüzün aktif olduğundan emin olun

    Terminal penceresindeki hata mesajlarını kontrol edin

Hostname Gösterilmiyor

    Admin dashboard'dan "Ağı Tara" butonuna tıklayın

    Tarama tamamlandıktan sonra hostname'ler görünecektir

DDoS Uyarısı Alıyorum

    10 saniyede 50'den fazla istek yapıyorsanız bu normaldir

    Sunucu otomatik olarak engelleyecektir

    10 saniye bekleyip tekrar deneyin

### 📞 Destek

Herhangi bir sorun veya öneri için lütfen geliştirici ile iletişime geçin.

Versiyon: 1.1

Lisans: MIT License
