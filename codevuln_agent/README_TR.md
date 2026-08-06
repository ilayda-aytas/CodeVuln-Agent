# CodeVuln Agent - Kod Güvenlik Analiz Aracı

CodeVuln Agent, kaynak kodlarda potansiyel güvenlik açıklarını tespit etmeye yardımcı olan Python ve Streamlit tabanlı bir SAST ön analiz aracıdır. Kullanıcı arayüzü üzerinden kod yapıştırabilir, bir veya birden fazla kaynak dosya yükleyebilir, bulguları inceleyebilir ve raporları JSON, Markdown veya HTML olarak dışa aktarabilirsiniz.

Bu proje yerel kural tabanlı tarama motorunu, opsiyonel Semgrep ve Bandit entegrasyonlarıyla birleştirir. İstenirse Groq API kullanılarak bulgular için LLM destekli açıklamalar ve yönetici özeti de üretilebilir.

## Öne Çıkan Özellikler

- Kod yapıştırarak veya dosya yükleyerek analiz yapma.
- Python, JavaScript, PHP, Java, HTML ve generic kod desteği.
- `scanner/rules/` altındaki yerel güvenlik kurallarıyla tarama.
- Semgrep ile opsiyonel statik analiz desteği.
- Bandit ile Python kodlarına özel güvenlik taraması.
- Arayüzden özel regex kuralı ekleme.
- Bulguları severity ve detection source alanlarına göre filtreleme.
- Kritik, yüksek, orta ve düşük seviye bulgu metrikleri.
- JSON, Markdown ve HTML rapor çıktıları.
- Groq API ile opsiyonel LLM açıklama zenginleştirmesi.

## Kullanılan Teknolojiler

| Teknoloji | Projedeki Görevi |
| --- | --- |
| Python 3.11 | Ana uygulama, tarama ve raporlama mantığı |
| Streamlit | Web tabanlı kullanıcı arayüzü |
| Pandas | Bulguların tablo halinde gösterilmesi |
| Semgrep | Opsiyonel çok dilli statik analiz motoru |
| Bandit | Python kodları için opsiyonel güvenlik tarayıcısı |
| Groq SDK | Opsiyonel LLM destekli açıklama ve özet üretimi |
| Pytest | Otomatik testler |
| Docker | Taşınabilir ve tekrarlanabilir çalışma ortamı |

## Proje Yapısı

```text
codevuln_agent/
+-- app.py                         # Streamlit arayüzü ve analiz akışı
+-- requirements.txt               # Python bağımlılıkları
+-- Dockerfile                     # Docker çalışma ortamı
+-- scanner/
|   +-- language_detector.py       # Dil algılama yardımcısı
|   +-- rule_scanner.py            # Yerel kural tabanlı tarayıcı
|   +-- semgrep_scanner.py         # Semgrep entegrasyonu
|   +-- bandit_scanner.py          # Bandit entegrasyonu
|   +-- rules/                     # Yerel güvenlik kuralları
+-- reporter/
|   +-- json_reporter.py           # JSON rapor üretimi
|   +-- markdown_reporter.py       # Markdown rapor üretimi
|   +-- html_reporter.py           # HTML rapor üretimi
+-- agent/
|   +-- llm_agent.py               # Groq ile opsiyonel LLM desteği
+-- tests/                         # Pytest testleri
```

## Kurulum

Proje klasörüne girin ve bağımlılıkları kurun:

```bash
cd codevuln_agent
python -m pip install -r requirements.txt
```

`requirements.txt` içinde Streamlit, Pandas, Groq, Bandit, Semgrep ve Pytest bağımlılıkları yer alır.

Semgrep veya Bandit aktif Python ortamınızda eksik görünürse ayrıca kurabilirsiniz:

```bash
python -m pip install semgrep bandit
```

## Uygulamayı Çalıştırma

```bash
python -m streamlit run app.py
```

Tarayıcıdan şu adrese gidin:

```text
http://localhost:8501
```

Windows'ta proje masaüstündeyse örnek yol:

```powershell
cd C:\Users\PC\OneDrive\Desktop\codevuln_agent
python -m streamlit run app.py
```

## Docker ile Çalıştırma

Docker imajını oluşturun:

```bash
docker build -t codevuln-agent:latest .
```

Konteyneri başlatın:

```bash
docker run --rm -p 8501:8501 codevuln-agent:latest
```

Ardından tarayıcıda açın:

```text
http://localhost:8501
```

## Analiz Akışı Nasıl Çalışır?

1. Kullanıcı arayüzünden kod yapıştırılır veya kaynak dosyalar yüklenir.
2. Auto mode seçiliyse `language_detector.py` kodun dilini tahmin eder.
3. `rule_scanner.py` yerel güvenlik kurallarını çalıştırır.
4. Semgrep etkin ve kuruluysa `semgrep_scanner.py` ek Semgrep taraması yapar.
5. Kod Python ise ve Bandit etkinse `bandit_scanner.py` Bandit bulgularını toplar.
6. Bulgular tekrar eden kayıtlar temizlenerek severity seviyesine göre sıralanır.
7. Results sekmesinde metrikler, tablo ve detaylı bulgu kartları gösterilir.
8. Sonuçlar JSON, Markdown veya HTML raporu olarak indirilebilir.

## Semgrep Kullanımı

Semgrep opsiyoneldir. Kurulu olduğunda CodeVuln Agent içinde ek bir detection source olarak çalışır.

Projede Semgrep için yerel fallback kurallar da bulunur. Bu sayede internet veya Semgrep registry erişimi olmadan da temel Semgrep pattern taraması yapılabilir. Semgrep uygulamayı çalıştıran Python ortamında kurulu değilse arayüzde unavailable olarak görünür.

Semgrep'i kontrol etmek için:

```bash
python -m semgrep --version
```

## Bandit Kullanımı

Bandit opsiyoneldir ve yalnızca Python kodları için çalışır. Subprocess kullanımı, hardcoded secret, insecure deserialization, zayıf kripto kullanımı gibi Python'a özel güvenlik risklerini yakalamaya yardımcı olur.

Bandit'i kontrol etmek için:

```bash
python -m bandit --version
```

## Groq LLM Desteği

Sidebar içinde Groq API Key alanı bulunur. Anahtar girilip LLM enhancement etkinleştirilirse bulgular daha açıklayıcı hale getirilebilir ve yönetici özeti üretilebilir.


## Test Etme

Testleri çalıştırmak için:

```bash
python -m pytest
```

Testler yerel rule scanner davranışını ve Semgrep entegrasyonundaki temel güvenlik kontrollerini kapsar.

## Sınırlamalar

- Bu araç bir ön analiz yardımcısıdır; profesyonel güvenlik denetiminin yerine geçmez.
- False positive ve false negative sonuçlar olabilir.
- Semgrep ve Bandit sonuçları, bu araçların uygulamayı çalıştıran Python ortamında kurulu olmasına bağlıdır.
- LLM ile üretilen açıklamalar manuel olarak kontrol edilmelidir.

