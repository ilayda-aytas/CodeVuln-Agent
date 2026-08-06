# CodeVuln Agent

CodeVuln Agent, kaynak kodlarda potansiyel güvenlik açıklarını tespit etmeye yardımcı olan Python ve Streamlit tabanlı bir SAST ön analiz aracıdır.

Uygulama; yerel güvenlik kuralları, Semgrep, Bandit ve opsiyonel Groq LLM desteği ile kod analizi yapar. Kullanıcılar kod yapıştırabilir, dosya yükleyebilir, özel regex kuralı ekleyebilir, bulguları filtreleyebilir ve raporları JSON, Markdown veya HTML formatında dışa aktarabilir.

## Özellikler

- Python, JavaScript, PHP, Java, HTML ve generic kod analizi
- Streamlit tabanlı web arayüzü
- Yerel rule-based scanner desteği
- Semgrep ile opsiyonel statik analiz
- Bandit ile Python güvenlik taraması
- Custom regex rule desteği
- Severity ve detection source filtreleme
- Detaylı bulgu ekranı
- JSON, Markdown ve HTML rapor indirme
- Opsiyonel Groq LLM explanation ve executive summary desteği

## Kullanılan Teknolojiler

| Teknoloji | Açıklama |
| --- | --- |
| Python | Ana backend ve analiz mantığı |
| Streamlit | Web arayüzü |
| Semgrep | Statik analiz ve pattern tabanlı güvenlik taraması |
| Bandit | Python kodları için güvenlik analizi |
| Pandas | Bulguların tablo halinde gösterilmesi |
| Groq SDK | Opsiyonel LLM destekli açıklama üretimi |
| Pytest | Test altyapısı |
| Docker | Konteyner ile çalıştırma |

```

### 1. Kod Analiz Ekranı

Kullanıcı bu ekranda analiz edilecek kodu yapıştırabilir veya kaynak dosya yükleyebilir. Sol menüden Semgrep, Bandit ve LLM seçenekleri kontrol edilebilir.

![Analyze Code](docs/images/analyze-code.png)

### 2. Analiz Sonuç Özeti

Analiz tamamlandıktan sonra uygulama tespit edilen dili, toplam bulgu sayısını ve severity dağılımını gösterir.

![Results Summary](docs/images/results-summary.png)

### 3. Bulgular Tablosu

Tespit edilen güvenlik bulguları tablo halinde listelenir. Bulgular severity, vulnerability name, line, CWE, OWASP category, source ve confidence bilgileriyle gösterilir.

![Findings Table](docs/images/findings-table.png)

### 4. Detaylı Bulgu İnceleme

Her bulgu açılarak detaylı şekilde incelenebilir. Bu bölümde etkilenen satır, kanıt kod parçası, açıklama ve güvenli çözüm önerisi gösterilir.

![Detailed Finding](docs/images/detailed-finding.png)

### 5. Rapor Dışa Aktarma

Analiz sonuçları JSON, Markdown veya HTML formatında indirilebilir.

![Export Report](docs/images/export-report.png)

### 6. Custom Regex Rule

Kullanıcı isterse arayüzden özel regex tabanlı güvenlik kuralı tanımlayabilir. Bu özellik proje özelinde kontrol edilmesi gereken pattern'ler için kullanılabilir.

![Custom Rule](docs/images/custom-rule.png)

## Proje Yapısı

```text
codevuln_agent/
+-- app.py
+-- requirements.txt
+-- Dockerfile
+-- scanner/
|   +-- language_detector.py
