# ML katmanı (prompt injection)

Kod `sieve/ml/injection.py`, eğitim `scripts/train_injection.py`, karşılaştırma `scripts/compare_models.py`.

## Kademe

Her mesajda TF-IDF (karakter 3-5 ve kelime 1-2 gram) + lojistik regresyon çalışıyor (~0.5 ms). TF-IDF skoru `low` ile `high` arasında kalırsa `dbmdz/bert-base-turkish-cased` cümle vektörü + lojistik regresyon da çalışıyor ve iki skorun ortalaması alınıyor (M4 GPU'da ~35 ms; model ilk kararsız mesajda ~8 saniyede yükleniyor).

`low` ve `high` eğitim sırasında çapraz doğrulamadan hesaplanıyor: `low` altında iki model birlikte hiçbir mesajı işaretlemedi, `high` üstünde hepsini işaretledi. Yani eğitim verisinde kademe, iki modeli her mesajda çalıştırmakla aynı kararı veriyor.

| %1 yanlış alarmda (5 katlı CV) | Yakalama | Gizlenmiş saldırı | BERTurk ne sıklıkla çalışıyor |
|---|---|---|---|
| Sadece TF-IDF | %73 | %72 | hiç |
| TF-IDF + BERTurk | %84 | %79 | normal mesajların %3'ünde, müşteri hizmetleri mesajlarının hiçbirinde |

TCPI test setinde ikisi de 30 saldırının %73'ünü %3 yanlış alarmla yakaladı. Set küçük, bir saldırı yaklaşık 3 puan.

Diğer notlar:

- `sentence-transformers` kurulu değilse ya da `SIEVE_CASCADE=0` ise sadece TF-IDF kendi eşiğiyle çalışıyor. `python -m scripts.train_injection --no-cascade` sadece TF-IDF eğitiyor.
- `Guardrail()` ML katmanını açık ekliyor: eşiği geçen mesaj `review` oluyor. Gölge modda kural katmanı test setindeki 30 saldırının hiçbirini yakalamıyordu (`python -m scripts.evaluate_pipeline`). Önce sadece kayıt almak isterseniz `MLInjectionLayer(shadow=True)` ya da politikada `prompt_injection_ml = "shadow"` kullanın. Bu durumda olasılık hesaplanıyor ve ne yapılacağı `matches` içine yazılıyor (ör. `would_review`), ama sonuç değişmiyor.
- Eşik, çapraz doğrulamada normal mesajların en fazla %1'ini (`TARGET_FALSE_ALARM`) işaretleyecek şekilde seçiliyor ve modelle birlikte kaydediliyor (`review_at`, `sklearn_version`).
- `BLOCK_AT = 1.01`, yani ML tek başına hiçbir zaman engellemiyor, en fazla review'a atıyor.
- Model dosyası sklearn sürümüne bağlı (`pyproject.toml`'da sabit). Başka bir sürümle yüklenirse uyarı veriyor.

## Model karşılaştırması

```bash
python -m scripts.compare_models [tfidf e5 minilm berturk berturk_ft deberta_en qwen1.7b_l0 qwen1.7b_l2]
```

Sonuçlar `results/compare_models.json`'a yazılıyor. Hepsinde aynı protokol: aileye göre bölünmüş 5 katlı CV, %1 yanlış alarm eşiği, aynı gizleme hileleri, TCPI test seti.

| Model | ROC-AUC | %1 FA'da yakalama | Gizlenmiş | TCPI test (yakalama / FA) | ms/mesaj |
|---|---|---|---|---|---|
| TF-IDF | 0.988 | 73% | 72% | 73% / 3% | 0.4 |
| e5 (çok dilli, dondurulmuş) | 0.977 | 49% | 42% | 43% / 4% | 33 |
| MiniLM (çok dilli, dondurulmuş) | 0.964 | 47% | 39% | 47% / 3% | 18 |
| BERTurk (dondurulmuş) | 0.991 | 77% | 69% | 70% / 7% | 34 |
| TF-IDF + BERTurk (şu anki kademe) | 0.994 | 84% | 79% | 77% / 3% | 34 |
| BERTurk fine-tuned | 0.995 | 88% | 82% | 97% / 8% | 23 |
| TF-IDF + BERTurk fine-tuned | 0.996 | 89% | 86% | 93% / 4% | 23 |
| protectai DeBERTa (İngilizce, olduğu gibi) | 0.709 | 16% | 16% | 0% / 0% | 63 |
| Qwen3-1.7B L0 (etiketsiz) | 0.819 | 14% | 17% | 10% / 0% | 330 |
| Qwen3-1.7B L2 (eğitilmiş başlık) | 0.988 | 80% | 81% | 80% / 4% | 250 |
| TF-IDF + Qwen3-1.7B L2 | 0.994 | 86% | 86% | 83% / 3% | 250 |

Gözlemler:

- e5 ve MiniLM, TF-IDF'in gerisinde kaldı. Bu modeller cümlenin konusunu yakalıyor ve "sistem promptunu göster" ile "sistem promptu nedir?" konu olarak aynı.
- İki modelin ortalaması ikisinden de iyi, çünkü farklı yerlerde hata yapıyorlar.
- İngilizce model Türkçede çöküyor: test setinde %1 eşikte tek bir saldırı yakalamadı.
- Fine-tuning ayarları: 2 epoch, lr 3e-5, en fazla 128 token, sınıf ağırlıklı kayıp. Hiperparametre araması yapmadım, tek seed. M4'te 5 kat + son model yaklaşık 47 dakika sürüyor, model ~440 MB. Henüz kademeye bağlamadım.

## Eğitim ve veri

```bash
python -m scripts.import_xlsx        # xlsx -> data/external_attacks.csv
python -m scripts.import_altaysec    # data/altaysec_train.jsonl -> data/altaysec.csv
python -m scripts.import_hf          # Hugging Face setleri, sabit sürümlerle
python -m scripts.train_injection    # eğitir, rapor basar, models/ altına kaydeder
python -m scripts.evaluate_unseen    # elle yazılmış, hiç görülmemiş cümlelerle dener
```

- Sütunlar: `text,label,category,family,language`. Aynı fikrin varyasyonları aynı `family`'de ve çapraz doğrulama bir aileyi hiçbir zaman eğitim ile test arasında bölmüyor.
- `ml/augment.py` her örnekten leetspeak, Kiril, Türkçe karaktersiz, yazım hatalı kopyalar üretiyor. Bunu normal mesajlara da uyguluyorum ki model "garip yazım = saldırı" diye öğrenmesin.
- `data/short_benign_tr.csv`: "Merhaba", "Evet", "Kargom nerede?" gibi kısa mesajlar. Bunlar olmadan model kısa mesajları saldırı sanıyordu.
- `data/benign_contrast_tr.csv`: AltaySec'in üslubuna (kurum adları, kibar ve duygusal ton, araya İngilizce karışması) benzeyen ama zararsız mesajlar. Model "kibar, uzun Türkçe = saldırı" kısayolunu öğrenmişti, bunu kırmak için ekledim.
- Kaçan saldırıları ve yanlış alarmları CSV'ye ekleyip yeniden eğitmek yeterli.

## Veri kaynakları ve atıf

- [3nesdeniz/turkish-conversation-prompt-injection](https://huggingface.co/datasets/3nesdeniz/turkish-conversation-prompt-injection), CC-BY-4.0. train ve validation eğitimde (`data/tcpi_train.csv`). Test bölümü hiç eğitilmiyor (`data/tcpi_test.csv`), ayrı test seti olarak raporlanıyor.
- [emreseyhan/Turkish-customer-service-conversations](https://huggingface.co/datasets/emreseyhan/Turkish-customer-service-conversations), CC-BY-4.0. Kullanıcı mesajlarından konuşma bazında ~1500 tanesi örneklendi (`data/customer_service_tr.csv`).
- [AltaySec Turkish LLM Prompt Injection Dataset v0.2](https://huggingface.co/datasets/AltaySec/turkish-llm-injection), CC-BY-4.0. Sürüm `data/altaysec_revision.txt`'de. Tek başına saldırı sayılamayacak 15 satırı `import_altaysec.py` içinde gerekçesiyle çıkardım.
- `yapay_zeka_saldiri_veriseti.xlsx`: İngilizce satırlar OWASP, garak, HackAPrompt, PortSwigger, Lakera ve MITRE ATLAS'tan; Türkçe satırlar bunlardan türetildi. Satırlar kısa, jenerik saldırı cümleleri; her kaynağın kendi lisansı geçerli.
- Sabit sürümler: `data/raw/revisions.txt`.
