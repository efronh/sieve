# Entegrasyon: politika, SIEM, oturum, veri toplama

Kod `sieve/integrations/` altında. Guardrail bunlar olmadan da çalışıyor; bunlar bir uygulamaya bağlarken lazım olan parçalar.

## Kiracı politikası ve SIEM

`tenant.py`, `siem.py`, `rules.py`.

```python
import logging
from sieve.integrations.siem import syslog_handler
from sieve.integrations.tenant import TenantGuardrail, load_policy

logging.getLogger("sieve.siem").addHandler(syslog_handler("siem.local", 514, "cef"))  # ya da "json"
guard = TenantGuardrail(load_policy("example_bank"))   # policies/default.toml + policies/example_bank.toml
result = guard.check(text, session_id="abc", user_id="42")
```

Politika TOML dosyalarında. `policies/default.toml` temel ayarlar, `policies/<kiracı>.toml` sadece değiştirdiği anahtarları eziyor. Bilinmeyen bir kural ID'si, katman ya da mod yüklemede hata veriyor; böylece yanlış yazılmış bir istisna kuralı sessizce açık bırakmıyor.

- `mode = "monitor"` her şeye izin veriyor ama olaya ne olacağını (`would_action`) yazıyor.
- `on_error` bir kontrol hata verirse ne olacağını söylüyor: `block` (varsayılan), `review` ya da `allow` (açık kalma, yine de loglanıyor). Shadow moddaki bir katmanın hatası engellemiyor. Politikanın kendi kodu hata verirse `on_error` ne derse desin sonuç block. Olayda kural `layer_error`, ayrıntıda katman ve hata tipi var, hata mesajı yok. `layer_error` `disabled_rules`'a yazılamıyor.
- `[layers]` altında her katman `enforce`, `shadow` (sadece kayıt) ya da `off`.
- `[tools.<ad>]` modelin çağırabileceği tool'lar, `guard.check_tool(...)` ile ([katmanlar](layers.md#tool-çağrıları-toolspy)). `[layers] tool_call` bunları açıp kapatıyor.
- Modelin okuyacağı dokümanlar (RAG, e-posta, tool sonucu) `guard.check_document(text)` ile ([katmanlar](layers.md#dokümanlar-documentspy)); olay `direction = "document"`, doküman maskeli. `[layers] indirect_injection` doküman kurallarını açıp kapatıyor; ML ve injection kuralları mesajlardaki ayarlarını kullanıyor.
- `disabled_rules` kapatılacak kural ID'leri. Bir bulgudaki kuralların hepsi kapalıysa bulgu bastırılıyor (`suppressed`); bir kısmı kapalıysa bulgu olduğu gibi kalıyor.

Kural ID'leri `rules.py`'de, `<katman>.<eşleşme>` biçiminde (ör. `prompt_injection_rules.ignore_instructions`). Her birinin bir OWASP LLM Top 10 (2025) kodu ve 1-10 arası bir önem derecesi var. SIEM kuralları bunlara bağlı olacağı için ID'ler değiştirilmiyor. Katalogda olmayan bir ID üretilirse `tests/test_rules.py` hata veriyor.

Olaylara ham metin hiç yazılmıyor. `message_hash` maskelenmiş metnin hash'i, yani aynı saldırı her kiracıda aynı hash'i veriyor. Oturum ve kullanıcı ID'leri anahtarlı hash; üretimde `SIEVE_PSEUDONYM_KEY` ayarlanmalı. `log_excerpt = true` ise maskelenmiş metnin ilk 200 karakteri ekleniyor. Varsayılan olarak sadece işaretlenen kararlar gönderiliyor (`log_allowed = false`).

## Oturum katmanı

`throttle.py` ve `tenant.py`. `TenantGuardrail.check` bir oturum ya da kullanıcı ID'si alınca çalışıyor. Ayarları politikada `[session]` altında, açıp kapatmak için `[layers] session`.

| Kural ID | Ne zaman | Karar |
|---|---|---|
| `session.rate_limit` | Kullanıcı dakikada `max_requests_per_minute`'tan fazla istek atarsa | block |
| `session.volume_limit` | `window_seconds` içinde `max_chars_per_window`'dan fazla metin | block |
| `session.repeat_offender` | Pencere içinde `max_flagged` işaretli mesajdan sonra, `cooldown_seconds` boyunca her mesaj | block |
| `session_split` | Son `context_messages` mesaj birlikte okununca, hiçbirinde tek başına olmayan bir kural tetikleniyorsa ("Önceki tüm talimatları" + "unut ve …") | review |

- Limitler `user_id` üzerinden sayılıyor (yoksa `session_id`), yani yeni oturum açmak limiti sıfırlamıyor. Bölünmüş saldırı kontrolü oturum başına.
- Gölge katmanlardan ve kapalı kurallardan gelen bulgular işaretli sayılmıyor.
- Bölünmüş saldırılarda iki yarısı tek başına geçen 32 saldırının 29'u yakalandı. 429 sentetik normal sohbette 2 yanlış alarm çıktı (mesaj sınırında yan yana gelen kelimeler). Bu yüzden sadece review'a atıyor.
- Durum bellekte, en fazla 50.000 anahtar tutuluyor (en eskisi atılıyor). Birden fazla süreç varsa her biri ayrı sayıyor.
- Mesaj başına süre oturumsuz ~0.8 ms, oturumla ~1.3 ms (son mesajlar birleştirilip kurallar bir kez daha çalıştırılıyor).

## Gerçek trafikten veri toplama

```python
from sieve.integrations.traffic_log import LoggingGuardrail

guard = LoggingGuardrail()
guard.check(mesaj, session_id=oturum)
```

```bash
python -m scripts.select_for_labeling   # logs/traffic.jsonl -> labeling/queue.csv
python -m scripts.label                 # terminalde 1/0 ile etiketle
python -m scripts.add_labels            # -> data/real_labeled.csv (%80) + data/real_holdout.csv (%20, eğitilmez)
python -m scripts.train_injection       # yeniden eğit, holdout sonucuna bak
```

- Log'a sadece maskelenmiş metin ve oturum ID'sinin hash'i yazılıyor.
- Kuyruğa girenler: `flagged` (review/block), `layers_disagree` (kurallar ve ML farklı düşünüyor), `ml_uncertain` (ML skoru 0.3–0.9), `random_allow` (geçen mesajların ~%2'si, kaçan saldırıları bulmak için).
- Holdout ayrımı oturum bazında yapılıyor.
- KVKK: maskeleme TC, IBAN, kart, telefon, e-posta ve anahtarları yakalıyor ama isim ve adresleri yakalamıyor. `logs/` ve `labeling/` kişisel veri içerebilir; erişimi kısıtlı tutun, saklama süresi belirleyin. İkisi de `.gitignore`'da.

## Maliyet ayarları

| Ayar | Nerede | Etkisi |
|---|---|---|
| LLM'i sadece gerekince çağırma | `Guardrail(llm_min_ml=0.2)` | Bkz. [llm.md](llm.md) |
| Uzun mesaj | `Guardrail(llm_max_chars=3000)` | LLM mesajın başını ve sonunu okuyor; yerel katmanlar 8000 karaktere kadar hepsini |
| Karar önbelleği | `Guardrail(cache_size=2048)` | Aynı mesaj tekrar hesaplanmıyor. LLM katmanı feedback ile değişirse `guard.cache.clear()` |
| Oturum kısıtlama | `throttle.SessionLimiter` | 10 dakikada 3 işaretli mesajdan sonra oturum 15 dakika duruyor |
| Ölçüm | `python -m scripts.evaluate_cost` | Eşiğe göre LLM çağrı oranı ve LLM'e sorulmadan geçen saldırı sayısı |
