# HTTP API

`sieve/server.py`. Sieve'i bir servis olarak çalıştırıyor: uygulama her sınırda bir JSON isteği gönderiyor, cevaptaki `action`'a göre davranıyor. Kütüphanedeki `TenantGuardrail`'in aynısı; politika, SIEM olayları ve oturum limitleri ([operations.md](operations.md)) aynen geçerli.

```bash
SIEVE_API_KEY=... python -m sieve.server --tenant example_bank --system-prompt prompt.txt --port 8080
```

| Seçenek | Varsayılan | |
|---|---|---|
| `--tenant` | `default` | `policies/<kiracı>.toml` |
| `--system-prompt` | yok | Operatörün sistem promptu (dosya); canary ekleniyor, modele `GET /v1/prompt`'taki verilmeli |
| `--host`, `--port` | `127.0.0.1`, `8080` | Dışarı açmak için `--host 0.0.0.0`, önünde TLS yapan bir reverse proxy ile |
| `--timeout` | `5` | Bir kontrolün saniye cinsinden süresi; aşarsa cevap block |
| `--siem` | `stdout` | `stdout` (satır başına bir JSON olay), `host:port` (TCP syslog, JSON) ya da `none` |
| `--insecure-no-auth` | kapalı | Anahtarsız çalıştırma; sadece yerel test için, sadece `127.0.0.1`/`::1`'de |
| `--ui` | kapalı | `/` adresinde bir sayfa: kontrol denemek, kararları izlemek, değerlendirmeyi okumak ([aşağıda](#sayfa---ui)) |

`SIEVE_API_KEY` yoksa ya da 32 karakterden kısaysa sunucu başlamıyor ([Anahtarlar](#anahtarlar)); `SIEVE_PSEUDONYM_KEY` yoksa uyarı veriyor. SIGTERM'de çalışan kontrolü bitirip temiz kapanıyor (systemd, Kubernetes ve `docker stop` böyle durduruyor). Sadece standart kütüphane kullanıyor (`http.server`): güvenilmesi gereken bir web framework'ü yok ([TH-13](../THREAT_MODEL.md#th-13-model-and-training-data-integrity)).

## Anahtarlar

İki anahtar var, ikisi de ortamdan, sunucu dinlemeye başlamadan kontrol ediliyor:

| | Kimin | Ne yapabilir |
|---|---|---|
| `SIEVE_API_KEY` | Uygulamanın | Her şey: dört kontrol, `GET /v1/prompt`, `GET /v1/stats` |
| `SIEVE_UI_KEY` | Sayfayı kullanan kişinin (isteğe bağlı) | Dört kontrol ve `GET /v1/stats`. `GET /v1/prompt` 403: sistem promptu ve canary uygulamanın. Gönderdiği `session_id` ve `user_id` `ui:` önekiyle ayrı tutuluyor, yani gerçek bir kullanıcının oturum limitlerine ve geçmişine dokunamıyor |

**Üretmek.** Her anahtar en az 32 karakter, yoksa sunucu başlamıyor; iki anahtar aynıysa da. Rastgele üretin, elle seçmeyin:

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

**Dağıtmak.** Anahtar repoya, loglara, bir komut satırına ya da bir sohbete girmiyor. Sunucuya ve uygulamaya aynı yerden, ortam değişkeni olarak veriliyor: bir secret manager (Vault, AWS Secrets Manager, Azure Key Vault), Kubernetes `Secret`, Docker secret, ya da systemd `EnvironmentFile` (sahibi servisin kullanıcısı, `chmod 600`). Uygulamanın anahtarı sadece uygulamada; sayfayı kullanacak kişiye `SIEVE_UI_KEY` veriliyor, uygulamanınki asla. `--ui` açık ve `SIEVE_UI_KEY` yoksa sunucu bunu uyarıyla söylüyor.

**Döndürmek.** `SIEVE_API_KEY` virgülle ayrılmış birden fazla anahtar alıyor: önce `SIEVE_API_KEY=yeni,eski` ile yeniden başlatın, uygulamaları yeni anahtara geçirin, sonra `SIEVE_API_KEY=yeni` ile bir kez daha. Arada iki anahtar da geçerli, hiçbir istek reddedilmiyor. Sızdığından şüphelenilen bir anahtar hemen çıkarılıyor.

**Yanlış anahtar.** Cevap 401. Her ret `GET /v1/stats`'ta `refused` olarak sayılıyor ve dakikada en fazla bir kez `sieve.server` logunda uyarı oluyor. Kilitleme yok: yanlış anahtarla gelen istekler gerçek uygulamayı da kilitleyebilirdi, 32 rastgele karakter de tahminle bulunamaz. Anahtarlar sabit sürede karşılaştırılıyor, hepsi her seferinde; süre hangisine yaklaşıldığını söylemiyor.

**Taşımak.** Sunucu TLS yapmıyor; anahtar düz HTTP'de gidiyor. Varsayılan `127.0.0.1` bu yüzden. Dışarı açılacaksa önünde TLS yapan bir reverse proxy olmalı, sayfa açılacaksa proxy'de bir de SSO.

## İstek

Her istek `Content-Type: application/json`, `Authorization: Bearer <SIEVE_API_KEY>` (`/healthz` hariç) ve en fazla 1.000.000 baytlık bir gövdeyle. Bilinmeyen bir alan, eksik ya da yanlış tipte bir alan 400; yazım hatası sessizce yok sayılmıyor.

Ortak, isteğe bağlı alanlar: `session_id`, `user_id` (oturum limitleri ve tool toplamları buna göre), `request_id` (bir isteğin olaylarını SIEM'de birleştiriyor), `detail` (`true` ise cevapta her katmanın bulgusu ve aşama süreleri; aşağıda).

### `POST /v1/check` — kullanıcının mesajı (B1)

```json
{"text": "Kartımın limiti ne kadar? TC 10000000146", "session_id": "s-1029", "user_id": "u-42"}
```
```json
{"action": "allow", "text": "Kartımın limiti ne kadar? TC [TC_KIMLIK]", "request_id": "6f1c…", "rules": []}
```

`text` modele gönderilecek maskeli metin. `action` `block` ise `text` boş: gönderilecek bir şey yok, `action`'a bakmayı unutan bir uygulama da bir şey gönderemiyor. `request_id` istekte yoksa Sieve veriyor; aynı isteğin aşağıdaki kontrollerine bu verilmeli. `X-Request-ID` başlığında da var. `rules` kararı belirleyen kural ID'leri ([`rules.py`](../sieve/rules.py)); uygulamanın ve loglarının, kullanıcıya ya da modele gösterilmiyor ([THREAT_MODEL §4](../THREAT_MODEL.md#4-what-sieve-needs-from-the-app)).

### `POST /v1/document` — modelin okuyacağı içerik (B2)

```json
{"text": "<p>Kampanya başladı…</p>", "source": "web", "session_id": "s-1029", "request_id": "6f1c…"}
```
```json
{"action": "allow", "wrapped": "<<web 3f9a…>>\nKampanya¦başladı…\n<</web 3f9a…>>", "rules": []}
```

`wrapped` prompta konacak hali: maskeli, sınır içinde, kelimeleri işaretli ([katmanlar](layers.md#dokümanlar-documentspy)). `block` ise `null`: doküman prompta girmemeli. Sınırın açıklaması `GET /v1/prompt`'taki `document_instructions`.

### `POST /v1/tool` — modelin yapmak istediği çağrı (B5)

```json
{"name": "para_transferi", "args": {"iban": "[IBAN_A]", "tutar": 500}, "user_data": ["Anneme 500 TL gönder…"],
 "session_id": "s-1029", "request_id": "6f1c…"}
```
```json
{"action": "review", "args": {"iban": "TR33 0006 1005 1978 6457 8413 26", "tutar": 500},
 "reasons": ["needs the user's confirmation"], "rules": ["tool_call.needs_confirmation"]}
```

Çağrı `args` ile çalıştırılmalı, modelin yazdığıyla değil: politika harfli etiketleri açtıysa ([katmanlar](layers.md#harfli-etiketler-vaultpy)) etiketler burada değerlerine dönmüş oluyor, örnekteki gibi. Çağrı argümanları okunmadan reddedildiyse `null`. `reasons` uygulama için; modele geri verilirse hangi kuralın aşılacağını söyler.

### `POST /v1/output` — modelin cevabı (B4)

```json
{"answer": "Kayıtlı numaranız …", "user_data": ["…"], "session_id": "s-1029", "request_id": "6f1c…"}
```
```json
{"action": "allow", "text": "Kayıtlı numaranız …", "rules": []}
```

`text` kullanıcıya gösterilecek hali; `block` ise güvenli yanıt.

### `GET /v1/prompt`

```json
{"system_prompt": "<operatörün promptu>\n\nInternal reference KNR-…", "document_instructions": "<<... 3f9a…>> ile …"}
```

Modele verilecek sistem promptu (canary ile) ve dokümanlar için açıklama. Sunucu her başladığında canary ve sınır yeniden üretiliyor; uygulama bunları sunucu başladıktan sonra almalı.

### `"detail": true`

Dört kontrolün cevabına `detail` ekliyor: her katmanın bulgusu (hiçbir şey bulmayanlar da, ML skoru görünsün diye), skoru, kararı, kuralları ve başlıkları, bir de aşama başına süre.

```json
"detail": {"findings": [{"check": "prompt_injection_rules", "score": 1.0, "action": "block",
                         "rules": [{"rule": "prompt_injection_rules.ignore_instructions", "title": "Ignore previous instructions", "detail": null}]},
                        {"check": "prompt_injection_ml", "score": 0.97, "action": "review", "rules": [...]}],
           "timings_ms": {"masking": 0.44, "prompt_injection_rules": 0.2, "prompt_injection_ml": 0.67, "policy": 0.05}}
```

Skorlar ve kurallar uygulamanın, `rules` gibi: kullanıcıya gösterilmemeli, bir saldırgan hangi kuralı tetiklediğini öğrenmesin ([TH-12](../THREAT_MODEL.md#th-12-probing-the-guardrail)). Önbellekten gelen bir sonucun süresi `cache`.

### `GET /v1/stats`

Sunucunun başladığından beri verdiği kararlar: yön ve karar başına sayılar, en çok tetiklenen 20 kural, son 50 kararın zamanı, yönü, kararı, kuralları ve süresi, zaman aşımları. Kiracı, politika sürümü ve mod da var, bir de yanlış anahtarla gelen isteklerin sayısı (`refused`). Metin, kullanıcı, oturum ve istek ID'si yok: kararları saklayan ve birleştiren yer SIEM. Süreç başına, bellekte; yeniden başlayınca sıfırlanıyor. İki anahtardan biri gerekiyor.

### `GET /healthz`

`{"status": "ok"}`; anahtar istemiyor, başka bir şey söylemiyor.

## Sayfa (`--ui`)

`--ui` ile sunucu `/` adresinde bir sayfa da veriyor, üç sekme:
- **Try a check:** dört sınırdan birini seçip bir mesaj, doküman, tool çağrısı ya da cevap gönderiyor (`detail` ile); kararı, modele ya da kullanıcıya gidecek hali, her katmanın bulgusunu ve süreleri gösteriyor. Örnekler hazır; tool örnekleri `policies/demo.toml`'daki iki tool'la çalışıyor.
- **Decisions:** `GET /v1/stats`, beş saniyede bir.
- **Evaluation:** `results/` altındaki sonuçların özeti (`/ui/results.json`: mühürlü set, aile karşılaştırması, dedektörler, süreler; hiçbir kayıt değil) ve README'deki grafikler.

```bash
SIEVE_API_KEY=... SIEVE_UI_KEY=... python -m sieve.server --tenant demo --ui
```

Sayfa ve dosyaları anahtarsız; kendileri veri taşımıyor, gösterdikleri API'den anahtarla geliyor. Anahtar sayfadaki alana yazılıyor, `SIEVE_UI_KEY` tercihen ([Anahtarlar](#anahtarlar)); sadece o alanda, bellekte duruyor, hiçbir yere kaydedilmiyor, sayfa yenilenince yeniden soruluyor. Sayfa saldırı metni gösterdiği için her şeyi metin olarak yazıyor, hiçbir zaman HTML olarak değil; bir test `innerHTML` ve benzerlerini arıyor. Sadece sabit bir listedeki dosyalar veriliyor (`/`, `/ui/app.js`, `/ui/app.css`, `/ui/results.json` ve dört SVG): başka bir yol 404. Başlıklar: `Content-Security-Policy` (sadece sunucunun kendi dosyaları, satır içi script yok, çerçeveye konamaz), `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `nosniff`. Varsayılan kapalı: bir üretim API'sinde fazladan bir HTML yüzeyi olmasın.

## Hatalar

```json
{"error": {"code": "bad_request", "message": "unknown field 'extra'"}}
```

| Durum | `code` | Ne zaman |
|---|---|---|
| 400 | `bad_request`, `bad_json` | Gövde JSON nesnesi değil, alan bilinmiyor, eksik ya da yanlış tipte |
| 401 | `unauthorized` | Anahtar yok ya da yanlış |
| 403 | `forbidden` | Sayfanın anahtarıyla `GET /v1/prompt` |
| 404 / 405 | `not_found`, `method_not_allowed` | Yol ya da metot yanlış |
| 411 / 413 / 415 | `length_required`, `too_large`, `unsupported_media_type` | `Content-Length` yok, gövde büyük, JSON değil |
| 503 | `busy` | Bekleyen ya da çalışan 64 istek var |
| 500 | `internal` | Sunucunun kendi hatası (kontroller kendi hatalarını block olarak cevaplıyor) |

Hata mesajı alanın adını söylüyor, değerini asla: istek kişisel veri taşıyabilir. Erişim logunda sadece metot, yol ve durum var; gövde ve query string yok.

**Uygulama 200 dışındaki her cevabı, zaman aşımını ve bağlantı hatasını block saymalı.** Sieve'e ulaşılamaması kontrol edilmemiş bir mesaj demek ([TH-15](../THREAT_MODEL.md#th-15-guard-failure)).

## Süre, sıra ve tekrar deneme

- **Bir kontrol en fazla `--timeout` saniye.** Aşarsa cevap `block`, `rules: ["layer_error"]`; SIEM olayında ayrıntı `timeout: TimeoutError`. Kontrol arka planda bitiyor ve kendi olayını da yazıyor; uygulama o sırada block'u almış oluyor.
- **Bir süreçte bir kontrol aynı anda çalışıyor.** Kiracının oturum durumu thread-safe değil. Sırada bekleyen bir isteğin süresi de sayılıyor: önündeki yavaş bir kontrol onu da block'a düşürebilir. Saldırı altında sunucu durmuyor, block'a dönüyor; bu bir kullanılabilirlik bedeli ([TH-11](../THREAT_MODEL.md#th-11-resource-exhaustion)). Daha fazlası için birden fazla süreç; oturum limitleri o zaman süreç başına.
- **64'ten fazla istek beklerse 503.** Bir istemcinin gövdeyi göndermesi için 10 saniye var; yavaş istemciler thread tutamıyor.
- **Tekrar deneme güvenli.** Hata veren bir kontrol önbelleğe girmiyor, tekrarında baştan çalışıyor. Süresi dolan bir kontrol arka planda bitince sonucu (allow ya da block, gerçek karar) önbelleğe giriyor; tekrar deneme o gerçek kararı alıyor, ilk denemenin hatasını değil. Her deneme `session.rate_limit`'e sayılıyor, işaretlenen her deneme `session.repeat_offender`'a da; yani bir saldırıyı tekrar tekrar denemek limite takılıyor.
