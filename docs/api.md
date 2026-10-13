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
| `--insecure-no-auth` | kapalı | Anahtarsız çalıştırma; sadece yerel test için |

`SIEVE_API_KEY` yoksa sunucu başlamıyor; `SIEVE_PSEUDONYM_KEY` yoksa uyarı veriyor. SIGTERM'de çalışan kontrolü bitirip temiz kapanıyor (systemd, Kubernetes ve `docker stop` böyle durduruyor). Sadece standart kütüphane kullanıyor (`http.server`): güvenilmesi gereken bir web framework'ü yok ([TH-13](../THREAT_MODEL.md#th-13-model-and-training-data-integrity)).

## İstek

Her istek `Content-Type: application/json`, `Authorization: Bearer <SIEVE_API_KEY>` (`/healthz` hariç) ve en fazla 1.000.000 baytlık bir gövdeyle. Bilinmeyen bir alan, eksik ya da yanlış tipte bir alan 400; yazım hatası sessizce yok sayılmıyor.

Ortak, isteğe bağlı alanlar: `session_id`, `user_id` (oturum limitleri ve tool toplamları buna göre), `request_id` (bir isteğin olaylarını SIEM'de birleştiriyor).

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

Çağrı `args` ile çalıştırılmalı, modelin yazdığıyla değil: politika harfli etiketleri açtıysa ([katmanlar](layers.md#harfli-etiketler-vaultpy)) etiketler burada değerlerine dönmüş oluyor, örnekteki gibi. Engellenen çağrıda `null`: `action`'a bakmayı unutan uygulamanın çalıştıracağı argüman yok. `reasons` uygulama için; modele geri verilirse hangi kuralın aşılacağını söyler.

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

### `GET /healthz`

`{"status": "ok"}`; anahtar istemiyor, başka bir şey söylemiyor.

## Hatalar

```json
{"error": {"code": "bad_request", "message": "unknown field 'extra'"}}
```

| Durum | `code` | Ne zaman |
|---|---|---|
| 400 | `bad_request`, `bad_json`, `duplicate_key` | Gövde JSON nesnesi değil, okunamıyor (binlerce seviye iç içe, binlerce basamaklı sayı), bir nesnede aynı anahtar iki kez var (modelin JSON'unu olduğu gibi geçiren uygulamanın ayrıştırıcısı ilkini, Sieve sonuncusunu okurdu), alan bilinmiyor, eksik ya da yanlış tipte |
| 401 | `unauthorized` | Anahtar yok ya da yanlış |
| 404 / 405 | `not_found`, `method_not_allowed` | Yol ya da metot yanlış |
| 411 / 413 / 415 | `length_required`, `too_large`, `unsupported_media_type` | `Content-Length` yok, gövde büyük, JSON değil |
| 503 | `busy` | Bekleyen ya da çalışan 64 istek ya da açık 128 bağlantı var |
| 500 | `internal` | Sunucunun kendi hatası (kontroller kendi hatalarını block olarak cevaplıyor) |

Hata mesajı alanın adını söylüyor, değerini asla: istek kişisel veri taşıyabilir. Erişim logunda sadece metot, yol ve durum var; gövde ve query string yok.

**Uygulama 200 dışındaki her cevabı, zaman aşımını ve bağlantı hatasını block saymalı.** Sieve'e ulaşılamaması kontrol edilmemiş bir mesaj demek ([TH-15](../THREAT_MODEL.md#th-15-guard-failure)).

## Süre, sıra ve tekrar deneme

- **Bir kontrol en fazla `--timeout` saniye.** Aşarsa cevap `block`, `rules: ["layer_error"]`; SIEM olayında ayrıntı `timeout: TimeoutError`. Kontrol arka planda bitiyor ve kendi olayını da yazıyor; uygulama o sırada block'u almış oluyor.
- **Bir süreçte bir kontrol aynı anda çalışıyor.** Kiracının oturum durumu ortak; `TenantGuardrail` çağrıları bir kilitle sırayla çalıştırıyor (kütüphane olarak birden fazla thread'den kullanılınca da). Sırada bekleyen bir isteğin süresi de sayılıyor: önündeki yavaş bir kontrol onu da block'a düşürebilir. Saldırı altında sunucu durmuyor, block'a dönüyor; bu bir kullanılabilirlik bedeli ([TH-11](../THREAT_MODEL.md#th-11-resource-exhaustion)). Daha fazlası için birden fazla süreç; oturum limitleri o zaman süreç başına.
- **64'ten fazla istek beklerse 503.** Aynı anda en fazla 128 bağlantı açık; fazlası thread başlatılmadan 503 alıp kapanıyor. İki okuma arasında en fazla 10 saniye, isteğin tamamı için 20 saniye var: bayt bayt gönderen bir istemci bağlantıyı istediği kadar tutamıyor.
- **Her kontrolün okuduğu miktar sınırlı.** Gövde en fazla 1 MB, ama hiçbir kontrol o kadarını işlemiyor: 50.000 karakterden uzun bir mesaj okunmadan block (`input_too_large`); bir dokümanın ilk 200.000 karakteri okunuyor, fazlası kesilip review (`input_length`) ve `wrapped` de aynı yerden kesiliyor; argümanlarıyla 50.000 karakteri aşan bir tool çağrısı okunmadan block; 50.000 karakterden uzun bir cevap kesilip review (`output_length`); `user_data`'nın ilk 50.000 karakteri okunuyor. Bu cihazda (M4) en kötü durum 1 MB'lık bir doküman: kontrol ve `wrapped` birlikte 2,5 saniye civarı. ([TH-11](../THREAT_MODEL.md#th-11-resource-exhaustion))
- **Tekrar deneme güvenli.** Hata veren bir kontrol önbelleğe girmiyor, tekrarında baştan çalışıyor. Süresi dolan bir kontrol arka planda bitince sonucu (allow ya da block, gerçek karar) önbelleğe giriyor; tekrar deneme o gerçek kararı alıyor, ilk denemenin hatasını değil. Her deneme `session.rate_limit`'e sayılıyor, işaretlenen her deneme `session.repeat_offender`'a da; yani bir saldırıyı tekrar tekrar denemek limite takılıyor.
