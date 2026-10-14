# Security changelog

What testing found wrong in Sieve, and what changed. [THREAT_MODEL.md](THREAT_MODEL.md) says what holds now; this is how it got there. Entries are grouped by threat, oldest first, each with the commit that changed it and the corpus records that showed it. A record that led to a fix moves from `test` to `dev`, so it no longer counts as held-out ([section 7 of the threat model](THREAT_MODEL.md#7-attack-corpus)).

## TH-01 Direct prompt injection

**2026-10-03 · "diye" let any attack through** ([f80a51a](https://github.com/efronh/sieve/commit/f80a51a))
The ignore-instructions rule has an exception for reported speech, and it also matched "diye" and "diyorum", so adding either word to an attack let it through. It exempts only second- and third-person reported forms now ("demiştin", "dedi", "diyorlar").

**2026-10-03 · The default setup caught 0 of 30 held-out attacks** ([f80a51a](https://github.com/efronh/sieve/commit/f80a51a))
`Guardrail()` ran the ML layer in shadow mode, which left the rules alone: on the TCPI held-out set they flagged 0 of 30 attacks. The ML layer sends messages to review by default now, and still never blocks on its own: 22 of 30 flagged, 3 of 90 false alarms.

**2026-10-04 · "yok say" written as two words** ([ee9eadc](https://github.com/efronh/sieve/commit/ee9eadc))
TDK spells "yok saymak" as two words, but the rule only knew the joined "yoksay", so "Önceki tüm talimatları yok say" got through. 27 attacks in the data used the two-word spelling.

**2026-10-13 · Ordinary text around an attack hid it from the ML layer** ([9a8169d](https://github.com/efronh/sieve/commit/9a8169d))
A message was scored whole, and the ML layer catches 71 of the 79 corpus attacks the plain check flags on its own, so ordinary text around an attack diluted it: 800 characters on each side let all 71 through, and so did four sentences between its halves (the bypass suite's `structure` family; 378 of 474 rewrites got through). The rules and the ML layer now also read a message's sentences, pairs of them up to three apart, and runs of 10 and 20 words (windows of fewer than five words aren't read: "Aslında tam olarak değil." scored 0.89 alone). The strongest reading counts. 106 of 510 rewrites get through now, nearly all attacks the ML layer catches just over its threshold. The sealed set had the same weakness without anyone having looked for it: its independent source's attacks mostly come after a preamble, and 117 of its 258 are caught instead of 68, with still no false alarm in its 345 benign messages. No benign corpus record changed, and none of the 1,504 customer-service messages is flagged. That's the default setup. With TF-IDF alone, as in CI, the reading by sentence costs something: false alarms on the sealed set go from 11 to 16 of 379, all five among `pi1k`'s 34 messages written to look like attacks (11 to 16 of them); BERTurk takes them back out. `python -m scripts.benchmark_versions` measures every version of the branch with the same scripts and data, both ways. An 8,000-character message takes about 25 ms more, 40 with BERTurk.

## TH-02 Obfuscated injection

**2026-10-13 · Encodings, look-alike letters and other alphabets got past decoding** ([60d8e52](https://github.com/efronh/sieve/commit/60d8e52))
The corpus had one attack per trick, so a trick that failed showed as one miss among the detector's. The bypass suite keeps the attack and changes only the trick: of the 79 corpus attacks caught plainly (TF-IDF alone, as in CI), rewriting let through 814 of 1,817 encoded versions, 356 of 2,528 Unicode ones, 154 of 158 written in Cyrillic or Greek letters, and 375 of 3,588 placements in a document. Mostly not the decoders but what came after them: TF-IDF scored a decoded instruction together with the token it came from, whose letters pulled an attack caught by ML alone under its threshold (0.84 plainly, 0.81 as base64). Others were holes in decoding: URL-safe base64, lowercase base32, spaced or escaped hex, percent-encoding between letters, named entities, `\u` escapes and quoted-printable weren't decoded; base64 in MIME lines decoded to broken letters; a decoded text with a line break was thrown away as unprintable; small capitals, parenthesized and negative circled letters, Hangul fillers and the braille blank weren't letters or spaces to the checks; Greek look-alikes and Turkish written in another alphabet weren't read. Now 238 encoded versions get through, of which 237 are ROT13 or reversed text with no word naming them (a model needs to be told to decode those too), 66 Unicode ones (mostly words run together with no spaces), none in another alphabet, and 9 placements. No benign record in the corpus changed its decision, and the sealed held-out set's counts are the same; 67 corpus attacks are now flagged or blocked more strictly, and 48 of the 65 OBF records are flagged at the message entry instead of 43. Tests for each hole: [`tests/test_bypass.py`](tests/test_bypass.py).

## TH-03 System prompt extraction

**2026-10-13 · The canary and the prompt in other letters leaked** ([fa6a999](https://github.com/efronh/sieve/commit/fa6a999))
Both leak checks read the answer as it came, while masking then showed it after NFKC: the canary in full-width or mathematical letters passed and reached the user as plain letters, and so did a line of the prompt in them, in capitals, without its Turkish letters, or in tag characters. The bypass suite wrote the canary and a prompt line its 57 ways: 53 of 114 got through. Both checks now read the answer cleaned and folded as the input checks do, decoded, and in ROT13, backwards and with each word backwards (compared only with the canary and the prompt, so ordinary text can't match), and the prompt is also compared as runs of 40 letters, for an answer with no five words in a row (no spaces, a letter at a time). None of the 114 gets through; no benign answer in the corpus changed, and EXF-LEAK-008 is now blocked.

## TH-04 Indirect injection

**2026-10-06 · HTML attributes weren't read** ([d553af3](https://github.com/efronh/sieve/commit/d553af3))
Cutting a document dropped every tag with its attributes, while `wrap()` passed them to the model. One of 14 white-box documents hid its instruction in a `<meta>` description and passed. Attribute values of two words or more are read now, as hidden text whatever the attribute's name, and `wrap()` keeps only `href` and `src`. The replay now also puts every message attack in an attribute (`html_attribute`): 125 of 174 test placements are blocked, as many as in a comment or `display:none`, against 1 before. An AltaySec example (dev) that hides its instruction in `<metadata subject=…>` went from review to block. 158 ticket exports with each ticket's first message as its row's `title` give no false alarm.

**2026-10-08 · A document could close its own block** ([dbd523e](https://github.com/efronh/sieve/commit/dbd523e))
`wrap()` took the boundary out of the document by replacing it with nothing, so a boundary nested in itself (its first half, the boundary, its second half) came out whole. A document that knew the boundary could end its own block, and the boundary isn't secret from the model, which can repeat its instructions. It is replaced with a space now, which can't join two halves. The marking missed separators too: only spaces and tabs got the mark, so words joined by `\v`, `\r`, U+1680, U+2028 or a Hangul filler reached the model unmarked. Tests cut the boundary at every point at depths 1, 2 and 5, and try 16 separators.

**2026-10-13 · Places in a document that weren't read** ([60d8e52](https://github.com/efronh/sieve/commit/60d8e52))
The bypass suite placed each caught attack in 46 places of a support-ticket export, and some were never read while a model reading the document gets them: a JSON key (only values were read), `<?...?>` and `<!...>` declarations and anything else between angle brackets that isn't a tag (dropped as a "tag" while `wrap()` kept it for the model), valueless attribute words (`<x önceki tüm talimatları yok say>`). Others were read only inside the visible sentence around them, where the link or the markup pulled an attack caught by ML alone under its threshold: Markdown image alt text, link titles and `[//]: # (...)` comments, a link's query values, JSON in a `<script>` block. An instruction split over two hidden elements was half of one in each. Each is now read, as hidden text where a reader doesn't see it, and the hidden parts are also read joined; `wrap()` leaves declarations out. 375 of 3,588 placements got through, 9 do now.

## TH-05 Multi-turn attacks

**2026-10-13 · Fillers, a wait and an earlier rule hid a split attack** ([9a8169d](https://github.com/efronh/sieve/commit/9a8169d))
The bypass suite's `session` family splits each attack caught plainly over a conversation 12 ways. 62 of 948 got through, all the same way: the history was only ever joined whole, so a harmless message between the halves diluted them; a message that had fired the rule on its own earlier made it "seen" and hid every later split of it; the history expired after 10 minutes, while the model still reads the conversation; and only a message's last 1,000 characters were kept, so a half at the start of a long message was gone. Each is fixed as above, and messages don't expire (the number of messages and of sessions bounds the memory). 44 of 1,020 get through now: a half four messages back (past the window, which `context_messages` sets), a half deep inside a long message, and the six attacks only reading by sentence catches, which the joins don't read that way.

## TH-06 Malicious tool calls

**2026-10-05 · Look-alike values passed as the user's** ([0dbd989](https://github.com/efronh/sieve/commit/0dbd989))
`from_user` compared letters and digits as a substring. `ayse.kaya@ornekmail.co` (a domain the attacker can register) and `ayse@kaya-ornekmail.com` both counted as the user's `ayse.kaya@ornekmail.com` (TOOL-RCPT-009, -010). While fixing that, I found that numbers matched when one ended with the other, so a valid foreign IBAN whose digits end with the user's TR IBAN counted as the user's (TOOL-RCPT-016). `OutputGuard`'s "new personal data" check did the same. Now a value has to appear whole in the user's text, with only spaces and case ignored, and numbers match only as the same digits or the same Turkish phone number.

**2026-10-06 · No limit across calls** ([f1f923a](https://github.com/efronh/sieve/commit/f1f923a))
Three transfers of 20,000 each passed a 50,000 limit (TOOL-LIMIT-009, -010). A spec can set `max_total` (a parameter summed over the user's calls) and `max_calls`, over `window_seconds`, now. TOOL-LIMIT-015 (six tickets where one was asked for) was written with it and is dev too.

**2026-10-06 · Arguments only got the input rules** ([bc3059d](https://github.com/efronh/sieve/commit/bc3059d))
An instruction for the agent that summarises tickets passed (TOOL-ARGINJ-007). Arguments get the whole document check now, ML included. TOOL-ARGINJ-015, written with it, hides an instruction in an e-mail body's HTML and is blocked. A tool call took 0.6 ms instead of 0.1 with TF-IDF then, and no new false alarm came up in the 17 benign calls, with or without BERTurk.

**2026-10-06 · Line breaks and spreadsheet formulas in arguments** ([81961a7](https://github.com/efronh/sieve/commit/81961a7))
An e-mail subject with `\r\nBcc: …` (TOOL-ARGINJ-012), a complaint subject that writes a fake log line (-013), and `=HYPERLINK(…)` in a description that runs when the CRM is exported (-011) passed. A spec can declare a parameter `line` now, and a line break there blocks the call; an argument that starts like a formula or a DDE call is reviewed. TOOL-ARGINJ-016 (a DDE call) was written with the fix.

**2026-10-06 · Short personal data in a URL** ([3c7067f](https://github.com/efronh/sieve/commit/3c7067f))
A URL needed a value of 16 or more characters to count as carrying data, so an 11-digit TC in `?t=10000000146` passed (TOOL-RCPT-015). The URL's path segments, query keys and values, fragment and subdomain labels go through the masking layers now, key and value together, so `cvv=123` counts. TOOL-RCPT-017 (a TC as a subdomain, which leaves through the DNS lookup) was written with the fix.

**2026-10-13 · Refused calls made another way, and a key twice in one object** ([fa6a999](https://github.com/efronh/sieve/commit/fa6a999))
The bypass suite made each refused or held call again with another name (case, a trailing space, a zero-width character, a Cyrillic letter, a hyphen), other types for the amount (text, a float, an exponent, `true`, NaN, infinity, a negative, 10^30, a list, an object), an extra parameter, a list for the arguments, an instruction rewritten the 57 ways, a spreadsheet formula with something before it, and a link with data in eight forms: none of the 96 got through but data split into a path, as in TH-07. Over HTTP, a key twice in one object was read as its last value; a parser that keeps the first (several do) would have run a call with arguments Sieve never saw when the app passes the model's JSON on as it came. It's a 400 now (`duplicate_key`).

## TH-07 Exfiltration through the answer

**2026-10-06 · Answers didn't go through the policy** ([b66c86d](https://github.com/efronh/sieve/commit/b66c86d))
`OutputGuard` wasn't wired into `TenantGuardrail`, so its decisions didn't follow the tenant's policy and didn't reach the SIEM. `TenantGuardrail.check_output` checks answers through the policy now, like messages.

**2026-10-13 · A host Python and the browser read differently, and CSS that fetched** ([fa6a999](https://github.com/efronh/sieve/commit/fa6a999))
Hosts were read with Python's `urlsplit`, which a browser doesn't agree with: in `https://evil.example\@ornekbank.com.tr/?q=...` it takes the host after the `@`, the allowed one, while a browser reads the `\` as `/` and loads the image from `evil.example`, data and all. The checks now read a URL as the WHATWG URL Standard does (tabs and line breaks dropped, `\` as `/` in a web URL), in answers, tool arguments and messages alike. A subdomain no site would name itself (16 characters or more) now carries data, as it leaves with the DNS lookup. CSS `url()` and `@import`, in a style attribute or a `<style>` block, are removed like an image instead of being reviewed and left for the browser to fetch. The bypass suite sends one link through 30 channels (Markdown, HTML, CSS, entity-encoded, protocol-relative, data in the path, subdomain or fragment, the allowed host as user info or prefix): 2 got through, none does.

## TH-08 Personal data leaving in prompts or logs

**2026-10-07 · Four masking problems a labelled set showed** ([3feeffc](https://github.com/efronh/sieve/commit/3feeffc))
- `DocumentGuard.wrap()` didn't mask at all, so a retrieved page or a ticket reached the model with every TC number and card in it. 0 of the test set's values were masked in documents.
- Numbers were read as one run when fewer than four characters apart, and a window slid through the run. A checksum-valid window across the end of a phone number and the start of a card hid half of each and left the card's expiry date and CVV in the clear. A phone number right after a TC number wasn't masked at all. A TC- or IBAN-shaped stretch in the middle of a tracking number or a file hash was masked. The "i" in a suffix like "462'dir" counted as a 1.
- "şifrem: …" and "parolanız=…" weren't password keywords: Turkish puts the owner on the word.
- A tax number starting with 5 was masked as a phone number.

The 10 test records that showed these are dev now, and 5 written with the fix are dev too. Dev values went from 13 of 27 right to 27 in messages, and from 5 to 27 in documents; in the random test, 99.1% of valid numbers were masked whole instead of 83.5%, and 7.7% of reference numbers by mistake instead of 14.4%.

**2026-10-08 · The traffic log's session hash could be reversed** ([d8a969e](https://github.com/efronh/sieve/commit/d8a969e))
The traffic log hashed session IDs without a key, so a phone number used as one could be found by hashing every number. It uses the SIEM's keyed pseudonym now. In the same commit: `OutputGuard` reported personal data masked whenever cleaning changed the answer, a no-break space included; it needs a masked value now.

**2026-10-08 · Three rules took more than personal data** ([f9d2148](https://github.com/efronh/sieve/commit/f9d2148))
Measuring what masking costs found them:
- After "şifremi", a word with a symbol in it was a password, and the full stop that ends a sentence counted: "Hesap şifremi unuttum." reached the model as "Hesap şifremi [SIFRE]".
- A foreign IBAN was tried at every length from 15 to 34, reading on through spaces and dashes into the next words, whatever its two letters were. About one start in five found a length that passed mod 97, and an order number with the three words after it became `[IBAN]`.
- A bare 10-digit number starting with 5 was a mobile number even right after "Sipariş numaram".

Wrong masks in 1,900 benign texts went from 8 of 124 to 1 of 117. In the random test, 48 more valid numbers aren't masked (98.7%, from 99.1%), phone numbers the generator put right after "Sipariş ", and 90 fewer reference numbers are (6.2%, from 7.7%). The labelled set's baseline didn't move.

**2026-10-13 · What Sieve writes leaked the prompt, paths and field names** ([0bdb41b](https://github.com/efronh/sieve/commit/0bdb41b))
What Sieve itself writes was checked value by value only for masking. [`tests/test_data_leaks.py`](tests/test_data_leaks.py) now puts marked secrets (a TC number, an IBAN, a card, a password, an API key, an e-mail address and phone number, a secret in the system prompt, the canary, Sieve's API key and the pseudonym key, and IDs an app might pass) through every entry point, in four policies, with every layer, the policy code and the server failing, and collects everything: every logger, stdout and stderr, events as JSON and CEF, HTTP answers and headers, errors and the access log. Against the old code it found:
- An answer that leaked the system prompt went into the output event's excerpt, canary and all, so whoever read the SIEM read the prompt. The event's text is `[SISTEM_PROMPTU]` now when `canary` or `prompt_overlap` fired; the rules say what leaked.
- The access log wrote the path as it came: `POST /v1/check/10000000146 404`. A malformed request line, which `http.server` puts in its error message, was logged too. Only a known method, a known path and a status are logged now.
- An unknown field was named in the 400, and the app may pass on JSON the model wrote, whose keys are anything. A key that isn't a field name isn't echoed.

It also checks that no value can split an event (a NUL, a line break, a forged `CEF:0|` header in the text, the IDs, a tool's name and its keys): JSON escapes control characters and CEF its separators, so none did. Beside it:
- The traffic log and its directory were made readable by every user on the machine (0644 in 0755). They're made 0600 and 0700 now; a file already there keeps its mode.
- Over TCP every event crossed the network readable. `syslog_handler(..., tls=True, cafile=...)` and the server's `--siem-tls` / `--siem-ca` send over TLS, checking the collector's certificate; one that doesn't verify is a failed connection, counted like the others.
- Without `SIEVE_PSEUDONYM_KEY` only the server said so. The library says it too, once per process: a TC number used as the user ID is one of about a billion, and hashing them all takes seconds.

## TH-09 Another customer's data in the answer

**2026-10-13 · Personal data encoded in an answer** ([fa6a999](https://github.com/efronh/sieve/commit/fa6a999))
Personal data written encoded wasn't seen: masking can't reach it where it stands, and the new-data check only read what masking replaced. A TC number in base64 or hex (EXF-PII-014) passed, and the decoder threw a decoded run of digits away as noise. The answer check now decodes digits too and reads personal data from what it decodes: `output_masking.encoded_personal_data`, review, unless it's the user's own, with or without `user_data`.

## TH-10 Active content in the answer

**2026-10-07 · Answers that take the user somewhere else** ([605e079](https://github.com/efronh/sieve/commit/605e079))
A phishing form posting to another host, a link whose text showed the bank's address, and a meta refresh passed (three OUT-ACTIVE records, dev now). A form sending outside the allowed hosts loses its tag now, a link whose text reads as an address and goes elsewhere becomes its text, and a meta refresh or `<base>` pointing outside is removed; all go to review. Link text with one level of brackets (`[Hesabım [güvenli]](javascript:...)`) went through as plain text and is read now.

## TH-11 Resource exhaustion

**2026-10-06 · Deep nesting crashed the document and tool checks** ([347f040](https://github.com/efronh/sieve/commit/347f040))
I found this while writing the threat model: JSON nested a few thousand levels deep raised `RecursionError` in `DocumentGuard.check` and `ToolGuard.check`. While fixing it, I found a second one: HTML comments inside hidden `div`s, 1,500 levels deep. Both get a decision now instead of an exception, and an attack ten levels deep is still read and blocked.

**2026-10-06 · The hidden-HTML pattern was quadratic** ([d553af3](https://github.com/efronh/sieve/commit/d553af3))
From every `<` it scanned the rest of the document for a closing tag. 200 KB of `<a ` took 4 minutes to cut into parts, and 195 KB of unclosed `<div hidden>` 16 seconds. The same inputs take 12–19 ms now.

**2026-10-06 · Masking and eight patterns grew faster than their input** ([08241bb](https://github.com/efronh/sieve/commit/08241bb))
For every look-alike digit (`ı`, `l`, `|`, `o`…) masking walked out to both ends of its word again, so one long word cost its length squared: 2,000 `ı` took 1.5 seconds and 8,000 kept `Guardrail.check` busy for over 20. Eight patterns rescanned the text from every start: `URL_PASSWORD` in masking; four code rules, which see a tool argument whole (`sql_comment_bypass`, `sql_stacked_query`, `shell_pipe_to_shell`, `template_injection`); `fake_system_line`; and the Markdown link, image and reference patterns and the HTML tag pattern in `OutputGuard`. 100 KB of `a-` took over 5 seconds in `URL_PASSWORD`, 50 KB of one letter over 5 in the code rules, 400 KB of `<a ` over 15 in `OutputGuard`. Each word is read once now, and each pattern starts only where a match can begin or stops at the last character a match can end on. No decision on the corpus changed; `OutputGuard` keeps the blank lines before a reference it removes, and reads `![a [b](url)` as the link it is in CommonMark. `scripts/fuzz_slow_inputs.py` came from this.

**2026-10-13 · Nothing bounded what one request could cost** ([185f9ae](https://github.com/efronh/sieve/commit/185f9ae))
Measuring every entry point at the server's 1 MB body showed no input whose cost was bounded except by the body. Masking reads everything the model gets, at up to 13 µs a character on a run of digits: 1 MB took 13 seconds as a message, an answer or a tool call, and a document's event masked all of it although the check read 200,000 characters. `wrap()` gave the model the whole document, so an instruction past 200,000 characters reached it unread, with only a review. The ML layer's second stage ran once per unsure sentence at 17 to 20 ms: a 12,000-character document of them took 7 seconds, 50,000 characters 28. With one worker, one such request held up every check behind it. Now each entry point has the limits above; masking tries a window's number as a slice and its real digits as a difference instead of joining and summing every window again (2.7 times faster, the same output on 20,000 random texts and the PII corpus); the second stage reads a document's parts in one batch (1,600 unsure sentences: 0.28 seconds) within a budget. No record of the corpus changes its decision, with or without BERTurk. At 1 MB every entry point now takes at most 1.2 seconds on this machine, a document the most.

Concurrency had its own failures. `TenantGuardrail` had no lock: from 8 threads at once, 102 of 3,200 messages were blocked by a check that raised mid-update (`policy: RuntimeError`), and two calls to a `ToolGuard` could both read a `max_total` before either was recorded, so 8 threads moved 1,020 to 1,040 against a limit of 1,000. The session limiter kept every session ever flagged, unbounded. The server started a thread for every connection, with no limit, and its socket timeout counts per read, so a client sending a byte every few seconds held one for as long as it liked; JSON nested too deep or a number too long to read dropped the connection without an answer. Each is fixed and tested.

## TH-13 Model and training data integrity

**2026-10-13 · A swapped model file would have been unpickled** ([10ab693](https://github.com/efronh/sieve/commit/10ab693))
`joblib.load` is pickle, and the model file was loaded without a check: whoever could write `models/prompt_injection_tr.joblib` could run code in the app, and the threat model listed it as a residual risk. The file is checked against `MODEL_SHA256` before it's opened now, and retraining rewrites that pin. BERTurk was loaded by name, so whatever its repository held that day was used; it and the scripts' models are pinned to the commits the results were measured with.

**2026-10-14 · Nothing locked or scanned the dependencies, the code or the history** ([f3b305b](https://github.com/efronh/sieve/commit/f3b305b))
The first gitleaks run found 9 secrets in the history; all were synthetic, put there to test masking and the leak checks (a fake Stripe key, GitHub token and JWT). Each value is allowed by itself. GitHub's push protection then refused the fake Stripe key, which looked like a live one; the leak test uses a random token instead, which masking catches as well, and the key was taken out of the unpushed commits. Allowing them only under `tests/` with gitleaks' `condition = "AND"` let every secret under `tests/` through (gitleaks 8.30), which a planted key showed; that config isn't used. bandit's two findings were a deliberate silent `except` on the path where sending an event fails, and the `[SIFRE]` mask label; each is marked with its reason. pip-audit finds no known vulnerability in the 72 locked packages.

## TH-14 Policy misconfiguration

**2026-10-12 · A tenant's own version hid changes to the base policy** ([6fdd41d](https://github.com/efronh/sieve/commit/6fdd41d))
A tenant that set its own `version` kept the same `policy_version` in its events while the thresholds or layers it inherits from `default.toml` changed under it, so a SIEM watching the version saw nothing. Its version names both now (`2026-09-24.1+default.2026-10-12.1`). `default.toml` itself had changed without a new version, left out the four answer checks a policy can set, the `line` type and the `max_total`, `max_calls` and `window_seconds` tool keys, and had stale comments.

**2026-10-12 · A lower ML threshold didn't reach documents or tool arguments** ([e2903a9](https://github.com/efronh/sieve/commit/e2903a9))
`DocumentGuard` dropped every allowed finding without a match when it merged a document's parts, the ML layer's quiet score among them. A `[thresholds.prompt_injection_ml]` below the layer's own threshold reviewed a message and let the same text through as a document or a tool argument. Found by the threshold sweep.

**2026-10-12 · The split check ignored the policy's thresholds** ([2b88147](https://github.com/efronh/sieve/commit/2b88147))
The session's split check decided the last messages joined by the layers' own thresholds, so a policy that raised the ML threshold still got `session_split` reviews at the layer's 0.76. It counts a finding as the policy's thresholds for messages do now.

**2026-10-13 · A layer set to off still counted in messages** ([3085fc1](https://github.com/efronh/sieve/commit/3085fc1))
`check()` didn't leave out the findings of a layer the policy turns off. `build_guardrail` never builds such a layer, but an app that passed its own `Guardrail` got them counted. Every entry point leaves them out now.

**2026-10-13 · Policy values of the wrong kind, and a Guardrail missing a layer** ([b2f0252](https://github.com/efronh/sieve/commit/b2f0252))
Only names were checked, not values. A value of the wrong kind loaded and then failed or misled at run time: `max_check_chars = "8000"` blocked every message, `0` read nothing and only reviewed (an attack that blocks got review), a negative `cooldown_seconds` never paused anyone, `window_seconds = "600"` blocked every message, `allowed_hosts = "ornekbank.com.tr"` became a set of letters, and `allowed_hosts = ["com"]` let every `.com` link through in answers and tool arguments, which allow subdomains of an allowed host. A misspelled `[url_check]` key was ignored. Now every top-level key has a type, the session limits are whole numbers with a minimum, an allowed host has to be a host name with a dot (no scheme, path or `*`), and `[url_check]` keys are checked. `TenantGuardrail` given a `Guardrail` of the app's own used to accept one without a layer the policy runs, and that layer was never asked; it now refuses it unless the policy sets that layer to `off`. Loading a policy now also warns about monitor mode, `on_error` other than `block`, a layer in shadow or off, and every disabled rule, not only `[actions]` and `[thresholds]` ([`tests/test_policy_safety.py`](tests/test_policy_safety.py)).

## TH-15 Guard failure

**2026-10-06 · The ML layer could drop out without a word** ([347f040](https://github.com/efronh/sieve/commit/347f040))
If the model file was missing or scikit-learn wasn't installed, the ML layer dropped out without an error or a log line, even when the policy said `prompt_injection_ml = "enforce"`: a silent fail-open on the main detector for TH-01. `TenantGuardrail` fails at start now when the policy wants the layer and it's unavailable, `Guardrail()` and `DocumentGuard()` log a warning, and the CI gate fails.

**2026-10-06 · A failing check reached the app as an exception** ([826228d](https://github.com/efronh/sieve/commit/826228d))
A layer that raised reached the app as an exception, and nothing said whether that meant block. Every check fails closed now, with `on_error` in the policy to choose otherwise, and unit tests inject a failure into each check and count the model calls.

**2026-10-08 · A bracket in a URL's host blocked the message** ([72f84d2](https://github.com/efronh/sieve/commit/72f84d2))
Failing closed makes every exception a block, so an input that makes a check raise is a false block anyone can cause. `http://[ornekbank` was one: `urlsplit` raises on a host it can't read, and the URL check didn't catch it. A typo blocked the message, and an outside author could get a whole document or tool argument dropped. In a session it was worse: the split check reads the masked history, where `http://ayse.kaya@ornekmail.com` is `http://[EPOSTA]`, and its error blocked whatever `on_error` said. A valid IPv6 host failed too. `scripts/fuzz_slow_inputs.py` reports any input that makes a check raise since.

**2026-10-08 · A failing layer took the other checks with it** ([5d3693c](https://github.com/efronh/sieve/commit/5d3693c))
In `DocumentGuard` the first failure stopped the rest, so with `on_error = "review"` a document whose URL check raised passed with review, its hidden instruction never looked at. In `ToolGuard`, the code rules failing on an argument dropped the spec's findings: a transfer over its limit went to review. The split check had no handler, so a layer failing on the session's history was a failure of the policy code, a block whatever `on_error` said. A document's failures were merged into one finding that the first layer's mode decided, so a shadow layer's failure could hide an enforced one's.

**2026-10-08 · A check failing on the history paused the session** ([8017755](https://github.com/efronh/sieve/commit/8017755))
With `on_error = "review"`, a layer failing on one message's history counted every later message as flagged and paused the session: a block for messages nothing was found in. Only a message's own findings count toward `repeat_offender` now.

**2026-10-08 · The audit trail couldn't see its own failures** ([c13a90c](https://github.com/efronh/sieve/commit/c13a90c))
`syslog_handler` used UDP, which drops an event without a word. Python's `SysLogHandler` over TCP raised at start when the collector was down, kept a broken connection for good (every later event lost) and had no timeout, and a handler's error only reaches stderr. CEF lost the user, the mode and which rules were only shadowed or suppressed. TCP is the default now, `SiemHandler` reconnects, times out and counts its failures, and events carry `instance`, `seq`, `checked` and a `request_id`, so a lost one is a gap the SIEM can see.

**2026-10-13 · A failing tool spec skipped the argument checks** ([b2f0252](https://github.com/efronh/sieve/commit/b2f0252))
In `ToolGuard` the reverse still held: the spec check raising skipped the argument checks, and its error was the `tool_call` layer's. With `tool_call` in shadow or off, that error decided nothing, so a call whose argument carried an instruction went through unread. A failure of the whole check was named `tool_call` too, so the same policy let through a call nothing had looked at. Now the spec failing leaves the argument checks running, and a whole-check failure is `tool_guard`, which only `on_error` decides. A blocked call also no longer returns its arguments (`args` is `None`, `null` over HTTP), so an app that forgets to look at `action` has nothing to run it with. A test now breaks each layer of each entry point in turn, in shadow and in off, and checks that the decision is the one the working layers make ([`tests/test_policy_safety.py`](tests/test_policy_safety.py)).
