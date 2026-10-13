# Security changelog

What testing found wrong in Sieve, and what changed. [THREAT_MODEL.md](THREAT_MODEL.md) says what holds now; this is how it got there. Entries are grouped by threat, oldest first, each with the commit that changed it and the corpus records that showed it. A record that led to a fix moves from `test` to `dev`, so it no longer counts as held-out ([section 7 of the threat model](THREAT_MODEL.md#7-attack-corpus)).

## TH-01 Direct prompt injection

**2026-10-03 · "diye" let any attack through** ([f80a51a](https://github.com/efronh/sieve/commit/f80a51a))
The ignore-instructions rule has an exception for reported speech, and it also matched "diye" and "diyorum", so adding either word to an attack let it through. It exempts only second- and third-person reported forms now ("demiştin", "dedi", "diyorlar").

**2026-10-03 · The default setup caught 0 of 30 held-out attacks** ([f80a51a](https://github.com/efronh/sieve/commit/f80a51a))
`Guardrail()` ran the ML layer in shadow mode, which left the rules alone: on the TCPI held-out set they flagged 0 of 30 attacks. The ML layer sends messages to review by default now, and still never blocks on its own: 22 of 30 flagged, 3 of 90 false alarms.

**2026-10-04 · "yok say" written as two words** ([ee9eadc](https://github.com/efronh/sieve/commit/ee9eadc))
TDK spells "yok saymak" as two words, but the rule only knew the joined "yoksay", so "Önceki tüm talimatları yok say" got through. 27 attacks in the data used the two-word spelling.

## TH-04 Indirect injection

**2026-10-06 · HTML attributes weren't read** ([d553af3](https://github.com/efronh/sieve/commit/d553af3))
Cutting a document dropped every tag with its attributes, while `wrap()` passed them to the model. One of 14 white-box documents hid its instruction in a `<meta>` description and passed. Attribute values of two words or more are read now, as hidden text whatever the attribute's name, and `wrap()` keeps only `href` and `src`. The replay now also puts every message attack in an attribute (`html_attribute`): 125 of 174 test placements are blocked, as many as in a comment or `display:none`, against 1 before. An AltaySec example (dev) that hides its instruction in `<metadata subject=…>` went from review to block. 158 ticket exports with each ticket's first message as its row's `title` give no false alarm.

**2026-10-08 · A document could close its own block** ([dbd523e](https://github.com/efronh/sieve/commit/dbd523e))
`wrap()` took the boundary out of the document by replacing it with nothing, so a boundary nested in itself (its first half, the boundary, its second half) came out whole. A document that knew the boundary could end its own block, and the boundary isn't secret from the model, which can repeat its instructions. It is replaced with a space now, which can't join two halves. The marking missed separators too: only spaces and tabs got the mark, so words joined by `\v`, `\r`, U+1680, U+2028 or a Hangul filler reached the model unmarked. Tests cut the boundary at every point at depths 1, 2 and 5, and try 16 separators.

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

## TH-07 Exfiltration through the answer

**2026-10-06 · Answers didn't go through the policy** ([b66c86d](https://github.com/efronh/sieve/commit/b66c86d))
`OutputGuard` wasn't wired into `TenantGuardrail`, so its decisions didn't follow the tenant's policy and didn't reach the SIEM. `TenantGuardrail.check_output` checks answers through the policy now, like messages.

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

## TH-13 Model and training data integrity

**2026-10-13 · A swapped model file would have been unpickled** ([10ab693](https://github.com/efronh/sieve/commit/10ab693))
`joblib.load` is pickle, and the model file was loaded without a check: whoever could write `models/prompt_injection_tr.joblib` could run code in the app, and the threat model listed it as a residual risk. The file is checked against `MODEL_SHA256` before it's opened now, and retraining rewrites that pin. BERTurk was loaded by name, so whatever its repository held that day was used; it and the scripts' models are pinned to the commits the results were measured with.

## TH-14 Policy misconfiguration

**2026-10-12 · A tenant's own version hid changes to the base policy** ([6fdd41d](https://github.com/efronh/sieve/commit/6fdd41d))
A tenant that set its own `version` kept the same `policy_version` in its events while the thresholds or layers it inherits from `default.toml` changed under it, so a SIEM watching the version saw nothing. Its version names both now (`2026-09-24.1+default.2026-10-12.1`). `default.toml` itself had changed without a new version, left out the four answer checks a policy can set, the `line` type and the `max_total`, `max_calls` and `window_seconds` tool keys, and had stale comments.

**2026-10-12 · A lower ML threshold didn't reach documents or tool arguments** ([e2903a9](https://github.com/efronh/sieve/commit/e2903a9))
`DocumentGuard` dropped every allowed finding without a match when it merged a document's parts, the ML layer's quiet score among them. A `[thresholds.prompt_injection_ml]` below the layer's own threshold reviewed a message and let the same text through as a document or a tool argument. Found by the threshold sweep.

**2026-10-12 · The split check ignored the policy's thresholds** ([2b88147](https://github.com/efronh/sieve/commit/2b88147))
The session's split check decided the last messages joined by the layers' own thresholds, so a policy that raised the ML threshold still got `session_split` reviews at the layer's 0.76. It counts a finding as the policy's thresholds for messages do now.

**2026-10-13 · A layer set to off still counted in messages** ([3085fc1](https://github.com/efronh/sieve/commit/3085fc1))
`check()` didn't leave out the findings of a layer the policy turns off. `build_guardrail` never builds such a layer, but an app that passed its own `Guardrail` got them counted. Every entry point leaves them out now.

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
