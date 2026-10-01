import csv
import json

from sieve.paths import DATA

SOURCE = DATA / "altaysec_train.jsonl"
TARGET = DATA / "altaysec.csv"

NOT_AN_ATTACK_ON_ITS_OWN = {
    "asama_1_giris": "friendly opener, no request yet",
    "asama_2_guven": "friendly opener, no request yet",
    "son_istek": "asks to ask one more thing, no request yet",
    "hayal_kirikligi": "pressure without a request",
    "kalp_kirildi": "pressure without a request",
    "ceviri_kodadi": "translates text the user wrote",
    "ozel_isim_koru": "translates text the user wrote",
    "audio_diagnostic": "repeats text the user wrote",
    "format_kontrol": "repeats text the user wrote",
    "yazim_denetimi": "proofreads text the user wrote",
    "iban_ceviri": "translates text the user wrote",
    "json_format": "formats text the user wrote",
    "alinti_kontrol": "quotes text the user wrote",
    "markdown_donus": "formats text the user wrote",
    "vatani_gorev": "biased translation, not an injection",
}


def load(path=SOURCE):
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def main():
    rows = load()
    output = []
    skipped = []

    for row in rows:
        if row["subcategory"] in NOT_AN_ATTACK_ON_ITS_OWN:
            skipped.append(row)
            continue
        output.append((row["prompt"], 1, f"altay_{row['category']}", f"alt_{row['category']}", "tr"))

    with open(TARGET, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["text", "label", "category", "family", "language"])
        writer.writerows(output)

    print(f"wrote {len(output)} rows to {TARGET.name}, skipped {len(skipped)}:")
    for row in skipped:
        print(f"  {row['subcategory']:18} {NOT_AN_ATTACK_ON_ITS_OWN[row['subcategory']]}")


if __name__ == "__main__":
    main()
