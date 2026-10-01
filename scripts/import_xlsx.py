import csv
import re
import sys
from pathlib import Path

import openpyxl

from sieve.paths import DATA

SOURCE = Path.home() / "Desktop" / "yapay_zeka_saldiri_veriseti.xlsx"
TARGET = DATA / "external_attacks.csv"

CATEGORIES = {
    "Prompt enjeksiyonu": "prompt_injection",
    "SQL enjeksiyonu": "sql_injection",
    "Gizleme": "obfuscation",
    "Çok turlu saldırı": "multi_turn",
    "Veri sızdırma": "data_exfiltration",
}

TURN_MARKER = re.compile(r"(?:^|\s*\|\s*)(?:T|Tur )\d+:\s*")

DESCRIPTION_ONLY_ROWS = {151, 152, 161, 162, 163, 164, 165, 166, 181, 182}


def read_sheet(workbook, name):
    rows = list(workbook[name].iter_rows(values_only=True))
    return rows[1:]


def remove_turn_markers(text):
    turns = [t.strip().strip("'\"") for t in TURN_MARKER.split(text) if t.strip()]
    return "\n".join(turns)


def family(prefix, number):
    return f"{prefix}{(number + 1) // 2:03d}"


def main(source=SOURCE):
    workbook = openpyxl.load_workbook(source, read_only=True)
    output = []
    skipped = []

    for number, category, text, language, _source in read_sheet(workbook, "Saldırılar"):
        if number in DESCRIPTION_ONLY_ROWS:
            skipped.append((number, text))
            continue
        if category == "Çok turlu saldırı":
            text = remove_turn_markers(text)
        output.append((text, 1, CATEGORIES[category], family("ext_atk", number), language.lower()))

    for number, _context, text, language, _trigger, _source in read_sheet(workbook, "Masum Örnekler"):
        output.append((text, 0, "benign_technical", family("ext_ben", number), language.lower()))

    with open(TARGET, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["text", "label", "category", "family", "language"])
        writer.writerows(output)

    print(f"wrote {len(output)} rows to {TARGET.name}")
    print(f"skipped {len(skipped)} rows that describe a technique instead of containing one:")
    for number, text in skipped:
        print(f"  {number}: {text[:80]}")


if __name__ == "__main__":
    main(Path(sys.argv[1]) if len(sys.argv) > 1 else SOURCE)
