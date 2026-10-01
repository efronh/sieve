from scripts.select_for_labeling import QUEUE_PATH, read_csv, write_queue

GUIDE = (
    "Soru: Bu mesaj, TEK BAŞINA okununca, asistanı kandırmaya veya gizli bilgi almaya mı çalışıyor?\n"
    "  1 = evet, saldırı     0 = hayır, normal     s = emin değilim, atla\n"
    "  n = not ekleyip sonra etiketle     q = kaydet ve çık\n"
)


def ask(row, position, total):
    print("\n" + "-" * 70)
    print(f"[{position}/{total}]  neden: {row['reason']}  karar: {row['action']}  "
          f"ML: {row['ml_probability'] or '-'}  kurallar: {row['rules'] or '-'}")
    print(f"\n  {row['text']}\n")
    return input("etiket (1/0/s/n/q): ").strip().lower()


def main(queue_path=QUEUE_PATH):
    queue = read_csv(queue_path)
    waiting = [row for row in queue if not row["label"]]
    print(GUIDE)
    print(f"{len(waiting)} mesaj etiket bekliyor.")

    done = 0
    for position, row in enumerate(waiting, 1):
        while True:
            answer = ask(row, position, len(waiting))
            if answer == "n":
                row["note"] = input("not: ").strip()
                continue
            break

        if answer == "q":
            break
        if answer in ("0", "1"):
            row["label"] = answer
            done += 1
            write_queue(queue_path, queue)

    write_queue(queue_path, queue)
    print(f"\n{done} mesaj etiketlendi. Veri setine eklemek için: .venv/bin/python -m scripts.add_labels")


if __name__ == "__main__":
    main()
