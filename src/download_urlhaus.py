import requests
import os
import zipfile
import io

URLHAUS_SOURCES = [
    # "Online" feed — plain CSV, currently-active malware URLs
    {
        "url"     : "https://urlhaus.abuse.ch/downloads/csv_online/",
        "is_zip"  : False,
    },
    # Full historical dump — served as a ZIP containing csv.txt
    {
        "url"     : "https://urlhaus.abuse.ch/downloads/csv/",
        "is_zip"  : True,
        "zip_name": "csv.txt",   # filename inside the archive
    },
]

SAVE_DIR  = "../data/raw/"
SAVE_PATH = os.path.join(SAVE_DIR, "urlhaus.csv")
MIN_ROWS  = 40_000   # aim for this many rows before stopping


def count_data_rows(text: str) -> int:
    """Count non-comment, non-empty lines (excluding the header)."""
    lines = [l for l in text.splitlines() if l and not l.startswith("#")]
    return max(0, len(lines) - 1)  # subtract 1 for the header row


def download_urlhaus_data():
    os.makedirs(SAVE_DIR, exist_ok=True)

    for source in URLHAUS_SOURCES:
        url = source["url"]
        print(f"📥 Trying {url} …")
        try:
            response = requests.get(url, timeout=180)
            response.raise_for_status()

            if source["is_zip"]:
                # ── The full dump is a ZIP file ──────────────────────────────
                print("   📦 Response is a ZIP — extracting …")
                try:
                    with zipfile.ZipFile(io.BytesIO(response.content)) as zf:
                        # Find the CSV/TXT entry (usually 'csv.txt')
                        names = zf.namelist()
                        target = source.get("zip_name", names[0])
                        if target not in names:
                            target = names[0]   # fallback to first entry
                        print(f"   📄 Reading '{target}' from archive …")
                        raw_bytes = zf.read(target)
                        # Decode with latin-1 to handle all byte values
                        csv_text = raw_bytes.decode("latin-1", errors="replace")
                except zipfile.BadZipFile:
                    print("   ⚠️  Response claimed ZIP but wasn't — treating as plain CSV.")
                    csv_text = response.content.decode("latin-1", errors="replace")
            else:
                csv_text = response.content.decode("latin-1", errors="replace")

            # Save the plain CSV text to disk
            with open(SAVE_PATH, "w", encoding="utf-8", errors="replace") as f:
                f.write(csv_text)

            n_rows = count_data_rows(csv_text)
            print(f"✅ Saved {n_rows:,} data rows → {SAVE_PATH}")

            if n_rows >= MIN_ROWS:
                print(f"   ✔  Sufficient data ({n_rows:,} rows) for 1-lakh dataset.")
                return
            else:
                print(f"   Only {n_rows:,} rows — trying next source …")

        except Exception as e:
            print(f"❌ Error: {e}")

    print(
        "\n⚠️  Warning: Could not reach 50 k malicious rows from URLhaus.\n"
        "   The dataset will be smaller but still balanced (1:1 ratio).\n"
        "   Consider supplementing with PhishTank or OpenPhish data."
    )


if __name__ == "__main__":
    download_urlhaus_data()