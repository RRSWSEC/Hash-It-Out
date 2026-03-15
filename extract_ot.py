import re
import os
import csv
from decimal import Decimal, InvalidOperation

import pandas as pd
from pypdf import PdfReader, PdfWriter
import pdfplumber

PAYSTUB_DIR = "paystubs"
OUTPUT_CSV = "overtime_summary.csv"

# If every stub uses the same password, set it here and ignore passwords.csv
GLOBAL_PASSWORD = "zenk2652"  # e.g. "MMDDYYYY" or whatever. Leave "" to use passwords.csv only.

# Optional: per-file passwords.
# Create a passwords.csv with columns: filename,password
# PASSWORDS_CSV = "passwords.csv"

# ---- What to look for (you can tune these once you see your stub text) ----
OT_HOURS_PATTERNS = [
    # examples: "Overtime 5.25", "OT Hours: 3.50", "OT Hrs 2.0"
    re.compile(r"(overtime|ot)\s*(hours|hrs)?\s*[:\-]?\s*([0-9]+(?:\.[0-9]+)?)", re.IGNORECASE),
]

OT_PAY_PATTERNS = [
    # examples: "Overtime $123.45", "OT Pay: 98.76", "OT Earnings 150.00"
    re.compile(r"(overtime|ot)\s*(pay|earnings|wages)?\s*[:\-]?\s*\$?\s*([0-9,]+(?:\.[0-9]{2})?)", re.IGNORECASE),
]

# If you mean "deductible portion" as in "OT premium only" or "OT earnings above base",
# you may need a different rule. This script captures the OT lines it can find.
# We can refine after you see the output columns.


def load_password_map():
    pw_map = {}
    if os.path.exists(PASSWORDS_CSV):
        with open(PASSWORDS_CSV, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                pw_map[row["filename"]] = row["password"]
    return pw_map


def safe_decimal(s: str):
    try:
        return Decimal(s.replace(",", ""))
    except (InvalidOperation, AttributeError):
        return None


def extract_text_from_pdf(path: str, password: str | None):
    # Use pdfplumber which can handle password-protected PDFs
    try:
        with pdfplumber.open(path, password=password) as pdf:
            texts = []
            for page in pdf.pages:
                t = page.extract_text() or ""
                texts.append(t)
            return "\n".join(texts)
    except Exception as e:
        return None, str(e)


def find_first_match(patterns, text):
    for pat in patterns:
        m = pat.search(text)
        if m:
            return m.group(3)
    return None


def main():
    pw_map = load_password_map()
    rows = []

    for fn in sorted(os.listdir(PAYSTUB_DIR)):
        if not fn.lower().endswith(".pdf"):
            continue

        path = os.path.join(PAYSTUB_DIR, fn)
        pw = GLOBAL_PASSWORD or pw_map.get(fn)

        text_or_none = None
        err = None

        result = extract_text_from_pdf(path, pw)
        if isinstance(result, tuple):
            text_or_none, err = result
        else:
            text_or_none = result

        if not text_or_none:
            rows.append({
                "filename": fn,
                "ot_hours": None,
                "ot_pay": None,
                "status": f"FAILED_TEXT_EXTRACT: {err or 'unknown'}",
            })
            continue

        ot_hours_str = find_first_match(OT_HOURS_PATTERNS, text_or_none)
        ot_pay_str = find_first_match(OT_PAY_PATTERNS, text_or_none)

        ot_hours = safe_decimal(ot_hours_str) if ot_hours_str else None
        ot_pay = safe_decimal(ot_pay_str) if ot_pay_str else None

        rows.append({
            "filename": fn,
            "ot_hours": float(ot_hours) if ot_hours is not None else None,
            "ot_pay": float(ot_pay) if ot_pay is not None else None,
            "status": "OK" if (ot_hours is not None or ot_pay is not None) else "NO_OT_FOUND",
        })

    df = pd.DataFrame(rows)
    df.to_csv(OUTPUT_CSV, index=False)

    # Totals (ignore None)
    total_hours = df["ot_hours"].dropna().sum() if "ot_hours" in df else 0
    total_pay = df["ot_pay"].dropna().sum() if "ot_pay" in df else 0

    print(f"Wrote {OUTPUT_CSV}")
    print(f"Total OT hours: {total_hours}")
    print(f"Total OT pay:   {total_pay}")


if __name__ == "__main__":
    main()
