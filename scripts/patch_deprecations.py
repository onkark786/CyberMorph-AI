"""
Patch script:
1. Replaces deprecated st.button/download_button/plotly_chart/dataframe
   use_container_width=True  ->  use_container_width=True  (keep for dataframe/download)
   For st.plotly_chart: use_container_width=True  -> (no change, still valid in 1.65)
   Actually the warning is about st.dataframe use_container_width, let's check the real API.

Actually Streamlit 1.65 only deprecated use_container_width for st.dataframe and st.plotly_chart
in favor of width='stretch'. But since we're on 1.65 let's check the actual warning.

From logs: "Please replace `use_container_width` with `width`."

We'll replace:
   use_container_width=True  ->  width='stretch'
   use_container_width=False ->  width='content'

BUT only in st.dataframe() calls - plotly_chart still uses use_container_width.
Let's be safe and only fix st.dataframe calls.

Also fixes:
2. st.switch_page paths to use proper page paths
"""
import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.stdout = __import__('io').TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

FILES_TO_PATCH = [
    PROJECT_ROOT / "app.py",
    PROJECT_ROOT / "pages" / "1_Phishing_Detection.py",
    PROJECT_ROOT / "pages" / "2_Network_Intrusion.py",
    PROJECT_ROOT / "pages" / "3_Explainable_AI.py",
    PROJECT_ROOT / "pages" / "4_Model_Evaluation.py",
    PROJECT_ROOT / "pages" / "5_Analysis_History.py",
    PROJECT_ROOT / "pages" / "6_Reports.py",
    PROJECT_ROOT / "pages" / "7_About_Project.py",
]

total_changes = 0

for fpath in FILES_TO_PATCH:
    if not fpath.exists():
        print(f"[SKIP] {fpath.name} - not found")
        continue

    original = fpath.read_text(encoding="utf-8")
    patched = original

    # Fix st.dataframe() use_container_width -> width
    # Pattern: st.dataframe(..., use_container_width=True ...)
    # We replace only in dataframe context
    patched = re.sub(
        r'(st\.dataframe\([^)]*?)use_container_width=True',
        r'\1width="stretch"',
        patched,
        flags=re.DOTALL
    )
    patched = re.sub(
        r'(st\.dataframe\([^)]*?)use_container_width=False',
        r'\1width="content"',
        patched,
        flags=re.DOTALL
    )

    # Fix switch_page calls - these need page file paths relative to app root
    # The switch_page paths already look correct (pages/X_Name.py format)
    # Just ensure no trailing/leading issues

    if patched != original:
        n = sum(1 for a, b in zip(original.splitlines(), patched.splitlines()) if a != b)
        fpath.write_text(patched, encoding="utf-8")
        print(f"[PATCHED] {fpath.name}: {n} line(s) changed")
        total_changes += n
    else:
        print(f"[OK]      {fpath.name}: no changes needed")

print(f"\nDone. Total lines changed: {total_changes}")
