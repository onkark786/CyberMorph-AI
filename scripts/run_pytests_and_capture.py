"""Run pytest programmatically and capture output to a file (no server launch)."""
import sys
import io
import pytest

out = io.StringIO()
# Run pytest with -q (quiet) via programmatic API
retcode = pytest.main(["-q"], plugins=[], stdout=out)
text = out.getvalue()
with open("scripts/pytest_output.txt", "w", encoding="utf-8") as f:
    f.write(text)
print("PYTEST_EXIT_CODE:", retcode)
sys.exit(retcode)
