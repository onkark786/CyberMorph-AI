from __future__ import annotations

import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest
import src.database as database
from src.database import (
    clear_all_history,
    delete_analysis_record,
    get_analysis_history,
    get_overview_stats,
    init_db,
    save_analysis,
    save_model_run,
)


@pytest.fixture(autouse=True)
def isolate_database_for_test(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep database tests away from the user's persistent project history."""
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "database_test.sqlite3")


def test_database_initialization():
    """Verify SQLite database initializes tables without error."""
    init_db()
    stats = get_overview_stats()
    assert isinstance(stats, dict)
    assert "total_analyses" in stats


def test_save_and_retrieve_analysis():
    """Verify inserting and querying analysis records."""
    rec_id = save_analysis(
        analysis_type="phishing",
        input_summary="https://test-example.com",
        predicted_class="LEGITIMATE",
        risk_level="Low",
        probability=0.95,
        model_name="Test Model",
        result_summary="Clean legitimate test structure.",
        details={"test_key": "test_val"},
    )
    assert rec_id > 0

    records = get_analysis_history(limit=5, analysis_type="phishing")
    assert len(records) > 0
    found = any(r["id"] == rec_id for r in records)
    assert found


def test_filter_and_search_history():
    """Verify filtering by analysis type, risk, and search term."""
    save_analysis(
        analysis_type="network",
        input_summary="Batch: test_flow.csv (100 records)",
        predicted_class="ATTACK",
        risk_level="High",
        probability=0.88,
        model_name="Network IDS",
        result_summary="Attack signature identified.",
    )

    filtered = get_analysis_history(analysis_type="network", risk_filter="High")
    assert any(r["predicted_class"] == "ATTACK" for r in filtered)

    searched = get_analysis_history(search_query="test_flow.csv")
    assert len(searched) > 0


def test_delete_analysis_record():
    """Verify deleting a specific record."""
    rec_id = save_analysis(
        analysis_type="phishing",
        input_summary="https://delete-me.com",
        predicted_class="LEGITIMATE",
        risk_level="Low",
        probability=0.99,
        model_name="Temp Model",
        result_summary="Temporary record.",
    )
    assert delete_analysis_record(rec_id) is True

    # Confirm it no longer exists
    records = get_analysis_history(limit=100)
    assert not any(r["id"] == rec_id for r in records)


def test_model_runs_logging():
    """Verify logging model training runs."""
    run_id = save_model_run(
        model_type="phishing",
        model_name="Random Forest Benchmark",
        dataset_name="UCI Phishing Websites",
        accuracy=0.965,
        precision=0.962,
        recall=0.968,
        f1_score=0.965,
        metadata={"trees": 100},
    )
    assert run_id > 0
