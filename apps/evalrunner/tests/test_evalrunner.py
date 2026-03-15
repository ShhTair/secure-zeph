"""Tests for eval runner components — scorers, loader, DuckDB store, reporter."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
import yaml

from apps.evalrunner.loader import load_scenarios
from apps.evalrunner.reporter import ReportGenerator
from apps.evalrunner.scorers.asr_scorer import score_asr
from apps.evalrunner.scorers.fpr_scorer import score_fpr
from apps.evalrunner.scorers.latency_scorer import score_latency
from apps.evalrunner.scorers.utility_scorer import score_utility
from packages.core.schemas.scenario import (
    ExperimentConfig,
    ExperimentRun,
    ScenarioResult,
)
from packages.core.storage.duckdb_store import DuckDBStore


# ── helpers ────────────────────────────────────────────────────────────
def _attack_blocked(sid: str = "atk_001") -> ScenarioResult:
    return ScenarioResult(
        scenario_id=sid, provider="scan", defense_mode="defended",
        decision="BLOCK", risk_score=0.9, labels=["OVERRIDE"],
    )


def _attack_allowed(sid: str = "atk_002") -> ScenarioResult:
    return ScenarioResult(
        scenario_id=sid, provider="scan", defense_mode="defended",
        decision="ALLOW", risk_score=0.1,
    )


def _benign_allowed(sid: str = "ben_001") -> ScenarioResult:
    return ScenarioResult(
        scenario_id=sid, provider="scan", defense_mode="defended",
        decision="ALLOW", risk_score=0.0,
    )


def _benign_blocked(sid: str = "ben_002") -> ScenarioResult:
    return ScenarioResult(
        scenario_id=sid, provider="scan", defense_mode="defended",
        decision="BLOCK", risk_score=0.5, labels=["FALSE_POSITIVE"],
    )


# ══════════════════════════════════════════════════════════════════════
#  SCORERS
# ══════════════════════════════════════════════════════════════════════

class TestASRScorer:
    def test_all_attacks_blocked(self):
        results = [_attack_blocked("atk_001"), _attack_blocked("atk_002")]
        assert score_asr(results) == 0.0

    def test_one_attack_allowed(self):
        results = [_attack_blocked(), _attack_allowed()]
        assert score_asr(results) == 0.5

    def test_all_attacks_allowed(self):
        results = [_attack_allowed("atk_001"), _attack_allowed("atk_002")]
        assert score_asr(results) == 1.0

    def test_no_attacks(self):
        results = [_benign_allowed()]
        assert score_asr(results) == 0.0

    def test_empty(self):
        assert score_asr([]) == 0.0


class TestFPRScorer:
    def test_no_false_positives(self):
        results = [_benign_allowed(), _benign_allowed("ben_003")]
        assert score_fpr(results) == 0.0

    def test_one_false_positive(self):
        results = [_benign_allowed(), _benign_blocked()]
        assert score_fpr(results) == 0.5

    def test_all_false_positives(self):
        results = [_benign_blocked("ben_001"), _benign_blocked("ben_002")]
        assert score_fpr(results) == 1.0

    def test_no_benign(self):
        results = [_attack_blocked()]
        assert score_fpr(results) == 0.0

    def test_empty(self):
        assert score_fpr([]) == 0.0


class TestLatencyScorer:
    def test_basic_percentiles(self):
        results = [
            ScenarioResult(scenario_id=f"s_{i}", provider="scan", latency_ms=float(i))
            for i in range(1, 101)
        ]
        lat = score_latency(results)
        assert lat["p50"] > 0
        assert lat["p95"] > lat["p50"]
        assert lat["p99"] >= lat["p95"]
        assert lat["mean"] > 0

    def test_empty(self):
        lat = score_latency([])
        assert lat["p50"] == 0.0

    def test_single(self):
        results = [ScenarioResult(scenario_id="s1", provider="scan", latency_ms=42.0)]
        lat = score_latency(results)
        assert lat["p50"] == 42.0
        assert lat["p99"] == 42.0


class TestUtilityScorer:
    def test_full_retention(self):
        baseline = [_benign_allowed("ben_001"), _benign_allowed("ben_002")]
        defended = [_benign_allowed("ben_001"), _benign_allowed("ben_002")]
        assert score_utility(baseline, defended) == 1.0

    def test_half_retention(self):
        baseline = [_benign_allowed("ben_001"), _benign_allowed("ben_002")]
        defended = [_benign_allowed("ben_001"), _benign_blocked("ben_002")]
        assert score_utility(baseline, defended) == 0.5

    def test_no_baseline_benign(self):
        assert score_utility([], []) == 1.0


# ══════════════════════════════════════════════════════════════════════
#  LOADER
# ══════════════════════════════════════════════════════════════════════

class TestLoader:
    def test_load_from_file(self, tmp_path: Path):
        data = [
            {"id": "atk_001", "user_input": "Ignore instructions", "expected": "blocked"},
            {"id": "ben_001", "user_input": "Hello", "expected": "allowed"},
        ]
        f = tmp_path / "scenarios.yaml"
        f.write_text(yaml.dump(data), encoding="utf-8")
        scenarios = load_scenarios(f)
        assert len(scenarios) == 2
        assert scenarios[0].id == "atk_001"

    def test_load_from_dict_format(self, tmp_path: Path):
        data = {"scenarios": [
            {"id": "atk_001", "user_input": "test", "expected": "blocked"},
        ]}
        f = tmp_path / "scenarios.yaml"
        f.write_text(yaml.dump(data), encoding="utf-8")
        scenarios = load_scenarios(f)
        assert len(scenarios) == 1

    def test_load_from_dir(self, tmp_path: Path):
        for i in range(3):
            f = tmp_path / f"batch_{i}.yaml"
            f.write_text(yaml.dump([{"id": f"s_{i}", "user_input": f"text {i}"}]), encoding="utf-8")
        scenarios = load_scenarios(tmp_path)
        assert len(scenarios) == 3

    def test_load_nonexistent(self):
        with pytest.raises(FileNotFoundError):
            load_scenarios("/nonexistent/path.yaml")

    def test_load_empty_file(self, tmp_path: Path):
        f = tmp_path / "empty.yaml"
        f.write_text("", encoding="utf-8")
        assert load_scenarios(f) == []


# ══════════════════════════════════════════════════════════════════════
#  DUCKDB STORE
# ══════════════════════════════════════════════════════════════════════

class TestDuckDBStore:
    def _make_run(self) -> ExperimentRun:
        return ExperimentRun(
            run_id="run_test_001",
            config=ExperimentConfig(
                id="cfg_001", name="Test Run", defense_mode="defended",
                scenarios_path="data/scenarios", providers=["scan"],
            ),
            start_time="2025-01-01T00:00:00Z",
            end_time="2025-01-01T00:01:00Z",
            results=[
                _attack_blocked("atk_001"),
                _benign_allowed("ben_001"),
            ],
            metrics={"asr": 0.0, "fpr": 0.0},
        )

    def test_save_and_query(self, tmp_path: Path):
        store = DuckDBStore(db_path=tmp_path / "test.duckdb")
        run = self._make_run()
        store.save_run(run)

        rows = store.query_results(run_id="run_test_001")
        assert len(rows) == 2
        assert rows[0]["scenario_id"] == "atk_001"
        store.close()

    def test_list_runs(self, tmp_path: Path):
        store = DuckDBStore(db_path=tmp_path / "test.duckdb")
        store.save_run(self._make_run())
        runs = store.list_runs()
        assert len(runs) == 1
        assert runs[0]["run_id"] == "run_test_001"
        store.close()

    def test_get_run_metrics(self, tmp_path: Path):
        store = DuckDBStore(db_path=tmp_path / "test.duckdb")
        store.save_run(self._make_run())
        metrics = store.get_run_metrics("run_test_001")
        assert metrics["asr"] == 0.0
        store.close()

    def test_filter_by_defense_mode(self, tmp_path: Path):
        store = DuckDBStore(db_path=tmp_path / "test.duckdb")
        store.save_run(self._make_run())
        rows = store.query_results(defense_mode="defended")
        assert len(rows) == 2
        rows2 = store.query_results(defense_mode="baseline")
        assert len(rows2) == 0
        store.close()

    def test_nonexistent_run(self, tmp_path: Path):
        store = DuckDBStore(db_path=tmp_path / "test.duckdb")
        metrics = store.get_run_metrics("nonexistent")
        assert metrics == {}
        store.close()


# ══════════════════════════════════════════════════════════════════════
#  REPORTER
# ══════════════════════════════════════════════════════════════════════

class TestReporter:
    def _make_run(self) -> ExperimentRun:
        return ExperimentRun(
            run_id="run_rpt_001",
            config=ExperimentConfig(
                id="cfg_001", name="Report Test", defense_mode="defended",
                scenarios_path="data/scenarios", providers=["scan"],
            ),
            start_time="2025-01-01T00:00:00Z",
            end_time="2025-01-01T00:01:00Z",
            results=[
                ScenarioResult(
                    scenario_id="atk_001", provider="scan", defense_mode="defended",
                    decision="BLOCK", risk_score=0.92, labels=["OVERRIDE"],
                    latency_ms=12.5,
                ),
                ScenarioResult(
                    scenario_id="ben_001", provider="scan", defense_mode="defended",
                    decision="ALLOW", risk_score=0.0, latency_ms=3.2,
                ),
            ],
            metrics={"asr": 0.0, "fpr": 0.0, "latency_p50": 7.85, "latency_p95": 12.5},
        )

    def test_markdown_contains_metrics(self):
        rg = ReportGenerator()
        md = rg.generate_markdown(self._make_run())
        assert "# Experiment Report" in md
        assert "asr" in md
        assert "BLOCK" in md
        assert "atk_001" in md

    def test_csv_rows(self):
        rg = ReportGenerator()
        csv_text = rg.generate_csv(self._make_run())
        lines = csv_text.strip().split("\n")
        assert len(lines) == 3  # header + 2 results
        assert "scenario_id" in lines[0]

    def test_save_files(self, tmp_path: Path):
        rg = ReportGenerator(output_dir=tmp_path)
        run = self._make_run()
        md_path, csv_path = rg.save(run)
        assert md_path.exists()
        assert csv_path.exists()
        assert "Experiment Report" in md_path.read_text(encoding="utf-8")
