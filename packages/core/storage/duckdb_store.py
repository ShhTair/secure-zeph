"""DuckDB Store — persist experiment runs and results locally."""

from __future__ import annotations

import json
from pathlib import Path

import duckdb

from packages.core.schemas.scenario import ExperimentRun, ScenarioResult


class DuckDBStore:
    """Lightweight local store for eval results backed by DuckDB."""

    def __init__(self, db_path: str | Path = "data/results/eval.duckdb"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = duckdb.connect(str(self.db_path))
        self._init_schema()

    def _init_schema(self) -> None:
        """Create tables if they don't exist."""
        self.conn.execute("""
            CREATE SEQUENCE IF NOT EXISTS result_seq START 1
        """)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS experiment_runs (
                run_id         VARCHAR PRIMARY KEY,
                config_id      VARCHAR,
                config_name    VARCHAR,
                defense_mode   VARCHAR,
                start_time     VARCHAR,
                end_time       VARCHAR,
                metrics_json   VARCHAR,
                config_json    VARCHAR
            )
        """)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS scenario_results (
                id             INTEGER PRIMARY KEY DEFAULT nextval('result_seq'),
                run_id         VARCHAR,
                scenario_id    VARCHAR,
                provider       VARCHAR,
                model          VARCHAR,
                defense_mode   VARCHAR,
                model_output   VARCHAR,
                risk_score     DOUBLE,
                decision       VARCHAR,
                labels_json    VARCHAR,
                trace_json     VARCHAR,
                scores_json    VARCHAR,
                latency_ms     DOUBLE,
                triage_bucket  VARCHAR
            )
        """)

    def save_run(self, run: ExperimentRun) -> None:
        """Persist an entire experiment run (header + results)."""
        self.conn.execute(
            """INSERT OR REPLACE INTO experiment_runs
               (run_id, config_id, config_name, defense_mode,
                start_time, end_time, metrics_json, config_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            [
                run.run_id,
                run.config.id,
                run.config.name,
                run.config.defense_mode,
                run.start_time,
                run.end_time,
                json.dumps(run.metrics),
                run.config.model_dump_json(),
            ],
        )
        for result in run.results:
            self.save_result(run.run_id, result)

    def save_result(self, run_id: str, result: ScenarioResult) -> None:
        """Persist a single scenario result."""
        self.conn.execute(
            """INSERT INTO scenario_results
               (run_id, scenario_id, provider, model, defense_mode,
                model_output, risk_score, decision, labels_json,
                trace_json, scores_json, latency_ms, triage_bucket)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            [
                run_id,
                result.scenario_id,
                result.provider,
                result.model,
                result.defense_mode,
                result.model_output,
                result.risk_score,
                result.decision,
                json.dumps(result.labels),
                json.dumps(result.scan_trace),
                json.dumps(result.scores),
                result.latency_ms,
                result.triage_bucket,
            ],
        )

    def query_results(
        self, run_id: str | None = None, defense_mode: str | None = None
    ) -> list[dict]:
        """Query stored results with optional filters."""
        sql = "SELECT * FROM scenario_results WHERE 1=1"
        params: list = []
        if run_id:
            sql += " AND run_id = ?"
            params.append(run_id)
        if defense_mode:
            sql += " AND defense_mode = ?"
            params.append(defense_mode)
        sql += " ORDER BY id"

        rows = self.conn.execute(sql, params).fetchall()
        columns = [desc[0] for desc in self.conn.description]
        return [dict(zip(columns, row)) for row in rows]

    def list_runs(self) -> list[dict]:
        """List all experiment runs."""
        rows = self.conn.execute(
            "SELECT * FROM experiment_runs ORDER BY start_time DESC"
        ).fetchall()
        columns = [desc[0] for desc in self.conn.description]
        return [dict(zip(columns, row)) for row in rows]

    def get_run_metrics(self, run_id: str) -> dict:
        """Get metrics for a specific run."""
        row = self.conn.execute(
            "SELECT metrics_json FROM experiment_runs WHERE run_id = ?",
            [run_id],
        ).fetchone()
        if row:
            return json.loads(row[0])
        return {}

    def close(self) -> None:
        """Close the database connection."""
        self.conn.close()
