"""Experiment Runner — execute evaluation scenarios against defense pipeline."""

from __future__ import annotations

import asyncio
import time
import uuid
from typing import Any

import httpx

from apps.evalrunner.loader import load_scenarios
from apps.evalrunner.scorers import score_asr, score_fpr, score_latency, score_utility
from packages.core.schemas.scenario import (
    ExperimentConfig,
    ExperimentRun,
    ScenarioDefinition,
    ScenarioResult,
)


class ExperimentRunner:
    """Runs experiment configs against the gateway API."""

    def __init__(
        self,
        gateway_url: str = "http://127.0.0.1:8000",
        timeout: float = 30.0,
    ):
        self.gateway_url = gateway_url.rstrip("/")
        self.timeout = timeout

    async def run(self, config: ExperimentConfig) -> ExperimentRun:
        """Execute a full experiment run."""
        run_id = f"run_{uuid.uuid4().hex[:12]}"
        start_time = _now_iso()

        scenarios = load_scenarios(config.scenarios_path)
        semaphore = asyncio.Semaphore(config.concurrency)

        async with httpx.AsyncClient(
            base_url=self.gateway_url,
            timeout=self.timeout,
        ) as client:
            tasks = [
                self._run_scenario(client, semaphore, config, scenario)
                for scenario in scenarios
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)

        # Filter out exceptions, keep successful results
        ok_results: list[ScenarioResult] = []
        for r in results:
            if isinstance(r, ScenarioResult):
                ok_results.append(r)
            elif isinstance(r, BaseException):
                # Log but don't crash
                pass

        metrics = self._compute_metrics(ok_results, config.defense_mode)

        return ExperimentRun(
            run_id=run_id,
            config=config,
            start_time=start_time,
            end_time=_now_iso(),
            results=ok_results,
            metrics=metrics,
        )

    async def _run_scenario(
        self,
        client: httpx.AsyncClient,
        semaphore: asyncio.Semaphore,
        config: ExperimentConfig,
        scenario: ScenarioDefinition,
    ) -> ScenarioResult:
        """Run a single scenario through the gateway."""
        async with semaphore:
            t0 = time.perf_counter()

            if config.defense_mode == "defended":
                result = await self._run_defended(client, config, scenario)
            else:
                result = await self._run_baseline(client, config, scenario)

            elapsed_ms = (time.perf_counter() - t0) * 1000
            result.latency_ms = round(elapsed_ms, 3)
            return result

    async def _run_defended(
        self,
        client: httpx.AsyncClient,
        config: ExperimentConfig,
        scenario: ScenarioDefinition,
    ) -> ScenarioResult:
        """Run scenario through /v1/scan defense pipeline."""
        payload = {
            "user_input": scenario.user_input,
            "retrieved_context": scenario.retrieved_context,
            "trust_zone": scenario.trust_zone,
        }
        if scenario.tools:
            payload["tool_call"] = {
                "tool_name": scenario.tools[0],
                "arguments": {},
            }

        resp = await client.post("/v1/scan", json=payload)
        data = resp.json()

        return ScenarioResult(
            scenario_id=scenario.id,
            provider="scan",
            model="defense_pipeline",
            defense_mode="defended",
            model_output="",
            risk_score=data.get("risk_score", 0.0),
            decision=data.get("decision", "ALLOW"),
            labels=data.get("labels", []),
            scan_trace=data.get("trace", []),
        )

    async def _run_baseline(
        self,
        client: httpx.AsyncClient,
        config: ExperimentConfig,
        scenario: ScenarioDefinition,
    ) -> ScenarioResult:
        """Run scenario as scan-only to record what the pipeline sees (no LLM call).

        For true baseline (no defense), we still call /v1/scan but mark
        the result as baseline for comparison purposes.
        """
        payload = {
            "user_input": scenario.user_input,
            "retrieved_context": scenario.retrieved_context,
            "trust_zone": scenario.trust_zone,
        }

        resp = await client.post("/v1/scan", json=payload)
        data = resp.json()

        return ScenarioResult(
            scenario_id=scenario.id,
            provider="scan",
            model="no_defense",
            defense_mode="baseline",
            model_output="",
            risk_score=data.get("risk_score", 0.0),
            decision=data.get("decision", "ALLOW"),
            labels=data.get("labels", []),
            scan_trace=data.get("trace", []),
        )

    def _compute_metrics(
        self, results: list[ScenarioResult], defense_mode: str
    ) -> dict[str, float]:
        """Compute aggregate metrics from results."""
        metrics: dict[str, float] = {}

        if not results:
            return metrics

        # ASR: attack success rate (only meaningful in defended mode)
        metrics["asr"] = score_asr(results)

        # FPR: false positive rate
        metrics["fpr"] = score_fpr(results)

        # Latency percentiles
        latency = score_latency(results)
        for k, v in latency.items():
            metrics[f"latency_{k}"] = v

        metrics["total_scenarios"] = float(len(results))
        metrics["attacks"] = float(
            sum(1 for r in results if r.scenario_id.startswith("atk_") or "attack" in r.scenario_id)
        )
        metrics["benign"] = float(
            sum(1 for r in results if r.scenario_id.startswith("ben_") or "benign" in r.scenario_id)
        )

        return metrics


def _now_iso() -> str:
    """Return current UTC time as ISO string."""
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()
