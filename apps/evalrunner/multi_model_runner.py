"""MultiModelRunner — parallel evaluation across models × scenarios × defense modes.

Core formula: total_tasks = len(models) × len(scenarios) × len(defense_modes) × repeat_count

Architecture:
  1. For each (model, scenario, defense_mode, repeat) combination, create a Task
  2. Tasks are fed into a bounded asyncio.Semaphore for concurrency control
  3. Each task either:
     a) BASELINE: sends prompt directly to model (no defense) → judge output
     b) DEFENDED: sends prompt through /v1/proxy (defense pipeline) → judge output
  4. Results are collected, scored, and aggregated per-model
"""

from __future__ import annotations

import asyncio
import statistics
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

import httpx
import structlog

from apps.evalrunner.judge import BaseJudge, HeuristicJudge, JudgeVerdict
from apps.evalrunner.loader import load_scenarios
from apps.gateway.app.providers import ProviderRegistry, create_default_registry
from packages.core.schemas.proxy_request import Message, ProxyRequest
from packages.core.schemas.scenario import (
    ExperimentConfig,
    ExperimentRun,
    ModelMetrics,
    ModelTarget,
    ScenarioDefinition,
    ScenarioResult,
)

logger = structlog.get_logger()


@dataclass
class TaskSpec:
    """One unit of work: model × scenario × defense_mode × repeat."""

    scenario: ScenarioDefinition
    model_target: ModelTarget
    defense_mode: str  # "baseline" | "defended"
    repeat_index: int = 0


class MultiModelRunner:
    """Orchestrate parallel evaluation across multiple models and scenarios.

    Usage:
        runner = MultiModelRunner(
            gateway_url="http://127.0.0.1:8000",
            registry=create_default_registry(),
        )
        run = await runner.run(config)
    """

    def __init__(
        self,
        gateway_url: str = "http://127.0.0.1:8000",
        registry: ProviderRegistry | None = None,
        judge: BaseJudge | None = None,
        timeout: float = 60.0,
    ):
        self.gateway_url = gateway_url.rstrip("/")
        self.registry = registry or create_default_registry()
        self.judge = judge or HeuristicJudge()
        self.timeout = timeout
        self._stats: dict[str, int] = {"completed": 0, "failed": 0, "total": 0}

    async def run(self, config: ExperimentConfig) -> ExperimentRun:
        """Execute full multi-model experiment."""
        run_id = f"run_{uuid.uuid4().hex[:12]}"
        start_time = _now_iso()

        scenarios = load_scenarios(config.scenarios_path)
        models = config.models or self._models_from_providers(config)
        defense_modes = config.defense_modes or [config.defense_mode or "defended"]

        # Build task list
        tasks_specs = self._build_tasks(scenarios, models, defense_modes, config.repeat_count)
        self._stats = {"completed": 0, "failed": 0, "total": len(tasks_specs)}

        logger.info(
            "multi_model_run_start",
            run_id=run_id,
            models=len(models),
            scenarios=len(scenarios),
            defense_modes=defense_modes,
            repeat_count=config.repeat_count,
            total_tasks=len(tasks_specs),
            concurrency=config.concurrency,
        )

        semaphore = asyncio.Semaphore(config.concurrency)
        results: list[ScenarioResult] = []

        async with httpx.AsyncClient(
            base_url=self.gateway_url,
            timeout=self.timeout,
        ) as http_client:
            coros = [
                self._execute_task(spec, http_client, semaphore)
                for spec in tasks_specs
            ]
            raw_results = await asyncio.gather(*coros, return_exceptions=True)

        for r in raw_results:
            if isinstance(r, ScenarioResult):
                results.append(r)
                self._stats["completed"] += 1
            elif isinstance(r, BaseException):
                self._stats["failed"] += 1
                logger.warning("task_exception", error=str(r))

        # Compute per-model metrics
        model_metrics = self._compute_model_metrics(results, models, defense_modes)
        flat_metrics = self._compute_flat_metrics(results)

        logger.info(
            "multi_model_run_complete",
            run_id=run_id,
            completed=self._stats["completed"],
            failed=self._stats["failed"],
            total=self._stats["total"],
        )

        return ExperimentRun(
            run_id=run_id,
            config=config,
            start_time=start_time,
            end_time=_now_iso(),
            results=results,
            metrics=flat_metrics,
            model_metrics=model_metrics,
        )

    # ------------------------------------------------------------------
    # Task building
    # ------------------------------------------------------------------

    def _build_tasks(
        self,
        scenarios: list[ScenarioDefinition],
        models: list[ModelTarget],
        defense_modes: list[str],
        repeat_count: int,
    ) -> list[TaskSpec]:
        tasks = []
        for model in models:
            for scenario in scenarios:
                for mode in defense_modes:
                    for rep in range(repeat_count):
                        tasks.append(
                            TaskSpec(
                                scenario=scenario,
                                model_target=model,
                                defense_mode=mode,
                                repeat_index=rep,
                            )
                        )
        return tasks

    def _models_from_providers(self, config: ExperimentConfig) -> list[ModelTarget]:
        """Backward compat: build ModelTargets from config.providers list."""
        targets = []
        for prov_name in config.providers:
            adapter = self.registry.get(prov_name)
            if adapter:
                targets.append(
                    ModelTarget(
                        provider=prov_name,
                        model="",  # will use adapter default
                        temperature=config.temperature,
                        max_tokens=config.max_tokens,
                    )
                )
        if not targets:
            # Fallback: scan-only mode (same as old runner)
            targets.append(
                ModelTarget(provider="scan", model="defense_pipeline")
            )
        return targets

    # ------------------------------------------------------------------
    # Task execution
    # ------------------------------------------------------------------

    async def _execute_task(
        self,
        spec: TaskSpec,
        http_client: httpx.AsyncClient,
        semaphore: asyncio.Semaphore,
    ) -> ScenarioResult:
        async with semaphore:
            t0 = time.perf_counter()

            if spec.model_target.provider == "scan":
                # Scan-only mode (same as old runner)
                result = await self._run_scan_only(
                    http_client, spec.scenario, spec.defense_mode
                )
            elif spec.defense_mode == "defended":
                result = await self._run_defended(
                    http_client, spec.scenario, spec.model_target
                )
            else:
                result = await self._run_baseline(
                    spec.scenario, spec.model_target
                )

            result.latency_ms = round((time.perf_counter() - t0) * 1000, 3)

            # Judge the output (only for real model calls with attack scenarios)
            if (
                spec.model_target.provider != "scan"
                and spec.scenario.expected == "blocked"
                and result.model_output
            ):
                verdict = await self.judge.evaluate(spec.scenario, result.model_output)
                result.injection_followed = verdict.injection_followed
                result.refusal_detected = verdict.refusal_detected
                result.judge_reasoning = verdict.reasoning

            return result

    async def _run_scan_only(
        self,
        http_client: httpx.AsyncClient,
        scenario: ScenarioDefinition,
        defense_mode: str,
    ) -> ScenarioResult:
        """Scan-only: no real LLM call, just defense pipeline check."""
        payload = {
            "user_input": scenario.user_input,
            "retrieved_context": scenario.retrieved_context,
            "trust_zone": scenario.trust_zone,
        }
        resp = await http_client.post("/v1/scan", json=payload)
        data = resp.json()

        return ScenarioResult(
            scenario_id=scenario.id,
            provider="scan",
            model="defense_pipeline",
            defense_mode=defense_mode,
            risk_score=data.get("risk_score", 0.0),
            decision=data.get("decision", "ALLOW"),
            labels=data.get("labels", []),
            scan_trace=data.get("trace", []),
        )

    async def _run_defended(
        self,
        http_client: httpx.AsyncClient,
        scenario: ScenarioDefinition,
        target: ModelTarget,
    ) -> ScenarioResult:
        """Defended: send through /v1/proxy with defense enabled."""
        messages = self._build_messages(scenario)

        payload = {
            "provider": target.provider,
            "model": target.model,
            "messages": [{"role": m.role, "content": m.content} for m in messages],
            "defense_mode": True,
            "temperature": target.temperature,
            "max_tokens": target.max_tokens,
        }

        try:
            resp = await http_client.post("/v1/proxy", json=payload)
            data = resp.json()

            blocked = "[BLOCKED" in data.get("output", "")
            decision = "BLOCK" if blocked else "ALLOW"

            return ScenarioResult(
                scenario_id=scenario.id,
                provider=target.provider,
                model=target.model or "default",
                defense_mode="defended",
                model_output=data.get("output", ""),
                risk_score=0.0,
                decision=decision,
                labels=[],
                scan_trace=data.get("defense_trace", []),
                token_usage_prompt=data.get("token_usage", {}).get("prompt_tokens", 0),
                token_usage_completion=data.get("token_usage", {}).get("completion_tokens", 0),
            )
        except Exception as e:
            return ScenarioResult(
                scenario_id=scenario.id,
                provider=target.provider,
                model=target.model or "default",
                defense_mode="defended",
                error=str(e),
            )

    async def _run_baseline(
        self,
        scenario: ScenarioDefinition,
        target: ModelTarget,
    ) -> ScenarioResult:
        """Baseline: send directly to model (no defense)."""
        adapter = self.registry.get(target.provider)
        if adapter is None or not adapter.is_configured():
            return ScenarioResult(
                scenario_id=scenario.id,
                provider=target.provider,
                model=target.model or "default",
                defense_mode="baseline",
                error=f"Provider '{target.provider}' not configured",
            )

        messages = self._build_messages(scenario)
        request = ProxyRequest(
            provider=target.provider,
            model=target.model,
            messages=messages,
            defense_mode=False,
            temperature=target.temperature,
            max_tokens=target.max_tokens,
        )

        try:
            response = await adapter.complete(request)
            return ScenarioResult(
                scenario_id=scenario.id,
                provider=target.provider,
                model=target.model or response.model,
                defense_mode="baseline",
                model_output=response.output,
                latency_ms=response.latency_ms,
                token_usage_prompt=response.token_usage.prompt_tokens,
                token_usage_completion=response.token_usage.completion_tokens,
            )
        except Exception as e:
            return ScenarioResult(
                scenario_id=scenario.id,
                provider=target.provider,
                model=target.model or "default",
                defense_mode="baseline",
                error=str(e),
            )

    def _build_messages(self, scenario: ScenarioDefinition) -> list[Message]:
        """Build message list from scenario."""
        messages: list[Message] = []
        if scenario.system_prompt:
            messages.append(Message(role="system", content=scenario.system_prompt))

        # Build user message including retrieved context (to simulate RAG)
        user_text = scenario.user_input
        if scenario.retrieved_context:
            context_block = "\n\n---\nRetrieved context:\n" + "\n".join(
                f"[{i+1}] {ctx}" for i, ctx in enumerate(scenario.retrieved_context)
            )
            user_text += context_block

        messages.append(Message(role="user", content=user_text))
        return messages

    # ------------------------------------------------------------------
    # Metrics computation
    # ------------------------------------------------------------------

    def _compute_model_metrics(
        self,
        results: list[ScenarioResult],
        models: list[ModelTarget],
        defense_modes: list[str],
    ) -> list[ModelMetrics]:
        """Compute per-model, per-defense_mode metrics."""
        metrics_list: list[ModelMetrics] = []

        for target in models:
            for mode in defense_modes:
                subset = [
                    r
                    for r in results
                    if r.provider == target.provider
                    and (r.model == target.model or r.model == "default" or not target.model)
                    and r.defense_mode == mode
                    and not r.error
                ]

                if not subset:
                    continue

                attacks = [r for r in subset if self._is_attack(r)]
                benign = [r for r in subset if not self._is_attack(r)]
                latencies = [r.latency_ms for r in subset if r.latency_ms > 0]

                # ASR: for scan-only mode, use decision-based; for real models, use judge-based
                if target.provider == "scan":
                    asr = self._asr_decision_based(attacks)
                else:
                    asr = self._asr_judge_based(attacks)

                # FPR
                fpr = self._fpr(benign)

                # Injection follow rate (only for real model calls)
                followed = [r for r in attacks if r.injection_followed is True]
                follow_rate = len(followed) / len(attacks) if attacks else 0.0

                # Refusal rate
                refused = [r for r in attacks if r.refusal_detected is True]
                refusal_rate = len(refused) / len(attacks) if attacks else 0.0

                # Tokens
                total_tokens = sum(
                    r.token_usage_prompt + r.token_usage_completion for r in subset
                )

                errors = len([r for r in results if r.error and r.provider == target.provider and r.defense_mode == mode])

                metrics_list.append(
                    ModelMetrics(
                        provider=target.provider,
                        model=target.model or "default",
                        defense_mode=mode,
                        total_scenarios=len(subset),
                        total_attacks=len(attacks),
                        total_benign=len(benign),
                        asr=round(asr, 4),
                        fpr=round(fpr, 4),
                        injection_follow_rate=round(follow_rate, 4),
                        refusal_rate=round(refusal_rate, 4),
                        mean_latency_ms=round(statistics.mean(latencies), 2) if latencies else 0.0,
                        p95_latency_ms=round(_percentile(latencies, 95), 2) if latencies else 0.0,
                        total_tokens=total_tokens,
                        error_count=errors,
                    )
                )

        return metrics_list

    def _compute_flat_metrics(self, results: list[ScenarioResult]) -> dict[str, float]:
        """Compute aggregated flat metrics (backward compat)."""
        ok = [r for r in results if not r.error]
        if not ok:
            return {}

        attacks = [r for r in ok if self._is_attack(r)]
        benign = [r for r in ok if not self._is_attack(r)]

        return {
            "total_scenarios": len(ok),
            "total_attacks": len(attacks),
            "total_benign": len(benign),
            "asr": round(self._asr_decision_based(attacks), 4),
            "fpr": round(self._fpr(benign), 4),
            "error_count": len([r for r in results if r.error]),
        }

    @staticmethod
    def _is_attack(result: ScenarioResult) -> bool:
        # Convention: scenario_id starts with "atk_" or "inj_" for attacks
        sid = result.scenario_id.lower()
        return sid.startswith(("atk_", "inj_", "attack_", "hack_"))

    @staticmethod
    def _asr_decision_based(attacks: list[ScenarioResult]) -> float:
        """ASR based on BLOCK/ALLOW decisions."""
        if not attacks:
            return 0.0
        allowed = sum(1 for r in attacks if r.decision != "BLOCK")
        return allowed / len(attacks)

    @staticmethod
    def _asr_judge_based(attacks: list[ScenarioResult]) -> float:
        """ASR based on judge verdict (did model follow injection?)."""
        if not attacks:
            return 0.0
        followed = sum(1 for r in attacks if r.injection_followed is True)
        return followed / len(attacks)

    @staticmethod
    def _fpr(benign: list[ScenarioResult]) -> float:
        if not benign:
            return 0.0
        blocked = sum(1 for r in benign if r.decision == "BLOCK")
        return blocked / len(benign)


def _now_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()


def _percentile(data: list[float], pct: float) -> float:
    if not data:
        return 0.0
    sorted_data = sorted(data)
    k = (len(sorted_data) - 1) * (pct / 100)
    f = int(k)
    c = f + 1
    if c >= len(sorted_data):
        return sorted_data[-1]
    return sorted_data[f] + (k - f) * (sorted_data[c] - sorted_data[f])
