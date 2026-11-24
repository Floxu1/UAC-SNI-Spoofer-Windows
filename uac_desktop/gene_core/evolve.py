from __future__ import annotations

import random
import time
import uuid
from dataclasses import dataclass, replace
from typing import Callable

from .schema import GeneStrategy, KNOWN_FAKE_SNIS, LabState, STRATEGY_METHODS
from .score import apply_score, score_dry_run
from .seeds import seed_strategies

LogFn = Callable[[str], None]
ProgressFn = Callable[[LabState, GeneStrategy | None], None]


@dataclass
class EvolutionConfig:
    population_size: int = 24
    elite_count: int = 4
    mutation_rate: float = 0.45
    crossover_rate: float = 0.55
    confirmations: int = 2
    save_every: int = 1
    max_generations: int = 0  # 0 = unlimited until stop
    dry_run: bool = True
    live_probe: bool = False
    traffic_cap_mb: float = 50.0
    network_id: str = "unknown"
    rng_seed: int = 42
    test_hosts: tuple = ()
    edge_ips: tuple = ()
    probe_timeout_s: float = 5.0
    probe_parallel: int = 2
    uac_root: str = ""
    # Bytes already spent before evolution (Stage 0 edge scan) - counted
    # against the same traffic cap.
    pre_traffic_bytes: int = 0


METHODS_POOL = (
    "wrong_seq", "full5", "sni_boundary", "sni_split",
    "tls_sni_records", "full10", "full20", "multi64",
)


class EvolutionEngine:
    def __init__(
        self,
        state: LabState,
        config: EvolutionConfig,
        log: LogFn | None = None,
        on_progress: ProgressFn | None = None,
        live_scorer: Callable[[GeneStrategy], object] | None = None,
    ) -> None:
        self.state = state
        self.config = config
        self.log = log or (lambda _m: None)
        self.on_progress = on_progress or (lambda _s, _c: None)
        self.live_scorer = live_scorer
        self._stop = False
        self._pause = False
        self._rng = random.Random(config.rng_seed or state.rng_seed or 42)

    def request_stop(self) -> None:
        self._stop = True

    def request_pause(self) -> None:
        self._pause = True

    def request_resume(self) -> None:
        self._pause = False

    @property
    def paused(self) -> bool:
        return self._pause

    def ensure_population(self) -> None:
        if self.state.population:
            return
        live_mode = bool(self.config.live_probe) and not bool(self.config.dry_run)
        seeds = seed_strategies(self.config.network_id)
        for seed in seeds:
            seed.mode = "live" if live_mode else "dry"
            seed.simulated = not live_mode
            seed.confirmed = False
            seed.recommended = False
            # Fresh seeds must be evaluated in the active mode.
            seed.tests = seed.successes = 0
            seed.score = seed.success_rate = seed.avg_ms = 0.0
            seed.traffic_bytes = 0
        self.state.population = seeds[: self.config.population_size]
        while len(self.state.population) < self.config.population_size:
            self.state.population.append(self._random_individual(generation=0))
        self.state.network_id = self.config.network_id
        self.state.dry_run = not live_mode
        self.state.live_probe = live_mode
        self.state.traffic_cap_mb = self.config.traffic_cap_mb
        self.state.rng_seed = self.config.rng_seed
        self.log(
            f"POP seed size={len(self.state.population)} network={self.config.network_id} "
            f"mode={'live' if live_mode else 'dry'}"
        )

    def _random_individual(self, generation: int = 0) -> GeneStrategy:
        method = self._rng.choice(METHODS_POOL)
        live_mode = bool(self.config.live_probe) and not bool(self.config.dry_run)
        return GeneStrategy(
            id=f"gene_{uuid.uuid4().hex[:12]}",
            name=f"{method}/rand",
            method=method,
            fake_sni=self._rng.choice(KNOWN_FAKE_SNIS),
            fake_repeat=self._rng.choice([1, 1, 1, 2, 3]),
            inject_delay_ms=self._rng.choice([0, 1, 1, 2, 5]),
            fragment_delay_ms=self._rng.choice([0, 3, 5, 8, 10, 15, 30]),
            chunk_size=self._rng.choice([5, 5, 10, 20, 64]),
            network_id=self.config.network_id,
            generation=generation,
            mode="live" if live_mode else "dry",
            simulated=not live_mode,
        )

    def _mutate(self, parent: GeneStrategy, generation: int) -> GeneStrategy:
        child = GeneStrategy.from_dict(parent.to_dict())
        child.id = f"gene_{uuid.uuid4().hex[:12]}"
        child.parent_ids = [parent.id]
        child.generation = generation
        child.tests = 0
        child.successes = 0
        child.score = 0.0
        child.success_rate = 0.0
        child.avg_ms = 0.0
        child.traffic_bytes = 0
        child.confirmed = False
        child.confirmed_ips = []
        child.working_ips = []
        child.confirm_need = max(1, int(self.config.confirmations))
        child.recommended = False
        child.fail_reset = 0
        child.fail_timeout = 0
        child.fail_other = 0
        child.created_at = time.time()
        child.updated_at = child.created_at

        roll = self._rng.random()
        if roll < 0.25:
            child.method = self._rng.choice(METHODS_POOL)
        elif roll < 0.45:
            child.fake_sni = self._rng.choice(KNOWN_FAKE_SNIS)
        elif roll < 0.60:
            child.fake_repeat = self._rng.choice([1, 1, 2, 3])
        elif roll < 0.75:
            child.inject_delay_ms = self._rng.choice([0, 1, 2, 5, 10])
        elif roll < 0.90:
            child.fragment_delay_ms = self._rng.choice([0, 3, 5, 8, 10, 15, 20, 40])
        else:
            child.chunk_size = self._rng.choice([5, 10, 20, 64])

        # Keep method legal.
        if child.method not in STRATEGY_METHODS:
            child.method = "wrong_seq"
        child.name = f"{child.method}/{child.fake_sni.split('.')[0]}"
        return child

    def _crossover(self, a: GeneStrategy, b: GeneStrategy, generation: int) -> GeneStrategy:
        child = GeneStrategy(
            id=f"gene_{uuid.uuid4().hex[:12]}",
            method=self._rng.choice([a.method, b.method]),
            fake_sni=self._rng.choice([a.fake_sni, b.fake_sni]),
            fake_repeat=self._rng.choice([a.fake_repeat, b.fake_repeat]),
            inject_delay_ms=self._rng.choice([a.inject_delay_ms, b.inject_delay_ms]),
            fragment_delay_ms=self._rng.choice([a.fragment_delay_ms, b.fragment_delay_ms]),
            chunk_size=self._rng.choice([a.chunk_size, b.chunk_size]),
            network_id=self.config.network_id,
            generation=generation,
            parent_ids=[a.id, b.id],
        )
        child.name = f"{child.method}/xover"
        return child

    def _evaluate(self, strategy: GeneStrategy) -> GeneStrategy:
        cap_bytes = int(self.config.traffic_cap_mb * 1024 * 1024)
        if self.state.traffic_bytes >= cap_bytes:
            self.log("TRAFFIC CAP reached — stopping evaluations")
            self._stop = True
            return strategy

        live_mode = (
            bool(self.config.live_probe)
            and not bool(self.config.dry_run)
            and self.live_scorer is not None
        )

        if live_mode:
            # Live scorer performs multi-IP confirmation itself.
            while self._pause and not self._stop:
                time.sleep(0.05)
            if self._stop:
                return strategy
            scorer = self.live_scorer
            # Prefer object API (LiveScorer.score) when available.
            if hasattr(scorer, "score"):
                if hasattr(scorer, "wait_for_connectivity"):
                    if not scorer.wait_for_connectivity(lambda: self._pause):  # type: ignore[misc]
                        self._stop = True
                        return strategy
                result = scorer.score(strategy, pause_check=lambda: self._pause)  # type: ignore[misc]
                if hasattr(scorer, "stats"):
                    self.state.live_stats = dict(scorer.stats.as_dict())  # type: ignore[misc]
            else:
                result = scorer(strategy)  # type: ignore[misc]
            strategy.mode = "live"
            strategy.simulated = False
            apply_score(strategy, result)
            self.state.traffic_bytes += int(getattr(result, "traffic_bytes", 0) or 0)
            self.state.evaluated += 1
            flag = "CONFIRMED" if getattr(strategy, "confirmed", False) else "live"
            self.log(
                f"EVAL {strategy.name} ok={getattr(result, 'success', False)} "
                f"score={strategy.score:.3f} rate={strategy.success_rate:.0%} "
                f"ms={strategy.avg_ms:.0f} mode={flag} detail={getattr(result, 'detail', '')[:120]}"
            )
            self.on_progress(self.state, strategy)
            return strategy

        rounds = max(1, int(self.config.confirmations))
        for _ in range(rounds):
            if self._stop:
                break
            while self._pause and not self._stop:
                time.sleep(0.05)
            result = score_dry_run(strategy, self.config.network_id)
            strategy.mode = "dry"
            strategy.simulated = True
            strategy.confirmed = False
            strategy.recommended = False
            apply_score(strategy, result)
            self.state.traffic_bytes += int(getattr(result, "traffic_bytes", 0) or 0)
            self.state.evaluated += 1
            self.log(
                f"EVAL {strategy.name} ok={getattr(result, 'success', False)} "
                f"score={strategy.score:.3f} rate={strategy.success_rate:.0%} "
                f"ms={strategy.avg_ms:.0f} mode=dry"
            )
            self.on_progress(self.state, strategy)
        return strategy

    def _update_hall_of_fame(self) -> None:
        ranked = sorted(
            self.state.population,
            key=lambda s: (
                1 if s.confirmed else 0,
                s.score,
                s.success_rate,
                -s.avg_ms,
            ),
            reverse=True,
        )
        merged = {s.fingerprint(): s for s in self.state.hall_of_fame}
        for strategy in ranked[:8]:
            if strategy.tests <= 0:
                continue
            prev = merged.get(strategy.fingerprint())
            if prev is None or strategy.score >= prev.score:
                merged[strategy.fingerprint()] = GeneStrategy.from_dict(strategy.to_dict())
        self.state.hall_of_fame = sorted(
            merged.values(),
            key=lambda s: (
                1 if s.confirmed else 0,
                s.score,
                s.success_rate,
                -s.avg_ms,
            ),
            reverse=True,
        )[:20]

    def _confirm_top_candidates(self) -> None:
        """Re-test top unconfirmed genes on more distinct edge IPs."""
        live_mode = (
            bool(self.config.live_probe)
            and not bool(self.config.dry_run)
            and self.live_scorer is not None
            and hasattr(self.live_scorer, "confirm_more")
        )
        if not live_mode or self._stop:
            return
        need = max(1, int(self.config.confirmations))
        ranked = sorted(
            self.state.population,
            key=lambda s: (s.score, s.success_rate, -s.avg_ms),
            reverse=True,
        )
        # Elites + a couple of near-elites that already showed a strong signal.
        pool = []
        for strategy in ranked:
            if strategy.tests <= 0:
                continue
            if strategy.confirmed and len(strategy.confirmed_ips) >= need:
                continue
            if strategy.score < 0.40 and not strategy.confirmed_ips:
                continue
            pool.append(strategy)
            if len(pool) >= max(self.config.elite_count, 4):
                break
        if not pool:
            return
        self.log(f"CONFIRM stage candidates={len(pool)} need_ips={need}")
        scorer = self.live_scorer
        for strategy in pool:
            if self._stop:
                break
            while self._pause and not self._stop:
                time.sleep(0.05)
            if len(strategy.confirmed_ips) >= need:
                strategy.confirmed = True
                strategy.recommended = True
                continue
            if hasattr(scorer, "wait_for_connectivity"):
                if not scorer.wait_for_connectivity(lambda: self._pause):  # type: ignore[misc]
                    self._stop = True
                    break
            result = scorer.confirm_more(strategy, pause_check=lambda: self._pause)  # type: ignore[misc]
            if hasattr(scorer, "stats"):
                self.state.live_stats = dict(scorer.stats.as_dict())  # type: ignore[misc]
            apply_score(strategy, result)
            self.state.traffic_bytes += int(getattr(result, "traffic_bytes", 0) or 0)
            self.state.evaluated += 1
            flag = "CONFIRMED" if strategy.confirmed else f"{len(strategy.confirmed_ips)}/{need}"
            self.log(
                f"CONFIRM {strategy.name} {flag} score={strategy.score:.3f} "
                f"detail={getattr(result, 'detail', '')[:120]}"
            )
            self.on_progress(self.state, strategy)
            if self.state.traffic_bytes >= int(self.config.traffic_cap_mb * 1024 * 1024):
                self.log("TRAFFIC CAP reached during confirm — stopping")
                self._stop = True
                break

    def run_generation(self) -> LabState:

        self.ensure_population()
        generation = self.state.generation + 1
        # Keep buckets separate when the active network changes mid-run.
        if self.config.network_id and self.state.network_id not in {"", "unknown"}:
            if self.config.network_id != self.state.network_id:
                self.log(
                    f"NETWORK change {self.state.network_id} -> {self.config.network_id} "
                    "(results stay partitioned by network_id on each strategy)"
                )
                self.state.network_id = self.config.network_id
        self.log(f"GEN {generation} start pop={len(self.state.population)}")

        for strategy in list(self.state.population):
            if self._stop:
                break
            while self._pause and not self._stop:
                time.sleep(0.05)
            if strategy.tests == 0 or strategy.generation == generation - 1:
                strategy.generation = max(strategy.generation, generation - 1)
                self._evaluate(strategy)

        self._confirm_top_candidates()
        self._update_hall_of_fame()
        ranked = sorted(
            self.state.population,
            key=lambda s: (
                1 if s.confirmed else 0,
                s.score,
                s.success_rate,
                -s.avg_ms,
            ),
            reverse=True,
        )
        elites = ranked[: self.config.elite_count]
        children: list[GeneStrategy] = [GeneStrategy.from_dict(e.to_dict()) for e in elites]

        while len(children) < self.config.population_size and not self._stop:
            if self._rng.random() < self.config.crossover_rate and len(ranked) >= 2:
                a, b = self._rng.sample(ranked[: max(4, len(ranked) // 2)], 2)
                child = self._crossover(a, b, generation)
            else:
                parent = self._rng.choice(ranked[: max(4, len(ranked) // 2)])
                child = GeneStrategy.from_dict(parent.to_dict())
                child.id = f"gene_{uuid.uuid4().hex[:12]}"
                child.parent_ids = [parent.id]
                child.generation = generation
                child.tests = child.successes = 0
                child.score = child.success_rate = child.avg_ms = 0.0
                child.traffic_bytes = 0
                child.confirmed = False
                child.confirmed_ips = []
                child.working_ips = []
                child.confirm_need = max(1, int(self.config.confirmations))
                child.recommended = False
                child.fail_reset = child.fail_timeout = child.fail_other = 0
            if self._rng.random() < self.config.mutation_rate:
                child = self._mutate(child, generation)
            # Dedup fingerprints in the new population.
            if any(c.fingerprint() == child.fingerprint() for c in children):
                child = self._mutate(child, generation)
            children.append(child)

        self.state.population = children[: self.config.population_size]
        self.state.generation = generation
        self.state.network_id = self.config.network_id
        self.state.dry_run = self.config.dry_run
        self.state.live_probe = self.config.live_probe
        self.state.traffic_cap_mb = self.config.traffic_cap_mb
        self.on_progress(self.state, elites[0] if elites else None)
        self.log(
            f"GEN {generation} done best={elites[0].name if elites else '-'} "
            f"score={elites[0].score if elites else 0:.3f} "
            f"hof={len(self.state.hall_of_fame)} traffic={self.state.traffic_bytes}"
        )
        return self.state

    def run(self, generations: int | None = None) -> LabState:
        self._stop = False
        live_mode = bool(self.config.live_probe) and not bool(self.config.dry_run)
        if live_mode and (self.state.dry_run or not self.state.live_probe):
            self.log("LIVE session: archiving prior dry-run results and starting fresh")
            self.state.prepare_live_session()
            self.state.traffic_cap_mb = float(self.config.traffic_cap_mb or 50.0)
        self.state.dry_run = not live_mode
        self.state.live_probe = live_mode
        pre = max(0, int(getattr(self.config, "pre_traffic_bytes", 0) or 0))
        if pre:
            self.state.traffic_bytes += pre
            self.config.pre_traffic_bytes = 0
            self.log(f"TRAFFIC stage0 edge scan counted: {pre / 1024:.0f} KB")
        self.ensure_population()
        target = generations if generations is not None else self.config.max_generations
        n = 0
        while not self._stop:
            if target and n >= target:
                break
            while self._pause and not self._stop:
                time.sleep(0.05)
            self.run_generation()
            n += 1
            if self.state.traffic_bytes >= int(self.config.traffic_cap_mb * 1024 * 1024):
                break
        return self.state
