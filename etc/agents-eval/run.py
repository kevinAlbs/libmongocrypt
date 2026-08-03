#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = ["rich>=13"]
# ///
"""Evaluate AGENTS.md.

Asks prompts to Claude. Test a before / after case and score the responses.
"""

import argparse
import json
import os
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

from rich.console import Console
from rich.table import Table

HERE = Path(__file__).resolve().parent
CASE_DIR = HERE / "tests"
OUT_DIR = HERE / "evals"  # gitignored
ROOT = Path(
    subprocess.run(
        ["git", "-C", str(HERE), "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
)

console = Console()

# Configurable via command-line flags:
MODEL = "sonnet"
EFFORT = "medium"
# Use a stronger model to evaluate answers.
EVALUATOR_MODEL = "opus"


def rel(p: Path) -> str:
    """Repo-relative path when possible, for readable output."""
    p = p.resolve()
    return str(p.relative_to(ROOT)) if p.is_relative_to(ROOT) else str(p)


def ask(prompt: str, system: Path | None, tools: str, model: str = "") -> dict:
    """Run one isolated headless claude and return its result JSON."""
    cmd = [
        "claude",
        "--strict-mcp-config",
        "--mcp-config",
        '{"mcpServers":{}}',
        "--disable-slash-commands",
        "--setting-sources",
        "",
        "--allowedTools",
        tools,
        "--output-format",
        "json",
        "--model",
        model or MODEL,
        "--effort",
        EFFORT,
    ]
    if system is not None:
        cmd += ["--append-system-prompt", system.read_text()]
    cmd += ["-p", prompt]

    proc = subprocess.run(
        cmd,
        cwd=ROOT,
        capture_output=True,
        text=True,
        env={
            **os.environ,
            # Keep each invocation independent of anything that ran before it.
            "CLAUDE_CODE_DISABLE_AUTO_MEMORY": "1",
            "DISABLE_PROMPT_CACHING": "1",
        },
    )

    if proc.returncode != 0:
        raise RuntimeError(
            f"claude failed ({proc.returncode}): stdout={proc.stdout.strip()} stderr={proc.stderr.strip()}"
        )
    return json.loads(proc.stdout)


EVALUATOR_PROMPT = """\
Below are a set of numbered statements and an answer, each between markers.

For each statement, decide whether the ANSWER states it.

Count a statement as met only if the answer conveys its substance. A statement
that merely name-drops a term the statement mentions, without the claim the
statement makes, is NOT met.

Output raw JSON and nothing else, listing the numbers of the statements met:
{{"met": [1, 4, 7]}}

--- BEGIN STATEMENTS ---
{statements}
--- END STATEMENTS ---

--- BEGIN ANSWER ---
{answer}
--- END ANSWER ---
"""


def score(answer: str, statements: list[str]) -> tuple[int, list[str]]:
    """Score an answer against the criteria. Returns (met count, missed).

    The evaluator gets no tools and no AGENTS.md.
    """
    numbered = "\n".join(f"{i}. {s}" for i, s in enumerate(statements, 1))
    out = ask(
        EVALUATOR_PROMPT.format(statements=numbered, answer=answer),
        None,
        "",
        EVALUATOR_MODEL,
    )
    # Tolerate code fences and pretty-printed JSON: take the outermost braces.
    match = re.search(r"\{.*\}", out.get("result", ""), re.DOTALL)
    if not match:
        raise RuntimeError(f"evaluator returned no JSON: {out.get('result')!r}")
    met = set(json.loads(match.group(0))["met"])

    missed = [f"{i}. {s}" for i, s in enumerate(statements, 1) if i not in met]
    return len(met), missed


@dataclass
class Run:
    cond: str
    index: int
    points: int
    missed: list[str]
    tokens: int


@dataclass
class Case:
    name: str
    prompt: str
    criteria: list[str]

    @classmethod
    def load(cls, path: Path) -> "Case":
        text = path.read_text()

        def section(title: str) -> str:
            m = re.search(
                rf"^## {title}\s*$(.*?)(?=^## |\Z)", text, re.MULTILINE | re.DOTALL
            )
            return m.group(1).strip() if m else ""

        prompt = section("Prompt")
        criteria = [
            re.sub(r"^\d+\.\s*", "", line).strip()
            for line in section("Criteria").splitlines()
            if re.match(r"^\d+\.", line.strip())
        ]
        if not prompt:
            raise ValueError(f"{path.name}: no '## Prompt' section")
        if not criteria:
            raise ValueError(f"{path.name}: no numbered criteria")
        return cls(path.stem, prompt, criteria)


@dataclass
class Tally:
    """Criteria met by each condition, out of the criteria attempted."""

    passed_before: int
    passed_after: int
    attempted: int
    tokens_before: int
    tokens_after: int


@dataclass
class Variant:
    """One side of the comparison: a label and the file to append (or nothing)."""

    label: str
    path: Path | None

    def describe(self) -> str:
        return rel(self.path) if self.path else "no AGENTS.md"


def one_run(case: Case, variant: Variant, index: int) -> Run:
    result = ask(case.prompt, variant.path, "Read Grep Glob")
    answer = result["result"]
    # Tokens the answer cost. Caching is disabled, so the cache fields are zero.
    # The evaluator's own usage is measurement overhead, and is not counted.
    usage = result["usage"]
    tokens = usage["input_tokens"] + usage["output_tokens"]

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUT_DIR / f"{case.name}-{variant.label}-{index}.md").write_text(answer)

    points, missed = score(answer, case.criteria)
    return Run(
        cond=variant.label,
        index=index,
        points=points,
        missed=missed,
        tokens=tokens,
    )


def run_case(
    case: Case, runs: int, before: Variant, after: Variant, jobs: int
) -> Tally:
    total = len(case.criteria)
    work = [(v, i) for v in (before, after) for i in range(1, runs + 1)]

    with console.status(f"[bold]{case.name}[/] — {len(work) * 2} invocations"):
        with ThreadPoolExecutor(max_workers=jobs) as pool:
            results = list(pool.map(lambda vi: one_run(case, vi[0], vi[1]), work))

    console.print(f"[bold]{case.name}[/] — {case.prompt}", soft_wrap=True)

    table = Table(header_style="bold")
    table.add_column("cond")
    table.add_column("run", justify="right")
    table.add_column("passed", justify="right")

    for r in results:
        style = "cyan" if r.cond == after.label else None
        table.add_row(r.cond, str(r.index), f"{r.points}/{total}", style=style)

    passed = {
        v.label: sum(r.points for r in results if r.cond == v.label)
        for v in (before, after)
    }
    tokens = {
        v.label: sum(r.tokens for r in results if r.cond == v.label)
        for v in (before, after)
    }
    attempted = total * runs
    table.add_section()
    for v in (before, after):
        rate = 100 * passed[v.label] / attempted
        table.add_row(
            f"[bold]{v.label}[/]",
            "total",
            f"{passed[v.label]}/{attempted} ({rate:.0f}%)",
        )

    delta = 100 * (passed[after.label] - passed[before.label]) / attempted
    table.add_row(
        "[bold]delta[/]",
        "",
        f"[{'green' if delta >= 0 else 'red'}]{delta:+.0f}%[/]",
    )
    console.print(table)

    for r in results:
        if r.missed:
            console.print(f"  [dim]{r.cond} {r.index} missed:[/]")
            for m in r.missed:
                console.print(f"    [yellow]-[/] {m}", soft_wrap=True)

    console.print(
        f"  [dim]{MODEL} at {EFFORT} effort"
        f"   runs: {runs}"
        f"   before: {before.describe()}"
        f"   after: {after.describe()}[/]",
        soft_wrap=True,
    )
    console.print(
        f"  [dim]answers: {rel(OUT_DIR)}/{case.name}-*.md[/]\n", soft_wrap=True
    )
    return Tally(
        passed[before.label],
        passed[after.label],
        attempted,
        tokens[before.label],
        tokens[after.label],
    )


def summary(tallies: list[Tally], before: Variant, after: Variant) -> None:
    """Two numbers for the whole suite, to compare against a later run.

    "passed" is what AGENTS.md gets right; "tokens" is what it costs to get
    there. AGENTS.md is re-sent every turn, so it can lower the token count only
    by saving more exploration than it adds.
    """
    total = Tally(
        sum(t.passed_before for t in tallies),
        sum(t.passed_after for t in tallies),
        sum(t.attempted for t in tallies),
        sum(t.tokens_before for t in tallies),
        sum(t.tokens_after for t in tallies),
    )

    table = Table(header_style="bold")
    table.add_column("cond")
    table.add_column("passed", justify="right")
    table.add_column("tokens", justify="right")
    for v, points, tokens in (
        (before, total.passed_before, total.tokens_before),
        (after, total.passed_after, total.tokens_after),
    ):
        rate = 100 * points / total.attempted
        table.add_row(
            f"[bold]{v.label}[/]",
            f"{points}/{total.attempted} ({rate:.0f}%)",
            f"{tokens:,}",
        )

    d_passed = 100 * (total.passed_after - total.passed_before) / total.attempted
    # Fewer tokens is better, so a negative delta is the good direction.
    d_tokens = 100 * (total.tokens_after - total.tokens_before) / total.tokens_before
    table.add_section()
    table.add_row(
        "[bold]delta[/]",
        f"[{'green' if d_passed >= 0 else 'red'}]{d_passed:+.0f}%[/]",
        f"[{'green' if d_tokens <= 0 else 'red'}]{d_tokens:+.0f}%[/]",
    )

    cases = "case" if len(tallies) == 1 else "cases"
    console.print(f"[bold]all {len(tallies)} {cases}[/]")
    console.print(table)
    console.print(
        f"  [dim]{MODEL} at {EFFORT} effort, graded by {EVALUATOR_MODEL}"
        f"   before: {before.describe()}   after: {after.describe()}[/]",
        soft_wrap=True,
    )


def banner(
    paths: list[Path], args: argparse.Namespace, before: Variant, after: Variant
) -> None:
    """Explain what is about to happen, before the first case takes minutes."""
    names = ", ".join(p.stem for p in paths)
    invocations = len(paths) * args.runs * 2 * 2  # 2 conditions, +1 evaluator each

    console.print(
        "\n[bold]Evaluating AGENTS.md[/]. A higher pass rate is better.\n",
        soft_wrap=True,
    )
    console.print(
        f"  [dim]cases:   {names}\n"
        f"  before:  {before.describe()}\n"
        f"  after:   {after.describe()}\n"
        f"  runs:    {args.runs} per condition\n"
        f"  jobs:    {args.jobs}\n"
        f"  model:   {args.model} at {args.effort} effort\n"
        f"  grader:  {args.evaluator_model}\n"
        f"  {invocations} claude invocations; this may take a while.[/]\n",
        soft_wrap=True,
    )


def main() -> None:
    global MODEL, EFFORT, EVALUATOR_MODEL

    p = argparse.ArgumentParser(
        description=(__doc__ or "").splitlines()[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("cases", nargs="*", help="case names (default: all)")
    p.add_argument(
        "--runs",
        type=int,
        default=3,
        help="runs per condition; more runs give a steadier pass rate (default: 3)",
    )
    p.add_argument(
        "--before",
        type=Path,
        default=None,
        help="the AGENTS.md to compare against; omit for no AGENTS.md at all",
    )
    p.add_argument(
        "--after",
        type=Path,
        default=ROOT / "AGENTS.md",
        help="the AGENTS.md under test (default: ./AGENTS.md)",
    )
    p.add_argument(
        "--jobs",
        type=int,
        default=None,
        help="concurrent job count (default: runs * 2)",
    )
    p.add_argument(
        "--model",
        default=MODEL,
        help=f"model alias or full name (default: {MODEL})",
    )
    p.add_argument(
        "--evaluator-model",
        default=EVALUATOR_MODEL,
        help=f"model that grades the answers (default: {EVALUATOR_MODEL})",
    )
    p.add_argument(
        "--effort",
        default=EFFORT,
        choices=("low", "medium", "high", "xhigh", "max"),
        help=f"effort level (default: {EFFORT})",
    )
    args = p.parse_args()
    # The parallelism within a case is every run of both conditions.
    args.jobs = args.jobs or args.runs * 2

    MODEL, EFFORT = args.model, args.effort
    EVALUATOR_MODEL = args.evaluator_model

    for f in (args.before, args.after):
        if f is not None and not f.exists():
            p.error(f"no such file: {f}")

    before = Variant("before", args.before)
    after = Variant("after", args.after)

    if args.cases:
        paths = [CASE_DIR / f"{c.removesuffix('.md')}.md" for c in args.cases]
    else:
        paths = sorted(CASE_DIR.glob("*.md"))

    for path in paths:
        if not path.exists():
            p.error(f"no such case: {rel(path)}")

    banner(paths, args, before, after)

    tallies = [
        run_case(Case.load(path), args.runs, before, after, args.jobs) for path in paths
    ]
    summary(tallies, before, after)


if __name__ == "__main__":
    main()
