# AGENTS.md evaluation

Evaluates `AGENTS.md` by testing prompt answers.

## Running

```bash
etc/agents-eval/run.py                        # every case
etc/agents-eval/run.py thread-safety          # one case
etc/agents-eval/run.py --runs 1 thread-safety # fewer runs while drafting criteria
etc/agents-eval/run.py --jobs 2 thread-safety # cap concurrent invocations
```

`run.py` needs [uv](https://docs.astral.sh/uv/) and `claude`.

By default the working-tree `AGENTS.md` is compared against no `AGENTS.md`.
Use `--before` to compare against a different `AGENTS.md`:

```bash
git show HEAD:AGENTS.md > /tmp/before.md
etc/agents-eval/run.py --before /tmp/before.md
```

Runs are expected to be read-only. Full answers are saved under the gitignored `evals/`.