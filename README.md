# mas-harness-model-plane

The model plane (repository R06, harness H2 Model & Inference). This tree is the health-only shell of
PLANE-BOOTSTRAP-R06: exact CPython 3.12.14, standard library only, one health module
(`src/planeon_model/health/`) with its unittest (`tests/health/`), and the offline packet transport under `ci/`.

## Scope

- Health only: `health()` returns `{"status": "ok", "plane": "model"}`; the WSGI callable `application` answers
  `GET /health` with that mapping as JSON, any other path with 404 and any other method on `/health` with 405.
- No image, database, deployment, hosted workflow, model server, Makefile, porting ledger, third-party dependency or
  runtime code.

## Verification

Every pull request is verified by the owner-operated verifier: it runs the packet's offline acceptance command
`python3 -I -B -m unittest discover -s tests/health` through `./ci/verify-offline.sh`, with the hash-pinned task
packet and all outbound network denied.

## What comes next

- `MODEL-001` stays this repository's registered bootstrap: it alone owns the `Makefile`, `ci/run_make_target.py` and
  `PORTING.yaml`, and turns this shell's files from added to modified when it is implemented.
- Runtime coding stays behind two gates: `CONF-LINUX-001` (a native Linux baseline PASS) and
  `LANG-HOTPATH-DECISION-001`.

## License

Apache License 2.0; see `LICENSE`.
