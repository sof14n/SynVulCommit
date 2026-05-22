# SynVulCommit

SynVulCommit is a standalone synthetic vulnerability-commit generator. It asks an AI provider to generate paired vulnerable/fixed Python code, validates the result, stores accepted samples as JSONL, and exports them to the VUDENC-style `plain_<mode>` files used by the older project code.

## Quick start

Run these commands from this folder:

```powershell
python -m synvulcommit.run_generation --per-cwe 1 --provider mock
```

Outputs:

```text
output/samples.jsonl
output/rejected.jsonl
output/vudenc/metadata.jsonl
output/vudenc/plain_sql
output/vudenc/plain_command_injection
output/vudenc/plain_directory_traversal
output/vudenc/plain_open_redirect
output/vudenc/plain_remote_code_execution
output/vudenc/plain_xss
output/vudenc/plain_xsrf
```

The mock provider is deterministic and works without an API key. It is meant for smoke-testing the pipeline.

Accepted `samples.jsonl` records include provenance fields: `provider`, `model`, `prompt_sha256`, `seed`, `attempt`, `generated_at`, and `validation_summary`.

## Optional validation tools

The pipeline always runs CWE-specific structural checks. If Bandit or Semgrep are installed, it also runs them and records their findings.

```powershell
python -m pip install -r requirements.txt
```

Use strict external-tool validation when you want missing Bandit/Semgrep to fail generation:

```powershell
python -m synvulcommit.run_generation --per-cwe 1 --provider mock --require-tools
```

## Production mode

Use production mode for real dataset generation:

```powershell
python -m synvulcommit.run_generation --production --require-tools --per-cwe 10 --provider local_http
```

Production mode refuses `--provider mock`, requires `--require-tools`, and requires model metadata through `SYNVUL_MODEL` for `openai_compatible` or `SYNVUL_LOCAL_MODEL` for `local_http`.

## OpenAI-compatible provider

Any chat-completions-compatible endpoint can be used:

```powershell
$env:SYNVUL_BASE_URL="https://api.openai.com/v1"
$env:SYNVUL_API_KEY="your_api_key"
$env:SYNVUL_MODEL="gpt-4.1-mini"
python -m synvulcommit.run_generation --per-cwe 10 --provider openai_compatible
```

For OpenRouter or similar gateways, set `SYNVUL_BASE_URL` to the gateway's OpenAI-compatible base URL and `SYNVUL_MODEL` to the routed model name.

## Local HTTP provider

Use this when a local model exposes a simple HTTP endpoint:

```powershell
$env:SYNVUL_LOCAL_URL="http://127.0.0.1:11434/api/generate"
$env:SYNVUL_LOCAL_MODEL="codellama"
python -m synvulcommit.run_generation --per-cwe 10 --provider local_http
```

The response parser accepts common shapes such as OpenAI `choices`, Ollama-style `response`, and simple `text` or `generated_text` fields.
It strips reasoning-model `<think>...</think>` blocks and parses the final JSON object, so thinking text is not written to accepted or rejected dataset files.
For Ollama reasoning models, the API may return reasoning in a separate `thinking` field; SynVulCommit ignores that field and parses only the final response text.
By default, the local provider sends `format=json`, `temperature=0.2`, `num_predict=4096`, and uses a 300-second HTTP timeout, which works well with Ollama. Set `SYNVUL_LOCAL_FORMAT=""` if your local endpoint does not accept that field, or set `SYNVUL_HTTP_TIMEOUT` for slower local models.

## Export only

```powershell
python -m synvulcommit.export_vudenc --input output/samples.jsonl --out output/vudenc
```

The export writes the seven `plain_<mode>` files plus `metadata.jsonl`. Each metadata row links one exported sample to its `plain_file`, `row_index`, `repo`, and `commit_id`, and preserves provider/model/prompt-hash provenance without storing API keys, authorization headers, or endpoint URLs.

## Notes

- This is teacher-generated synthetic supervision, not classic logit-based knowledge distillation.
- The AI generates candidates; the pipeline validates and stores only accepted samples.
- Use `--require-tools` for strict runs that require Bandit and Semgrep to execute successfully.
- Thinking/reasoning model output is sanitized before JSON parsing, but production runs should still prefer JSON/structured-output modes when the provider supports them.
