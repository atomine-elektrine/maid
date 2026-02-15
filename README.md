# maid

`maid` is a local-first assistant runtime with:

- groups (context/workspaces)
- scheduled tasks
- plugins and skills
- CLI + dashboard + gateway + Telegram surfaces

## How to run commands

All examples below use `maid` directly:

```bash
maid <command>
```

If you are running from source and do not have `maid` installed, use:

```bash
cargo run -p maid -- <command>
```

Optional shell helper while developing from source:

```bash
alias maid='cargo run -p maid --'
```

## 5-minute setup

1. Create config:

```bash
maid init --template personal
```

2. Add API key to `.env`:

```bash
OPENAI_API_KEY=your_key_here
```

3. Validate environment:

```bash
maid doctor
```

4. Create a group and run a prompt:

```bash
maid group create work
maid run --group work --prompt "Plan my day in 5 bullets"
```

## Common commands

```bash
# status
maid status

# groups
maid group list

# tasks
maid task list --group work
maid task run-now --id <task_id>

# plugins
maid plugin list
maid plugin run --name <plugin> --command help
```

## Run services

```bash
# scheduler only
maid daemon

# dashboard (HTTP)
maid dashboard --port 18790

# gateway
maid gateway --port 18789

# scheduler + gateway + telegram
maid serve

# prometheus metrics (gateway)
curl -s http://127.0.0.1:18789/metrics
```

## Plugin HTTP API (generic)

When dashboard is running, call any enabled plugin via HTTP.

```bash
# list plugins
curl -s http://127.0.0.1:18790/api/plugins | jq .

# plugin capability discovery
curl -s http://127.0.0.1:18790/api/plugins/<plugin>/describe | jq .

# capability-style call (defaults to command=execute)
curl -s http://127.0.0.1:18790/api/plugins/<plugin>/execute \
  -H "content-type: application/json" \
  -d '{"args":{"capability":"siem.query.convert.ai","from":"spl","to":"kql"},"input":"search EventCode=4625 user=alice"}' | jq .

# direct command call
curl -s http://127.0.0.1:18790/api/plugins/<plugin>/command/convert \
  -H "content-type: application/json" \
  -d '{"args":{"from":"spl","to":"kql"},"input":"search EventCode=4625 user=alice"}' | jq .
```

## Where things are

- config: `config.toml`
- data: `data/assistant.db`
- groups: `groups/`
- plugins: `plugins/`
- skills: `skills/`

## Notes

- Default model provider in this repo is OpenAI-compatible.
- Start with `status`, `doctor`, and `plugin list` if something is unclear.
