# maid

`maid` is a local-first assistant runtime with:

- groups (context/workspaces)
- scheduled tasks
- plugins and skills
- CLI + dashboard + gateway + Telegram surfaces

## 5-minute setup

1. Create config:

```bash
cargo run -p maid -- init --template personal
```

2. Add API key to `.env`:

```bash
OPENAI_API_KEY=your_key_here
```

3. Validate environment:

```bash
cargo run -p maid -- doctor
```

4. Create a group and run a prompt:

```bash
cargo run -p maid -- group create work
cargo run -p maid -- run --group work --prompt "Plan my day in 5 bullets"
```

## Common commands

```bash
# status
cargo run -p maid -- status

# groups
cargo run -p maid -- group list

# tasks
cargo run -p maid -- task list --group work
cargo run -p maid -- task run-now --id <task_id>

# plugins
cargo run -p maid -- plugin list
cargo run -p maid -- plugin run --name <plugin> --command help
```

## Run services

```bash
# scheduler only
cargo run -p maid -- daemon

# dashboard (HTTP)
cargo run -p maid -- dashboard --port 18790

# gateway
cargo run -p maid -- gateway --port 18789

# scheduler + gateway + telegram
cargo run -p maid -- serve

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
