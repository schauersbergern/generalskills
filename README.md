# nikskills

A collection of custom Claude Code skills. Each skill lives in its own directory containing a `SKILL.md` and optional support scripts.

## Skills

### `gpt-image-skill`

Generates images via OpenAI `gpt-image-1` API, saves as PNG, and presents them in chat.

| File | Purpose |
|------|---------|
| `gpt-image-skill/SKILL.md` | Skill definition — trigger description, workflow, error handling |
| `gpt-image-skill/generate_image.js` | Node.js script that calls the OpenAI Images API and saves the result as PNG |

**Required env var:** `OPENAI_API_KEY`

## Usage

Install a skill in Claude Code by referencing the skill directory. Ensure any required environment variables are set in your container.

## Skill Structure

Each skill lives in its own directory:

```
<skill-name>/
  SKILL.md          # Required: skill definition with YAML frontmatter
  <support files>   # Optional: scripts, assets, etc.
```

### SKILL.md Frontmatter

```yaml
---
name: <skill-name>
description: >
  Trigger description — tells Claude when to invoke this skill.
---
```

The `description` field controls when Claude auto-invokes the skill, so it should list all relevant trigger phrases and use-cases.

## Skill Architecture

- **`SKILL.md`**: The skill prompt itself. Contains the frontmatter trigger description and full instructions Claude follows when the skill is invoked. Written in Markdown with step-by-step workflow sections.
- **Support scripts**: Node.js or shell scripts that the skill instructs Claude to execute via `Bash` tool calls. Designed to run in the Claude Code container environment (`/home/claude/`, `/mnt/user-data/outputs/`).

## Runtime Environment Assumptions

Skills in this repo assume the Claude Code container environment:
- Node.js available
- Output path: `/mnt/user-data/outputs/`
- Skill scripts installed at: `/home/claude/<skill-name>/`
- Environment variables for API keys (e.g., `OPENAI_API_KEY`)
