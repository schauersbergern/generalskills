# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Purpose

This is a collection of custom Claude Code skills. Each skill is packaged as a `.skill` file, which is a ZIP archive.

## Skill File Format

A `.skill` file is a ZIP archive with the following structure:

```
<skill-name>/
  SKILL.md          # Required: skill definition with YAML frontmatter
  <support files>   # Optional: scripts, assets, etc. (e.g., generate_image.js)
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

## Building a Skill

To create a `.skill` file from a directory:

```bash
zip -r <skill-name>.skill <skill-name>/
```

To inspect an existing `.skill` file:

```bash
unzip -l <skill-name>.skill        # list contents
unzip -p <skill-name>.skill <skill-name>/SKILL.md  # read SKILL.md
```

To extract and edit:

```bash
unzip <skill-name>.skill -d extracted/
# edit files in extracted/<skill-name>/
cd extracted && zip -r ../<skill-name>.skill <skill-name>/
```

## Skill Architecture

- **`SKILL.md`**: The skill prompt itself. Contains the frontmatter trigger description and full instructions Claude follows when the skill is invoked. Written in Markdown with step-by-step workflow sections.
- **Support scripts**: Node.js or shell scripts that the skill instructs Claude to execute via `Bash` tool calls. Designed to run in the Claude Code container environment (`/home/claude/`, `/mnt/user-data/outputs/`).

## Current Skills

| Skill | Description |
|-------|-------------|
| `gpt-image-skill` | Generates images via OpenAI `gpt-image-1` API, saves as PNG, presents in chat |

## Runtime Environment Assumptions

Skills in this repo assume the Claude Code container environment:
- Node.js available
- Output path: `/mnt/user-data/outputs/`
- Skill scripts installed at: `/home/claude/<skill-name>/`
- Environment variables for API keys (e.g., `OPENAI_API_KEY`)
