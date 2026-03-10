# nikskills

A collection of custom Claude Code skills.

## Skills

| Skill | Description |
|-------|-------------|
| `gpt-image-skill` | Generate images via OpenAI `gpt-image-1` API directly in chat |

## Usage

Install a skill in Claude Code by uploading the `.skill` file. Ensure any required environment variables (e.g. `OPENAI_API_KEY`) are set in your container.

## File Format

Each `.skill` file is a ZIP archive containing a `SKILL.md` (with YAML frontmatter and instructions) and optional support scripts.
