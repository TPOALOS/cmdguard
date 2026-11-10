# Changelog

## 1.0.0

First release.

- Classifies commands as allow, ask or deny; understands quotes, pipes, substitutions, bash -c, eval and wrappers
- Works as a Claude Code PreToolUse hook (exit 2 blocks, JSON ask) and as `check`; `install` prints the settings snippet and edits nothing
- Fails closed; modes, allow-rule, deny-regex, redacted decision log
