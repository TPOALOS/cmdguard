#!/usr/bin/env python3
"""cmdguard - stop an AI agent from running the shell command you would never approve.

Coding agents run shell commands for you. Most are harmless; a few are `rm -rf ~`, `curl ... | sudo sh`, uploading
your SSH key, or force-pushing over main. cmdguard reads a proposed command and says allow, ask or deny. It works as a
Claude Code PreToolUse hook (it reads the hook's JSON on stdin) and as a plain command line check. It never runs the
command it inspects.

    cmdguard check 'rm -rf ~'          # try it
    cmdguard install                   # prints the settings.json snippet to register the hook (it never edits your settings)

It is a safety net of known-dangerous patterns, NOT a sandbox: a determined or obfuscated command can get past a
pattern list. Pair it with the agent's own permission prompts and, for untrusted work, a container or VM.
Exit codes: hook mode 0 = allow (or ask, via JSON), 2 = block; `check` 0 = allow, 1 = ask/deny, 2 = usage error.
"""
import argparse
import json
import os
import re
import sys
import time

__version__ = "1.0.0"

MAX_INPUT = 1_000_000
MAX_DEPTH = 4
SEV = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}

OPERATORS = {";", "&&", "||", "|", "&", "\n", "|&"}
WRAPPERS = {"sudo", "doas", "env", "command", "nohup", "time", "nice", "ionice", "exec", "stdbuf", "builtin", "setsid", "caffeinate"}
SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "fish"}
DANGEROUS_RM = {"/", "/*", "~", "~/", "~/*", "$HOME", "${HOME}", "$HOME/", "${HOME}/", "$HOME/*", "${HOME}/*", ".", "./", "..", "../", "*", ".*",
                "./*", "../*", "../..", ".git", "/.", "/Users", "/home", "/root", "/etc", "/usr", "/var", "/bin", "/sbin", "/lib", "/opt", "/System",
                "/Library", "/Applications", "/private", "/boot", "/dev", "/proc", "/sys", "C:\\", "C:/"}
SYSTEM_PATH = re.compile(r"^/(opt|usr|etc|var|bin|sbin|lib|lib64|boot|srv|root|System|Library|Applications|private|Volumes|mnt|media)(/|$)")
SENSITIVE_DIR = re.compile(r"(\.ssh|\.aws|\.gnupg|\.kube|\.config/gcloud|\.azure|\.password-store)(/|\s|$)")
SENSITIVE = re.compile(
    r"(~|\$HOME|\$\{HOME\}|/Users/[^/\s]+|/home/[^/\s]+|/root)?/?\.(ssh|aws|gnupg|kube|docker|config/gcloud|azure|npmrc|pypirc|netrc|pgpass|git-credentials|password-store)(/|\b)"
    r"|id_(rsa|dsa|ecdsa|ed25519)\b|/etc/(shadow|sudoers|master\.passwd)\b|\.env(\.[A-Za-z0-9_-]+)?\b|credentials(\.json)?\b|keychain|\.kdbx\b|\.pem\b|\.p12\b")
SECRET_DUMP = re.compile(r"\b(printenv|env|set|export\s+-p|history)\b|/proc/[^\s]*/environ")
NETWORK_UPLOADERS = {"curl", "wget", "nc", "ncat", "netcat", "socat", "scp", "sftp", "rsync", "ftp", "http", "httpie", "xh"}
PERSISTENCE_FILES = re.compile(r"(\.bashrc|\.bash_profile|\.zshrc|\.zprofile|\.profile|\.zshenv|\.bash_login|/etc/profile|/etc/rc\.local|"
                               r"authorized_keys|\.ssh/config|/etc/cron|/var/spool/cron|LaunchAgents|LaunchDaemons|/etc/systemd|\.config/autostart)")
REMOTE_DESTRUCTIVE = (
    (r"\bterraform\s+(destroy|apply\s+.*-auto-approve)", "terraform-destroy", "destroys or applies infrastructure without a review"),
    (r"\bkubectl\s+delete\s+(ns|namespace|all|--all|node|pv|crd)\b|\bkubectl\s+delete\b.*--all\b", "kubectl-delete", "deletes cluster resources in bulk"),
    (r"\baws\s+s3\s+(rm|rb)\b.*--recursive|\baws\s+s3\s+rb\b|\baws\s+\S+\s+delete-", "aws-delete", "deletes cloud resources"),
    (r"\bgcloud\s+.*\bdelete\b|\baz\s+.*\bdelete\b", "cloud-delete", "deletes cloud resources"),
    (r"\bgh\s+repo\s+delete\b", "gh-repo-delete", "deletes a GitHub repository"),
    (r"\bnpm\s+publish\b|\bcargo\s+publish\b|\btwine\s+upload\b|\bgem\s+push\b", "publish-package", "publishes a package to a public registry"),
    (r"\bdocker\s+(system|volume|image|container)\s+prune\b.*(-a|--all|-f|--force)|\bdocker\s+rm\s+-f\b.*\$\(", "docker-prune", "removes containers, images or volumes in bulk"),
    (r"\b(drop\s+(database|table|schema)|truncate\s+table|delete\s+from\s+\w+\s*(;|$|\"|'))", "sql-destructive", "runs destructive SQL"),
    (r"\bflushall\b|\bflushdb\b", "redis-flush", "wipes a Redis database"),
)


# ---------------------------------------------------------------- tokenising
def _find_close(s, i, open_ch, close_ch):
    """Index of the bracket that closes the one opened just before ``i`` (quotes respected), or len(s)."""
    depth, quote = 1, None
    while i < len(s):
        c = s[i]
        if quote:
            if c == "\\" and quote == '"':
                i += 1
            elif c == quote:
                quote = None
        elif c in ("'", '"'):
            quote = c
        elif c == "\\":
            i += 1
        elif c == open_ch:
            depth += 1
        elif c == close_ch:
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return len(s)


def tokenize(s):
    """Split a shell command line -> (tokens, substitutions). tokens: ('w', text) or ('op', operator)."""
    tokens, subs = [], []
    word, in_word, i, n = [], False, 0, len(s)

    def flush():
        nonlocal word, in_word
        if in_word:
            tokens.append(("w", "".join(word)))
        word, in_word = [], False

    while i < n:
        c = s[i]
        if c == "\\" and i + 1 < n:
            if s[i + 1] == "\n":
                i += 2
                continue
            word.append(s[i + 1])
            in_word = True
            i += 2
        elif c == "'":
            j = s.find("'", i + 1)
            j = n if j == -1 else j
            word.append(s[i + 1:j])
            in_word = True
            i = j + 1
        elif c == '"':
            in_word = True
            i += 1
            while i < n and s[i] != '"':
                if s[i] == "\\" and i + 1 < n:
                    word.append(s[i + 1])
                    i += 2
                elif s.startswith("$(", i):
                    j = _find_close(s, i + 2, "(", ")")
                    subs.append(s[i + 2:j])
                    word.append(s[i:j + 1])
                    i = j + 1
                elif s[i] == "`":
                    j = s.find("`", i + 1)
                    j = n if j == -1 else j
                    subs.append(s[i + 1:j])
                    word.append(s[i:j + 1])
                    i = j + 1
                else:
                    word.append(s[i])
                    i += 1
            i += 1
        elif s.startswith("$(", i) or s.startswith("<(", i) or s.startswith(">(", i):
            j = _find_close(s, i + 2, "(", ")")
            subs.append(s[i + 2:j])
            word.append(s[i:j + 1])
            in_word = True
            i = j + 1
        elif c == "`":
            j = s.find("`", i + 1)
            j = n if j == -1 else j
            subs.append(s[i + 1:j])
            word.append(s[i:j + 1])
            in_word = True
            i = j + 1
        elif c in " \t\r":
            flush()
            i += 1
        elif c == "\n":
            flush()
            tokens.append(("op", "\n"))
            i += 1
        elif c == "#" and not in_word:
            while i < n and s[i] != "\n":
                i += 1
        elif c in ";&|":
            flush()
            two = s[i:i + 2]
            if two in ("&&", "||", "|&"):
                tokens.append(("op", two))
                i += 2
            else:
                tokens.append(("op", c))
                i += 1
        elif c == ")" or (c in "({}" and not in_word):
            flush()
            i += 1
        else:
            word.append(c)
            in_word = True
            i += 1
    flush()
    return tokens, subs


def split_commands(tokens):
    """Group tokens into simple commands: [{"words": [...], "pipe_to": next command words or None}]."""
    cmds, cur = [], []
    for kind, value in tokens:
        if kind == "w":
            cur.append(value)
        else:
            if cur:
                cmds.append({"words": cur, "op": value})
            cur = []
    if cur:
        cmds.append({"words": cur, "op": None})
    return cmds


def strip_prefix(words):
    """Drop env assignments and wrappers (sudo, env, nohup ...). -> (core words, set of wrappers seen, assignments)."""
    words, wrappers, assigns = list(words), set(), []
    while words:
        w = words[0]
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", w):
            assigns.append(words.pop(0))
        elif os.path.basename(w) in WRAPPERS:
            wrappers.add(os.path.basename(w))
            words.pop(0)
            while words and (words[0].startswith("-") or re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", words[0]) or
                             (wrappers & {"timeout", "nice", "ionice"} and re.match(r"^\d+[smhd]?$", words[0]))):
                if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", words[0]):
                    assigns.append(words[0])
                words.pop(0)
        elif w == "timeout" and len(words) > 1:
            wrappers.add("timeout")
            words = words[2:]
        else:
            break
    if not words and "env" in wrappers:  # a bare `env` prints the environment: it is a command, not a wrapper
        words = ["env"]
    return words, wrappers, assigns


# ------------------------------------------------------------------ analysis
def _rm_findings(words, add):
    flags = [w for w in words[1:] if w.startswith("-")]
    targets = [w for w in words[1:] if not w.startswith("-")]
    recursive = any(f in ("--recursive",) or (not f.startswith("--") and re.search(r"[rR]", f)) for f in flags)
    if "--no-preserve-root" in words:
        add("HIGH", "rm-no-preserve-root", "rm with --no-preserve-root removes the filesystem root")
    if not recursive:
        return
    for t in targets:
        if SENSITIVE_DIR.search(t + " ") and not re.search(r"\.pub\b|known_hosts", t):
            add("MEDIUM", "rm-credentials", "deletes a folder that holds your SSH keys or credentials (%s)" % t)
        bare = t.rstrip("/") or "/"
        if t in DANGEROUS_RM or bare in DANGEROUS_RM or re.fullmatch(r"~[A-Za-z0-9_.-]*/?\*?", t) or \
                re.fullmatch(r"/[^/]+/?\*?", t) and t not in ("/tmp", "/tmp/") or t.startswith("/*") or re.fullmatch(r"(\.\./?)+\*?", t):
            add("HIGH", "rm-recursive-broad", "recursive delete of %s would wipe far more than a project" % t)
        elif re.match(r"^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?(/\*?)?$", t) or re.match(r"^\"?\$\{?[A-Za-z_]\w*\}?/?\"?$", t):
            add("MEDIUM", "rm-unset-variable", "recursive delete of %s: if the variable is empty this becomes `rm -rf /`" % t)
        elif SYSTEM_PATH.match(t) and not t.startswith(("/var/tmp/", "/var/folders/", "/private/tmp/", "/private/var/folders/")):
            add("MEDIUM", "rm-recursive-system-path", "recursive delete under a system path (%s)" % t)
    if not targets:
        add("MEDIUM", "rm-recursive-no-target", "recursive rm whose targets come from elsewhere (xargs or a pipe)")


def analyze_command(command, depth=0, findings=None):
    """Findings for a command string: [(severity, rule, message)]. Never executes anything."""
    findings = [] if findings is None else findings
    add = lambda sev, rule, msg: findings.append((sev, rule, msg))
    if depth > MAX_DEPTH:
        add("MEDIUM", "too-deeply-nested", "the command nests substitutions or shells too deeply to inspect")
        return findings
    raw = command
    if re.search(r":\s*\(\s*\)\s*\{[^}]*:\s*\|\s*:\s*&", raw):
        add("HIGH", "fork-bomb", "this is a fork bomb")
    tokens, subs = tokenize(command)
    cmds = split_commands(tokens)
    for sub in subs:
        analyze_command(sub, depth + 1, findings)
    for idx, c in enumerate(cmds):
        words, wrappers, assigns = strip_prefix(c["words"])
        if "sudo" in wrappers or "doas" in wrappers:
            add("MEDIUM", "sudo", "runs with administrator rights")
        for a in assigns:
            if re.match(r"^(LD_PRELOAD|DYLD_INSERT_LIBRARIES)=", a):
                add("HIGH", "library-injection", "injects a library into the process")
        if not words:
            continue
        base = os.path.basename(words[0])
        line = " ".join(words)
        nxt = cmds[idx + 1]["words"] if c["op"] in ("|", "|&") and idx + 1 < len(cmds) else None
        nxt_core, _, _ = strip_prefix(nxt) if nxt else ([], set(), [])
        nxt_base = os.path.basename(nxt_core[0]) if nxt_core else ""

        if base == "rm":
            _rm_findings(words, add)
        if base == "find" and "-delete" in words:
            where = [w for w in words[1:] if not w.startswith("-")][:1]
            add("HIGH" if where and where[0] in DANGEROUS_RM else "MEDIUM", "find-delete", "find -delete removes everything it matches")
        if base == "find" and re.search(r"-exec\s+(sudo\s+)?rm\b", line) and any(w in DANGEROUS_RM for w in words[1:2]):
            add("HIGH", "find-delete", "find ... -exec rm on a broad location")
        if base == "dd" and any(w.startswith("of=/dev/") for w in words):
            add("HIGH", "disk-overwrite", "dd writes straight to a disk device")
        if re.match(r"^(mkfs|mke2fs|newfs)", base) or base in ("fdisk", "parted", "sfdisk", "wipefs", "gdisk") or \
                (base == "diskutil" and re.search(r"erase|partition|apfs\s+delete", line)):
            add("HIGH", "disk-format", "formats or repartitions a disk")
        if base == "shred" and any(w.startswith("/dev/") for w in words):
            add("HIGH", "disk-overwrite", "shred on a disk device")
        if base in ("shutdown", "reboot", "halt", "poweroff") or (base == "init" and words[1:2] in (["0"], ["6"])):
            add("HIGH", "power-off", "shuts down or reboots the machine")
        if base in ("chmod", "chown", "chgrp") and any(f in words for f in ("-R", "-r", "--recursive")) and \
                any(t in DANGEROUS_RM for t in words[1:]):
            add("HIGH", "chmod-recursive-broad", "recursive permission change on a broad location")
        if base == "chmod" and any(re.match(r"^[0-7]*7[0-7]7$", w) or w in ("a+rwx", "o+w", "ugo+rwx") for w in words[1:]):
            add("MEDIUM", "chmod-world-writable", "makes files world-writable")
        if base == "chmod" and any(re.match(r"^[ug]\+s$|^[2467][0-7]{3}$", w) for w in words[1:]):
            add("MEDIUM", "setuid", "sets a setuid/setgid bit")
        if base in ("kill", "killall", "pkill") and (words[1:3] in (["-9", "-1"], ["-KILL", "-1"]) or "-1" in words[1:3] and base == "kill"):
            add("HIGH", "kill-everything", "kills every process you own")
        if base in ("killall", "pkill") and any(re.fullmatch(r"-?(9|KILL)", w) for w in words[1:]):
            add("MEDIUM", "kill-broad", "force-kills processes by name")
        if base == "git":
            sub = [w for w in words[1:] if not w.startswith("-")][:1]
            if sub == ["push"] and any(w in ("--force", "-f") or w.startswith("--force=") for w in words) and "--force-with-lease" not in line:
                add("MEDIUM", "git-force-push", "force-pushing can destroy other people's commits")
            if sub == ["push"] and any(w in ("--mirror", "--delete", "-d") for w in words):
                add("MEDIUM", "git-push-destructive", "deletes remote branches or overwrites the whole remote")
            if sub == ["reset"] and "--hard" in words:
                add("MEDIUM", "git-reset-hard", "discards uncommitted work for good")
            if sub == ["clean"] and any(re.match(r"^-[a-z]*f", w) for w in words) and any("x" in w or "d" in w for w in words if w.startswith("-")):
                add("MEDIUM", "git-clean", "deletes untracked (and maybe ignored) files for good")
            if sub in (["checkout"], ["restore"]) and words[-1] == ".":
                add("MEDIUM", "git-discard-changes", "throws away all local changes")
            if sub == ["filter-branch"] or sub == ["filter-repo"]:
                add("MEDIUM", "git-rewrite-history", "rewrites repository history")
        if base in SHELLS:
            code = None
            for k, w in enumerate(words):
                if w in ("-c", "-lc", "-ic", "-xc") and k + 1 < len(words):
                    code = words[k + 1]
            if code:
                analyze_command(code, depth + 1, findings)
        if base in ("eval",):
            payload = " ".join(words[1:])
            analyze_command(payload, depth + 1, findings)
            if re.search(r"\$\(|`|\$\{?[A-Za-z_]", payload):
                add("MEDIUM", "eval-dynamic", "eval executes text that is only known at run time")
        if base in ("python", "python3", "node", "ruby", "perl", "php") and any(w in ("-c", "-e", "-r") for w in words):
            code = " ".join(words[1:])
            if re.search(r"os\.system|subprocess|child_process|exec\(|popen|system\(|`", code) and re.search(
                    r"rm\s+-[a-z]*r|curl|wget|/dev/tcp|nc\s|base64|\.ssh|\.aws|chmod\s+777", code):
                add("MEDIUM", "inline-interpreter-shell", "an inline script runs shell commands that look risky")
        # pipes into shells and interpreters
        if base in ("curl", "wget", "fetch", "http") and nxt_base in SHELLS | {"python", "python3", "perl", "ruby", "node", "sudo", "source", "."}:
            sudoed = nxt_base == "sudo" or (nxt and nxt[0] == "sudo")
            add("HIGH" if sudoed else "MEDIUM", "pipe-to-shell", "downloads a script and runs it without reading it" + (" as administrator" if sudoed else ""))
        if base in ("base64", "xxd", "openssl", "rev", "tr", "gunzip", "zcat") and nxt_base in SHELLS | {"python", "python3", "perl", "sudo"} \
                and re.search(r"(-d|--decode|-D|-r\b|enc)", line):
            add("HIGH", "obfuscated-execution", "decodes text and runs it, a way to hide what the command does")
        if base in SHELLS | {"source", "."} and any(re.match(r"^(<|>)\((curl|wget)\b", w) for w in words[1:]):
            add("MEDIUM", "pipe-to-shell", "runs a script downloaded on the fly")
        if base in SHELLS and any(w.startswith("-c") for w in words) and re.search(r"\$\((curl|wget)\b|`(curl|wget)\b", line):
            add("MEDIUM", "pipe-to-shell", "runs a script downloaded on the fly")
        if base == "xargs" and nxt is None and len(words) > 1:
            for k, w in enumerate(words[1:], 1):
                if os.path.basename(w) == "rm":
                    _rm_findings(words[k:], add)
                    if any(f in ("-r", "-R", "-rf", "-fr", "-Rf", "-fR", "--recursive") for f in words[k + 1:]):
                        add("MEDIUM", "rm-recursive-no-target", "recursive rm whose targets come from elsewhere (xargs or a pipe)")
                    break

        # reading, copying or uploading secrets
        touches_secret = bool(SENSITIVE.search(line))
        if base in NETWORK_UPLOADERS:
            if touches_secret and re.search(r"(-d|--data\S*|-F|--form\S*|-T|--upload-file|--post-file|--body-file)[ =]*(\w+=)?@|scp |rsync |sftp |nc |ncat |socat |\s<\s*\S", line + " "):
                add("HIGH", "exfiltration", "sends a file that holds credentials to another machine")
            if SECRET_DUMP.search(line) and re.search(r"\$\(|`", line) and re.search(r"(-d|--data|-F|--form|-T|--upload-file)", line):
                add("HIGH", "exfiltration", "sends environment variables or shell history to another machine")
        if nxt_base in NETWORK_UPLOADERS and (touches_secret or base in ("env", "printenv")):
            add("HIGH", "exfiltration", "pipes credentials or environment variables into a network tool")
        if base in ("cat", "less", "more", "head", "tail", "cp", "mv", "base64", "tar", "zip", "xxd", "strings", "open", "bat", "grep", "sed", "awk"):
            if re.search(r"(\.ssh/(id_[a-z0-9]+|[^\s]*_key)\b|\.aws/credentials|\.gnupg/|\.netrc|\.git-credentials|/etc/(shadow|sudoers)|\.kube/config|"
                         r"\.docker/config\.json|\.config/gcloud|\.pgpass|\.password-store)", line) and not re.search(r"\.pub\b", line):
                add("HIGH", "reads-credentials", "reads a file that holds private keys or credentials")
            elif re.search(r"(^|[\s/])\.env(\.[A-Za-z0-9_-]+)?(\s|$)", line) and not re.search(r"\.env\.(example|sample|template)", line):
                add("MEDIUM", "reads-env-file", "reads an .env file, which usually holds secrets")
        if base in ("tar", "zip", "7z", "cp", "mv", "rsync", "scp", "ditto", "gzip", "bzip2") and SENSITIVE_DIR.search(line) and not re.search(r"\.pub\b|known_hosts", line):
            add("HIGH", "reads-credentials", "copies or archives a folder that holds private keys or credentials")
        if base == "security" and re.search(r"find-(generic|internet)-password.*-[a-z]*w|dump-keychain|export", line):
            add("HIGH", "reads-credentials", "reads passwords from the macOS keychain")
        if base in ("pass", "gopass", "op", "bw", "lpass") and re.search(r"\b(show|get|item|read|export)\b", line):
            add("MEDIUM", "password-manager-read", "reads secrets from a password manager")

        # persistence and startup files
        if PERSISTENCE_FILES.search(line):
            if re.search(r"authorized_keys", line) and (base in ("tee", "cp", "mv", "install", "ln") or (base == "sed" and any(w.startswith("-i") for w in words))):
                add("HIGH", "ssh-authorized-keys", "adds access to your account through authorized_keys")
            elif base in ("tee", "cp", "mv", "ln", "install") or (base == "sed" and any(w.startswith("-i") for w in words)) or \
                    re.search(r">>?\s*\S*" + PERSISTENCE_FILES.pattern, command):
                add("MEDIUM", "persistence", "changes a shell startup, scheduler or service file that runs code later")
        if re.search(r">>?\s*~?/?\S*(authorized_keys)\b", command):
            add("HIGH", "ssh-authorized-keys", "adds access to your account through authorized_keys")
        if re.search(r">>?\s*\S*(\.bashrc|\.zshrc|\.profile|\.bash_profile|\.zprofile|/etc/profile)\b", command):
            add("MEDIUM", "persistence", "changes a shell startup file that runs code in every new terminal")
        if base == "crontab" and "-r" in words:
            add("MEDIUM", "crontab-remove", "removes all your scheduled jobs")
        if base == "crontab" and "-" in words[1:]:
            add("MEDIUM", "persistence", "installs scheduled jobs")
        if base in ("launchctl", "systemctl") and re.search(r"\b(load|enable|bootstrap|link)\b", line):
            add("MEDIUM", "persistence", "installs a service that starts automatically")

        # containers and remote systems
        if base in ("docker", "podman") and words[1:2] == ["run"]:
            if "--privileged" in words:
                add("HIGH", "container-privileged", "runs a container with full access to the host")
            if re.search(r"(-v|--volume)[ =]\s*(/|~|\$HOME)(:|\s)|docker\.sock", line):
                add("HIGH", "container-broad-mount", "mounts the whole disk, your home folder or the Docker socket into a container")
        for rx, rule, msg in REMOTE_DESTRUCTIVE:
            if re.search(rx, line, re.I):
                add("MEDIUM", rule, msg)
        if base in ("npm", "pnpm", "yarn") and re.search(r"\b(i|install|add)\b", line) and re.search(r"\s-g\b|--global", line):
            add("LOW", "global-install", "installs a package globally")
        if base in ("pip", "pip3") and re.search(r"install", line) and re.search(r"https?://|git\+", line):
            add("LOW", "install-from-url", "installs code straight from a URL")
    return findings


def classify(findings, mode="normal"):
    """-> (decision, findings). decision: allow / ask / deny. Modes: normal, strict (ask becomes deny), permissive (only HIGH asks)."""
    worst = min((SEV[f[0]] for f in findings), default=9)
    if worst == 0:
        return "deny", findings
    if worst == 1:
        return ("deny" if mode == "strict" else "allow" if mode == "permissive" else "ask"), findings
    return "allow", findings


def reasons(findings, limit=4):
    ranked = sorted(set(findings), key=lambda f: (SEV[f[0]], f[1]))
    return "; ".join("%s: %s (%s)" % (r, m, s) for s, r, m in ranked[:limit])


def filter_rules(findings, allow_rules=(), extra_deny=(), command=""):
    kept = [f for f in findings if f[1] not in set(allow_rules)]
    for rx in extra_deny:
        try:
            if re.search(rx, command):
                kept.append(("HIGH", "custom-deny", "matches your deny pattern %r" % rx))
        except re.error:
            pass
    return kept


def redact(command, limit=300):
    out = re.sub(r"(?i)((?:token|password|passwd|secret|api[_-]?key|authorization)[=: ]+['\"]?(?:bearer\s+)?)[^\s'\"]{4,}", r"\1***", command)
    out = re.sub(r"\b(?:ghp_|github_pat_|sk-|xox[baprs]-|AKIA)[A-Za-z0-9_-]{8,}", "***", out)
    out = re.sub(r"(://[^/\s:@]+:)[^/\s@]+(@)", r"\1***\2", out)
    return out if len(out) <= limit else out[:limit] + "..."


def log_decision(path, command, decision, findings, tool="Bash"):
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as fh:
            fh.write(json.dumps({"time": int(time.time()), "tool": tool, "decision": decision,
                                 "rules": sorted({f[1] for f in findings}), "command": redact(command)}) + "\n")
    except OSError:
        pass


def hook(stdin_text, mode="normal", allow_rules=(), extra_deny=(), fail_open=False, log=None):
    """Run as a Claude Code PreToolUse hook. -> (exit_code, stdout, stderr). Never raises."""
    try:
        if len(stdin_text) > MAX_INPUT:
            raise ValueError("hook input is larger than %d bytes" % MAX_INPUT)
        data = json.loads(stdin_text)
        if not isinstance(data, dict):
            raise ValueError("hook input is not a JSON object")
        tool = data.get("tool_name")
        tool_input = data.get("tool_input") if isinstance(data.get("tool_input"), dict) else {}
        command = tool_input.get("command")
        if tool != "Bash" and not (tool is None and isinstance(command, str)):
            return 0, "", ""
        if not isinstance(command, str):
            raise ValueError("a Bash tool call without a command string")
        findings = filter_rules(analyze_command(command), allow_rules, extra_deny, command)
        decision, _ = classify(findings, mode)
        if log:
            log_decision(log, command, decision, findings)
        if decision == "allow":
            return 0, "", ""
        why = reasons(findings)
        if decision == "deny":
            return 2, "", "cmdguard blocked this command: %s. If it is really intended, run it yourself or ask the user to approve." % why
        out = {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "ask",
                                      "permissionDecisionReason": "cmdguard: %s" % why}}
        return 0, json.dumps(out), ""
    except Exception as exc:  # a crashing hook would otherwise let the command through (only exit code 2 blocks)
        if fail_open:
            return 0, "", "cmdguard: could not inspect the command (%s); allowed because of --fail-open" % exc
        return 2, "", "cmdguard could not inspect this command (%s), so it was blocked. Use --fail-open to allow on errors." % exc


SNIPPET = {"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "cmdguard"}]}]}}


def main(argv=None, stdin=None):
    ap = argparse.ArgumentParser(description="Allow, ask or deny shell commands proposed by an AI agent.")
    ap.add_argument("--version", action="version", version=__version__)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--mode", choices=("normal", "strict", "permissive"), default="normal",
                        help="normal: HIGH denies, MEDIUM asks; strict: MEDIUM denies; permissive: only HIGH is stopped")
    common.add_argument("--allow-rule", action="append", default=[], metavar="RULE", help="never act on this rule (repeatable)")
    common.add_argument("--deny-regex", action="append", default=[], metavar="REGEX", help="also deny commands matching this regex (repeatable)")
    common.add_argument("--log", metavar="FILE", help="append every decision (secrets redacted) to this file")
    sub = ap.add_subparsers(dest="cmd")
    h = sub.add_parser("hook", parents=[common], help="act as a PreToolUse hook (the default when input is piped in)")
    h.add_argument("--fail-open", action="store_true", help="allow the command if cmdguard itself fails (default: block)")
    c = sub.add_parser("check", parents=[common], help="check one command given as an argument")
    c.add_argument("command")
    c.add_argument("--json", action="store_true")
    sub.add_parser("install", help="print the settings.json snippet that registers the hook")
    sub.add_parser("rules", help="list the rule names")
    args = ap.parse_args(argv)
    stdin = stdin or sys.stdin
    if args.cmd is None:
        args = ap.parse_args(["hook"] + list(argv or []))
    if args.cmd == "install":
        print(json.dumps(SNIPPET, indent=2))
        print("\nAdd this to your Claude Code settings.json (cmdguard must be on your PATH, or use its absolute path).\n"
              "cmdguard never edits your settings itself.", file=sys.stderr)
        return 0
    if args.cmd == "rules":
        for rule in sorted(ALL_RULES):
            print(rule)
        return 0
    if args.cmd == "check":
        findings = filter_rules(analyze_command(args.command), args.allow_rule, args.deny_regex, args.command)
        decision, _ = classify(findings, args.mode)
        if args.log:
            log_decision(args.log, args.command, decision, findings)
        if args.json:
            print(json.dumps({"decision": decision, "findings": [{"severity": s, "rule": r, "message": m} for s, r, m in sorted(set(findings), key=lambda f: (SEV[f[0]], f[1]))]}, indent=2))
        else:
            print(decision.upper())
            for s, r, m in sorted(set(findings), key=lambda f: (SEV[f[0]], f[1])):
                print("  %-6s %-24s %s" % (s, r, m))
        return 0 if decision == "allow" else 1
    code, out, err = hook(stdin.read(MAX_INPUT + 1), args.mode, args.allow_rule, args.deny_regex, args.fail_open, args.log)
    if out:
        print(out)
    if err:
        print(err, file=sys.stderr)
    return code


ALL_RULES = {"rm-recursive-broad", "rm-no-preserve-root", "rm-unset-variable", "rm-recursive-system-path", "rm-recursive-no-target", "rm-credentials", "find-delete",
             "disk-overwrite", "disk-format", "power-off", "chmod-recursive-broad", "chmod-world-writable", "setuid", "kill-everything", "kill-broad",
             "git-force-push", "git-push-destructive", "git-reset-hard", "git-clean", "git-discard-changes", "git-rewrite-history", "eval-dynamic",
             "inline-interpreter-shell", "pipe-to-shell", "obfuscated-execution", "exfiltration", "reads-credentials", "reads-env-file",
             "password-manager-read", "ssh-authorized-keys", "persistence", "crontab-remove", "container-privileged", "container-broad-mount",
             "global-install", "install-from-url", "sudo", "fork-bomb", "library-injection", "too-deeply-nested", "custom-deny"} | \
    {rule for _, rule, _ in REMOTE_DESTRUCTIVE}


def run():
    try:
        return main()
    except SystemExit:
        raise
    except Exception as exc:
        print("cmdguard: internal error (%s); blocking to be safe" % exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(run())
