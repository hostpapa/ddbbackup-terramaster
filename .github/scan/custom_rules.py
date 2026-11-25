#!/usr/bin/env python3
"""Our own rules for files going public, for what gitleaks doesn't know is
sensitive to us (DDB-447).

    custom_rules.py [--show] [--denylist FILE] --index INDEX VIEW
    custom_rules.py --redact [--denylist FILE]
    custom_rules.py --digest FILE

The first form is run by gate.sh on its scan view: VIEW holds every file
under a neutral name (f000001.txt), text as it is and anything else as its
strings, and INDEX maps each one to its real path ("<view name> TAB
text|strings TAB <real path>"). File names are checked as well as content,
and strings with looser rules (see compile_rules). Prints "path:line:
rule" for each hit and exits 1 if there is any. Without --show the matched
text isn't printed: CI logs on a public repository are public, and printing
an internal address there would leak it.

The second form copies its input to its output with anything a rule matches
(the looser rules) replaced by [rule], and each path component that names a
key file by [key-file]. gate.sh passes its output through it when run
without --show, so a path component or a name in a message that matches a
rule doesn't reach a public log either.

The third form prints the SHA-256 of a denylist's words (comments, blank
lines, case and order ignored), so the store repository's release workflow
can check its copy of the list matches the build server's.

The rules are generic patterns, because this file is published with the
store repository's scan. Specific internal names (host names, IPs, the build
server's paths) go in the denylist, which is never published and reaches the
store repository's workflows only as a secret. Its entries must be at least
MIN_WORD characters long: the gate reads binaries as their strings of that
length or more, so a shorter entry could pass unseen.
"""
import hashlib
import io
import os
import re
import sys

# Matches that are fine to publish. Each is a full match of the hit.
PUBLIC_HOSTS = [
    r"(?:www|connect|mydata)\.datadepositbox\.com",
    r"service\.acpana\.com",
]
PUBLIC_EMAILS = [
    r"support@datadepositbox\.com",
]
PUBLIC_LINKS = [
    r"github\.com[/:]hostpapa/ddbbackup-[a-z0-9-]+(?:\.git)?",
]

PRIVATE_IP = (r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
              r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
              r"|192\.168\.\d{1,3}\.\d{1,3}")

# (rule, pattern, allowed matches)
CONTENT_RULES = [
    ("private-ip", r"\b(?:" + PRIVATE_IP + r")\b", []),
    # Home folders (Linux, macOS, Windows), macOS volumes, and temporary
    # folders. macOS writes /Users and /Volumes capitalised, so those match
    # case-sensitively and an API path such as /users/<name> doesn't. The
    # [x] classes keep this line from matching itself: the file is published
    # and scanned like the rest.
    ("build-path",
     r"/hom[e]/[A-Za-z0-9._-]+|/roo[t]/|(?-i:/User[s]/[A-Za-z0-9._-]+|/Volume[s]/[A-Za-z0-9._ -]+)"
     r"|/tmp/claud[e]-|\b[A-Za-z]:[\\/]User[s][\\/]", []),
    # Any name under our domains that isn't a public service: staging,
    # internal and build hosts. A match starts only where a name can: not
    # inside a label, and not after a dot that ends one, but after leading
    # dots (".staging...", "load...staging..."). With \b instead, a long
    # dotted line (an SVG path, say) took time growing with its square; this
    # way each run of labels is tried once. "email" starts the same way.
    ("internal-host",
     r"(?<![a-z0-9_-])(?<![a-z0-9_-]\.)(?:[a-z0-9_-]+\.)+(?:datadepositbox|acpana|hostpapa)\.[a-z]{2,}(?:\.[a-z]{2})?\b",
     PUBLIC_HOSTS),
    # Any email address, not only ours: a personal address in a comment is
    # as unwanted as a staff one.
    ("email",
     r"(?<![a-z0-9._%+-])[a-z0-9._%+-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,}\b", PUBLIC_EMAILS),
    # Links to private repositories and to our Jira. A repository name may
    # start with a dot (.github-private); its other dots sit between other
    # characters, so a sentence's full stop after a link isn't part of it.
    ("internal-link",
     r"\bhostpapa\.atlassian\.net\b|github\.com[/:]hostpapa/\.?[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*", PUBLIC_LINKS),
    # gitleaks has a rule for these too; a key is the worst thing to miss.
    ("private-key",
     r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----", []),
]

# Key, certificate and credential files, by name.
KEY_FILE = re.compile(
    r"\.(?:pem|key|p12|pfx|jks|keystore|ppk|der|crt|cer|csr|kdbx|gpg|asc)$"
    r"|(?:^|/)id_(?:rsa|dsa|ecdsa|ed25519)(?:\.pub)?$"
    r"|(?:^|/)(?:secret\.h|\.env|\.netrc|\.npmrc|\.pypirc|credentials(?:\.json)?)$",
    re.I)
# A path in a line of output: the gate prints "path:line: rule" and the like.
PATH_IN_TEXT = re.compile(r"[^\s:]+")
# The shortest denylist entry; gate.sh reads binaries with strings -n 4.
MIN_WORD = 4


def denylist_words(path):
    words = set()
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                words.add(line.lower())
    return sorted(words)


def compile_rules(denylist, loose=False):
    """The rules for text, or with loose=True for a binary's strings (and
    for redacting the gate's output, which must hide anything either finds).

    A short literal in a binary is often compiled into an instruction as a
    number, so no copy of it sits among the binary's data, and strings shows
    it run together with the next instruction's first byte: "10.0.0.5H". In
    strings, then, only digits end an IP address, and a denylist word may
    have anything on either side."""
    rules = []
    for name, pat, allowed in CONTENT_RULES:
        if loose and name == "private-ip":
            pat = r"(?<!\d)(?:" + PRIVATE_IP + r")(?!\d)"
        rules.append((name, re.compile(pat, re.I), [re.compile(a, re.I) for a in allowed]))
    words = denylist_words(denylist) if denylist else []
    if any(len(w) < MIN_WORD for w in words):
        # Not the entry itself: this may print in a public log.
        sys.exit(f"custom_rules.py: a denylist entry is shorter than {MIN_WORD} characters")
    if words:
        # In text, whole words, where a word is letters and digits: "nas1"
        # doesn't hit "nas10", but hits in api.nas1.net, nas1-02.lan and
        # /srv/nas1_build.
        alts = "(?:" + "|".join(map(re.escape, words)) + ")"
        rules.append(("denylist",
                      re.compile(alts if loose else r"(?<![A-Za-z0-9])" + alts + r"(?![A-Za-z0-9])", re.I),
                      []))
    return rules


def is_allowed(text, allowed):
    return any(a.fullmatch(text) for a in allowed)


def hits_in(text, rules):
    for rule, rx, allowed in rules:
        for m in rx.finditer(text):
            if not is_allowed(m.group(0), allowed):
                yield rule, m.group(0)


def mask_key_files(line):
    """Replace each path component in line that KEY_FILE matches."""
    def path(m):
        return "/".join("[key-file]" if KEY_FILE.search(part) else part
                        for part in m.group(0).split("/"))
    return PATH_IN_TEXT.sub(path, line)


def redact(rules):
    """Copy stdin to stdout, each rule's hits replaced by [rule] and key file
    names by [key-file]."""
    stdin = io.TextIOWrapper(sys.stdin.buffer, encoding="utf-8", errors="replace")
    for line in stdin:
        for rule, rx, allowed in rules:
            line = rx.sub(lambda m, rule=rule, allowed=allowed:
                          m.group(0) if is_allowed(m.group(0), allowed) else f"[{rule}]", line)
        print(mask_key_files(line), end="", flush=True)


def scan(view, index, denylist, show):
    text_rules = compile_rules(denylist)
    strings_rules = compile_rules(denylist, loose=True)
    hits = 0

    def report(where, rule, text):
        nonlocal hits
        print(f"{where}: {rule}" + (f": {text}" if show else ""))
        hits += 1

    with open(index, encoding="utf-8") as f:
        rows = [line.rstrip("\n").split("\t", 2) for line in f if line.strip()]
    for name, kind, real in rows:
        where = f"{real} (strings)" if kind == "strings" else real
        if KEY_FILE.search(real):
            report(where, "key-file", "")
        for rule, text in hits_in(real, text_rules):   # the name is published too
            report(f"{where} (name)", rule, text)
        rules = strings_rules if kind == "strings" else text_rules
        with open(os.path.join(view, name), encoding="utf-8", errors="replace") as f:
            for lineno, line in enumerate(f, 1):
                for rule, text in hits_in(line, rules):
                    report(f"{where}:{lineno}", rule, text)
    return hits


def main(argv):
    show = redacting = False
    denylist = index = digest = None
    dirs = []
    args = iter(argv)
    for a in args:
        if a == "--show":
            show = True
        elif a == "--redact":
            redacting = True
        elif a in ("--denylist", "--index", "--digest"):
            value = next(args, None)
            if value is None:
                print(f"custom_rules.py: {a} needs a file", file=sys.stderr)
                return 2
            if a == "--denylist":
                denylist = value
            elif a == "--index":
                index = value
            else:
                digest = value
        elif a.startswith("-"):
            print(f"custom_rules.py: unknown option {a}", file=sys.stderr)
            return 2
        else:
            dirs.append(a)
    if digest:
        print(hashlib.sha256("\n".join(denylist_words(digest)).encode()).hexdigest())
        return 0
    if redacting:
        redact(compile_rules(denylist, loose=True))
        return 0
    if len(dirs) != 1 or not index:
        print(__doc__, file=sys.stderr)
        return 2
    hits = scan(dirs[0], index, denylist, show)
    print(f"custom rules: {hits} hit(s)")
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
