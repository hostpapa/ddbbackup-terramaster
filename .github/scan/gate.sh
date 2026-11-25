#!/bin/bash
# The pre-publish gate (DDB-447). Everything bound for a public repository or
# release goes through here first, and any hit stops the publish. It runs on
# the build server before anything is pushed, and again in the store
# repository's workflows (on every change, and on each draft release before it
# is published).
#
#   gate.sh [--tree DIR --files LIST] [--deb FILE] --gitleaks BIN
#           [--denylist FILE] [--show]
#
#   --tree, --files  the repository files; LIST (files.txt) names every file
#                    allowed in the repository, and DIR must hold exactly those
#   --deb            a package to release: unpacked (data and DEBIAN) and
#                    given the same scans
#   --gitleaks       the gitleaks binary (get-gitleaks.sh fetches the pinned one)
#   --denylist       extra words to stop on, kept out of the public repository
#                    (internal host names and the like)
#   --show           print what matched, with the real paths. Without it the
#                    output may end up in a public log (the store repository's
#                    workflows), so it is passed through custom_rules.py
#                    --redact: anything a rule matches, a path component or a
#                    name in a message, becomes [rule]
#
# Checks, each fatal:
#   1. The tree holds exactly the listed files: none extra or missing, no
#      links or special files, none over 1 MiB.
#   2. The package has no links, special files or git metadata.
#   3. Every ELF binary is stripped: no .symtab, no debug sections (DWARF,
#      MiniDebugInfo or stabs).
#   4. No spaces, colons or control characters in file names, and no
#      archives or compressed files (the scans below would see only packed
#      bytes).
#   5. gitleaks (its default rules) on a view of everything: text files as
#      they are, every other file as its strings, each under a neutral name
#      (f000001.txt) so none of gitleaks' default path exclusions applies,
#      and with inline gitleaks:allow markers ignored.
#   6. custom_rules.py on the same view and on the file names: key files by
#      name, private IPs, build paths, internal host names, email addresses,
#      private repository links, private key blocks, and the denylist.
set -euo pipefail
umask 077

HERE=$(cd "$(dirname "$0")" && pwd)
TREE='' FILES='' DEB='' GITLEAKS='' DENYLIST='' SHOW=''
ARGS=("$@")
usage() { sed -n '8,9p' "$0" >&2; exit 2; }
while [ $# -gt 0 ]; do
  case "$1" in
    --tree) TREE=${2:?}; shift 2 ;;
    --files) FILES=${2:?}; shift 2 ;;
    --deb) DEB=${2:?}; shift 2 ;;
    --gitleaks) GITLEAKS=${2:?}; shift 2 ;;
    --denylist) DENYLIST=${2:?}; shift 2 ;;
    --show) SHOW=--show; shift ;;
    *) echo "gate: unknown argument $1" >&2; usage ;;
  esac
done
[ -n "$TREE$DEB" ] || usage
[ -z "$TREE" ] || [ -n "$FILES" ] || { echo "gate: --tree needs --files" >&2; exit 2; }
[ -n "$GITLEAKS" ] && [ -x "$GITLEAKS" ] || { echo "gate: --gitleaks <binary> is required" >&2; exit 2; }
for c in dpkg-deb readelf strings file python3 find sort comm sed; do
  command -v "$c" >/dev/null || { echo "gate: $c not found" >&2; exit 2; }
done

# Without --show, run again with the output redacted (see --show above). The
# exit status is the gate's (pipefail).
if [ -z "$SHOW" ] && [ "${DDB_GATE_REDACTED:-}" != 1 ]; then
  DDB_GATE_REDACTED=1 bash "$0" "${ARGS[@]}" 2>&1 |
    python3 -I "$HERE/custom_rules.py" --redact ${DENYLIST:+--denylist "$DENYLIST"}
  exit
fi

WORK=$(mktemp -d "${TMPDIR:-/tmp}/gate.XXXXXX")
trap 'rm -rf "$WORK"' EXIT
PROBLEMS=0
problem() { echo "FAIL: $*"; PROBLEMS=$((PROBLEMS + 1)); }
# A path to print: spaces, colons and control characters become "?". The
# redaction (see --show) works a path at a time, and a path in the output
# ends at a space or a colon, so a key file's name could otherwise be masked
# only in part.
shown() { printf '%s' "${1//[[:space:][:cntrl:]:]/?}"; }
title() { echo; echo "== $*"; }

# Files under $1 other than directories, relative, without .git, each ended
# by a NUL: a name may hold a newline, and each must reach shown() whole.
list_files() { (cd "$1" && find . -path ./.git -prune -o ! -type d -print0 | sed -z 's|^\./||' | LC_ALL=C sort -z); }
# list_into <file> <what> <command...>: the command's output in <file>. A
# command that fails is a problem: the files it didn't list would go
# unchecked. (A loop reading "< <(command)" never sees its exit status.)
list_into() {
  local out=$1 what=$2
  shift 2
  "$@" > "$out" || problem "could not list $what (exit $?)"
}
# each_file <message> <command...>: problem "<message>: <name>" for each
# NUL-ended name the command prints, with a leading ./ or $WORK/deb/ removed.
each_file() {
  local msg=$1 f
  shift
  list_into "$WORK/names" "the files for \"$msg\"" "$@"
  while IFS= read -r -d '' f; do
    f=${f#./}
    problem "$msg: $(shown "${f#"$WORK/deb/"}")"
  done < "$WORK/names"
}
# The tree's files, without its .git, that match the find tests in "$@".
tree_find() { (cd "$TREE" && find . -path ./.git -prune -o "$@" -print0); }

# The scan view: each file of $1 as $VIEW/f<n>.txt, text as it is and
# anything else as its strings, and a line in $INDEX mapping it back to
# "$2/<path>". The neutral names keep gitleaks' default path exclusions (any
# path containing gitleaks.toml, pictures, node_modules/, ...) from skipping a
# file, and no two files can share one. With $3 = checkout, a root .git (the
# checkout's own) is left out; a package's files are all scanned.
VIEW="$WORK/view"
INDEX="$WORK/index.tsv"
NVIEW=0
mkdir -p "$VIEW"
: > "$INDEX"
# Archive and compressed file types, as file(1) names them.
PACKED='^(application/(gzip|zlib|zstd|zip|x-(gzip|bzip2|xz|lzma|lzip|lz4|compress|zstd|tar|cpio|archive|7z-compressed|rar|rpm|iso9660-image|squashfs)|vnd\.rar|java-archive|vnd\.debian\.binary-package|vnd\.ms-cab-compressed|pdf|epub\+zip|vnd\.openxmlformats-.*|vnd\.oasis\.opendocument\..*)|font/woff2?)$'
# Files under $1 for the view, each ended by a NUL; with $2 = checkout,
# without its root .git.
view_files() {
  (cd "$1" && if [ "$2" = checkout ]; then find . -path ./.git -prune -o -type f -print0; else find . -type f -print0; fi)
}
make_view() {
  local src=$1 area=$2 what=$3 p kind out mime
  list_into "$WORK/view-files" "the files of $area" view_files "$src" "$what"
  while IFS= read -r -d '' p; do
    p=${p#./}
    case "$p" in
      *[[:space:][:cntrl:]:]*) problem "space, colon or control character in a file name: $area/$(shown "$p")"; continue ;;
    esac
    NVIEW=$((NVIEW + 1))
    out=$(printf 'f%06d.txt' "$NVIEW")
    # Empty files count as text (file(1) calls them binary).
    if [ ! -s "$src/$p" ]; then
      kind=text; : > "$VIEW/$out"
    else
      mime=$(file -b --mime "$src/$p")      # "<type>; charset=<encoding>"
      [[ ! ${mime%%;*} =~ $PACKED ]] || problem "archive or compressed file, not scannable: $area/$p"
      case "${mime##*charset=}" in
        us-ascii|utf-8) kind=text; cp "$src/$p" "$VIEW/$out" ;;
        # Strings of 4 or more (8-bit, then UTF-16LE): custom_rules.py
        # refuses shorter denylist entries.
        *) kind='strings'; { strings -a -n 4 "$src/$p"; strings -a -n 4 -e l "$src/$p"; } > "$VIEW/$out" ;;
      esac
    fi
    printf '%s\t%s\t%s\n' "$out" "$kind" "$area/$p" >> "$INDEX"
  done < "$WORK/view-files"
}

if [ -n "$TREE" ]; then
  title "Repository files: $TREE"
  grep -v -E '^[[:space:]]*(#|$)' "$FILES" | awk '{print $1}' | tr '\n' '\0' | LC_ALL=C sort -z > "$WORK/want"
  list_files "$TREE" > "$WORK/have"
  each_file "not in $(basename "$FILES")" env LC_ALL=C comm -z -13 "$WORK/want" "$WORK/have"
  each_file "missing" env LC_ALL=C comm -z -23 "$WORK/want" "$WORK/have"
  each_file "link or special file" tree_find ! -type d ! -type f
  each_file "over 1 MiB" tree_find -type f -size +1024k
  echo "$(tr -cd '\0' < "$WORK/have" | wc -c) files"
  make_view "$TREE" repo checkout
fi

if [ -n "$DEB" ]; then
  title "Package: $DEB"
  mkdir -p "$WORK/deb/DEBIAN"
  dpkg-deb -x "$DEB" "$WORK/deb"
  dpkg-deb -e "$DEB" "$WORK/deb/DEBIAN"
  each_file "link or special file in the package" find "$WORK/deb" ! -type d ! -type f -print0
  each_file "git metadata in the package" find "$WORK/deb" -name .git -print0
  n=0
  list_into "$WORK/deb-files" "the package's files" find "$WORK/deb" -type f -print0
  while IFS= read -r -d '' f; do
    [ "$(head -c 4 "$f" | od -An -tx1 | tr -d ' \n')" = 7f454c46 ] || continue
    n=$((n + 1))
    # readelf on its own: a binary it can't read must not pass as stripped.
    if ! sections=$(readelf -S -W "$f" 2>&1); then
      problem "could not read the sections of $(shown "${f#$WORK/deb/}")"
      continue
    fi
    # .gnu_debugdata is MiniDebugInfo (an xz-packed symbol table), .stab and
    # .stabstr old-style debug info. .gnu_debuglink only names a debug file.
    secs=$(grep -o -E '\.(symtab|gnu_debugdata|stab(str)?|z?debug_[a-z_.]+)' <<< "$sections" | LC_ALL=C sort -u | tr '\n' ' ' || true)
    [ -z "$secs" ] || problem "not stripped: $(shown "${f#$WORK/deb/}") ($secs)"
  done < "$WORK/deb-files"
  echo "$(find "$WORK/deb" -type f -printf . | wc -c) files, $n ELF"
  make_view "$WORK/deb" deb package
fi

title "gitleaks"
# Run inside the view, so the only paths its exclusions see are the neutral
# names, and with inline gitleaks:allow markers ignored, so a file can't
# exempt its own secrets. Its findings are printed with the real paths,
# redacted.
if ! (cd "$VIEW" && "$GITLEAKS" dir --config "$HERE/gitleaks-config.toml" --no-banner --redact \
        --ignore-gitleaks-allow --exit-code 1 --report-format json --report-path "$WORK/gitleaks.json" .); then
  if [ -s "$WORK/gitleaks.json" ]; then
    python3 -I - "$INDEX" "$WORK/gitleaks.json" <<'PY' || true
import json, os, sys
index = {}
for row in open(sys.argv[1], encoding="utf-8"):
    name, kind, real = row.rstrip("\n").split("\t", 2)
    index[name] = real + (" (strings)" if kind == "strings" else "")
for f in json.load(open(sys.argv[2])):
    name = os.path.basename(f["File"])
    print(f'{index.get(name, name)}:{f["StartLine"]}: gitleaks {f["RuleID"]}')
PY
  fi
  problem "gitleaks found something (above)"
fi

title "Custom rules"
if ! python3 -I "$HERE/custom_rules.py" $SHOW ${DENYLIST:+--denylist "$DENYLIST"} --index "$INDEX" "$VIEW"; then
  problem "custom rules hit (above)"
fi

echo
if [ "$PROBLEMS" -gt 0 ]; then
  echo "GATE FAILED: $PROBLEMS problem(s). Nothing may be published."
  exit 1
fi
echo "GATE PASSED"
