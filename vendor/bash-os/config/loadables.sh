# Shared NAME[|SHORT-DOC] list parser. Blank lines and whole-line comments are
# ignored; duplicate names and malformed entries are errors. The help text is
# everything after the first '|'. See config/loadables.py for the grammar.
BASH_OS_LOADABLES_PARSER="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/loadables.py"
loadables_parse() { python3 "$BASH_OS_LOADABLES_PARSER" parse "$1"; }
loadables_names() {
    local parsed
    parsed=$(loadables_parse "$1") || return
    [[ -z $parsed ]] || printf '%s\n' "$parsed" | cut -f1
}
