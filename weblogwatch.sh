#!/usr/bin/env bash
#
# weblogwatch.sh — quick access-log traffic analysis (DDoS / request volume)
# across servers with different hosting panels, rendered with goaccess.
#
# Usage:
#   weblogwatch.sh [-p PANEL[,PANEL...]] [-i SINCE] [-t TO] [-f FORMAT]
#                  [-o REPORT.html] [-r] [-- EXTRA_GOACCESS_ARGS]
#
# Time specs (GNU date):
#   30m | 2h | 1d | 1w          -> N minutes/hours/days/weeks ago
#   "1 hour ago" | "today" | "yesterday 20:00" | "2026-10-10 20:00"
#
# Examples:
#   weblogwatch.sh                        # auto-detect panel, last hour
#   weblogwatch.sh -p hestia -i 30m       # hestia logs, last 30 minutes
#   weblogwatch.sh -p da,nginx -i 15m     # merge directadmin + nginx logs
#   weblogwatch.sh -p aapanel -i 2h -o /root/report.html
#   weblogwatch.sh -p isp -i 1d -- -a --no-query-string
#
# Panel aliases: hestia | isp (ispmanager) | da (directadmin) | aapanel |
#                nginx | apache | auto (default)

set -euo pipefail
export LC_ALL=C    # match English month names used in log timestamps

PANEL="auto"
SINCE="1h"
TO="now"
FORMAT="${GOACCESS_LOG_FORMAT:-COMBINED}"
OUTPUT=""
ROTATED=0
EXTRA=()

die() { echo "ERROR: $*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

usage() { sed -n '2,30p' "$0" | sed -e 's/^#\{1,\} \{0,1\}//'; }

# --- args -------------------------------------------------------------------
while (($#)); do
    case $1 in
        -p|--panel)    PANEL=$2; shift 2 ;;
        -i|--since|--interval) SINCE=$2; shift 2 ;;
        -t|--to)       TO=$2; shift 2 ;;
        -f|--format)   FORMAT=$2; shift 2 ;;
        -o|--output)   OUTPUT=$2; shift 2 ;;
        -r|--rotated)  ROTATED=1; shift ;;
        -h|--help)     usage; exit 0 ;;
        --)            shift; EXTRA+=("$@"); break ;;
        *)             die "unknown option: $1 (see --help)" ;;
    esac
done

# --- deps -------------------------------------------------------------------
if ((${BASH_VERSINFO[0]} < 4 || (${BASH_VERSINFO[0]} == 4 && ${BASH_VERSINFO[1]} < 4))); then
    die "bash >= 4.4 is required (mapfile -d)"
fi
have goaccess || die "goaccess not found in PATH"

# --- time helpers -----------------------------------------------------------
# Normalize shorthand intervals ("30m", "2h", "1d", "1w"); pass the rest through.
normalize_spec() {
    local spec=$1
    if [[ $spec =~ ^[0-9]+[smhdw]$ ]]; then
        local n=${spec%?} u=${spec: -1}
        case $u in
            s) echo "$n seconds ago";;
            m) echo "$n minutes ago";;
            h) echo "$n hours ago";;
            d) echo "$n days ago";;
            w) echo "$n weeks ago";;
        esac
    else
        echo "$spec"
    fi
}
log_ts() { date -d "$(normalize_spec "$1")" '+[%d/%b/%Y:%H:%M:%S'; }   # bracketed, matches $4 in logs
hum_ts() { date -d "$(normalize_spec "$1")" '+%F %T'; }

# --- panel -> log directories ----------------------------------------------
# Access logs only; *error* / *bytes* files are excluded during find.
roots_for() {
    case $1 in
        hestia)              printf '%s\n' /home/*/web/*/logs ;;
        isp|ispmanager)      printf '%s\n' /var/www/httpd-logs /var/log/nginx ;;
        da|directadmin)      printf '%s\n' /var/log/httpd/domains /var/log/nginx/domains ;;
        aapanel|aa|aa-panel) printf '%s\n' /www/wwwlogs ;;
        nginx)               printf '%s\n' /var/log/nginx ;;
        apache|httpd)        printf '%s\n' /var/log/apache2 /var/log/httpd ;;
        *) die "unknown panel: $1 (choose: hestia, isp, da, aapanel, nginx, apache, auto)";;
    esac
}

detect_panel() {
    local p roots r
    for p in hestia isp da aapanel; do
        roots=$(roots_for "$p")
        for r in $roots; do
            [[ -d $r ]] && { printf '%s\n' "$p"; return 0; }
        done
    done
    return 1
}

# --- resolve panels and existing directories --------------------------------
if [[ $PANEL == auto ]]; then
    PANEL=$(detect_panel) || die "could not auto-detect the panel; pass -p explicitly"
fi

ROOTS=()
for p in ${PANEL//,/ }; do
    case $p in
        hestia|isp|ispmanager|da|directadmin|aapanel|aa|aa-panel|nginx|apache|httpd) ;;
        *) die "unknown panel: $p (see --help)" ;;
    esac
    while read -r d; do
        [[ -d $d ]] && ROOTS+=("$d")
    done < <(roots_for "$p")
done
((${#ROOTS[@]})) || die "no log directories found for panel(s): $PANEL"

# --- collect log files -------------------------------------------------------
EXPR=( -name '*.log' )
if ((ROTATED)); then
    EXPR+=( -o -name '*.log.[0-9]*' -o -name '*.log.[0-9]*.gz' )
fi

mapfile -d '' -t FILES < <(
    find -L "${ROOTS[@]}" -maxdepth 1 -type f \( "${EXPR[@]}" \) \
        ! -name '*error*' ! -name '*bytes*' -print0 2>/dev/null
)

# Deduplicate: panels often symlink the same file under several paths.
declare -A SEEN=()
LOGS=()
for f in "${FILES[@]}"; do
    r=$(readlink -f -- "$f")
    [[ -n ${SEEN[$r]+x} ]] && continue
    SEEN[$r]=1
    LOGS+=("$f")
done
((${#LOGS[@]})) || die "no access logs matched in: ${ROOTS[*]}"

# --- time window --------------------------------------------------------------
FROM_LOG=$(log_ts "$SINCE"); TO_LOG=$(log_ts "$TO")
FROM_H=$(hum_ts "$SINCE");   TO_H=$(hum_ts "$TO")
FROM_E=$(date -d "$(normalize_spec "$SINCE")" +%s)
TO_E=$(date -d "$(normalize_spec "$TO")" +%s)
((FROM_E <= TO_E)) || die "empty time window: $FROM_H .. $TO_H"

# --- read helpers -------------------------------------------------------------
# Concatenate logs; rotated .gz files are decompressed on the fly.
cat_all() {
    local f
    for f in "$@"; do
        case $f in
            *.gz) gzip -cd -- "$f" 2>/dev/null || true ;;
            *)    cat -- "$f" 2>/dev/null || true ;;
        esac
    done
}

# --- report -------------------------------------------------------------------
cat >&2 <<EOF
panel:      $PANEL
files:      ${#LOGS[@]}
window:     $FROM_H .. $TO_H   (-i $SINCE -t $TO)
log format: $FORMAT
output:     ${OUTPUT:-terminal}
EOF

GOA_ARGS=(--log-format="$FORMAT" "${EXTRA[@]}")
[[ -n $OUTPUT ]] && GOA_ARGS+=(-o "$OUTPUT")

# $4 is [dd/Mon/yyyy:HH:MM:SS — lexicographic comparison works because the
# fields are zero-padded; the timezone in $5 never enters the comparison.
cat_all "${LOGS[@]}" |
awk -v from="$FROM_LOG" -v to="$TO_LOG" '
    $4 >= from && $4 <= to { n++; print }
    END { printf "lines in window: %d\n", n+0 > "/dev/stderr" }
' |
goaccess "${GOA_ARGS[@]}" -
