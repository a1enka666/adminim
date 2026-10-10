#!/usr/bin/env bash
#
# weblogwatch.sh — quick access-log traffic analysis (DDoS / request volume)
# across servers with different hosting panels, rendered with goaccess.
#
# Every log line is tagged with its virtual host (derived from the log file
# name, since all supported panels keep one file per domain), so goaccess
# shows the "Virtual Hosts" panel and the script prints a per-domain top list.
#
# Usage:
#   weblogwatch.sh [-p PANEL[,PANEL...]] [-i SINCE] [-t TO] [-f FORMAT]
#                  [-o REPORT.html] [-r] [-V] [--top N] [-- EXTRA_GOACCESS_ARGS]
#
# Time specs (GNU date):
#   30m | 2h | 1d | 1w          -> N minutes/hours/days/weeks ago
#   "1 hour ago" | "today" | "yesterday 20:00" | "2026-10-10 20:00"
#
# Options:
#   -V, --no-vhost   disable per-domain tagging (e.g. one shared access.log)
#   -r, --rotated    include rotated logs (*.log.N, *.log.N.gz)
#   --top N          domains in the stderr top list (default 15)
#
# Examples:
#   weblogwatch.sh                        # auto-detect panel, last hour
#   weblogwatch.sh -p hestia -i 30m       # hestia logs, last 30 minutes
#   weblogwatch.sh -p da,nginx -i 15m     # merge directadmin + nginx logs
#   weblogwatch.sh -p aapanel -i 2h -o /root/report.html
#   weblogwatch.sh -p nginx -i 1d -V      # shared access.log, no vhosts
#
# Panel aliases: hestia | isp (ispmanager) | da (directadmin) | aapanel |
#                nginx | apache | auto (default)

set -euo pipefail
export LC_ALL=C    # match English month names used in log timestamps

PANEL="auto"
SINCE="1h"
TO="now"
FORMAT="${GOACCESS_LOG_FORMAT:-}"   # empty = built-in per-mode default
OUTPUT=""
ROTATED=0
VHOST=1
TOPN=15
EXTRA=()

die() { echo "ERROR: $*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

usage() { sed -n '2,37p' "$0" | sed -e 's/^#\{1,\} \{0,1\}//'; }

# --- args -------------------------------------------------------------------
while (($#)); do
    case $1 in
        -p|--panel)    PANEL=$2; shift 2 ;;
        -i|--since|--interval) SINCE=$2; shift 2 ;;
        -t|--to)       TO=$2; shift 2 ;;
        -f|--format)   FORMAT=$2; shift 2 ;;
        -o|--output)   OUTPUT=$2; shift 2 ;;
        -r|--rotated)  ROTATED=1; shift ;;
        -V|--no-vhost) VHOST=0; shift ;;
        --top)         TOPN=$2; shift 2 ;;
        -h|--help)     usage; exit 0 ;;
        --)            shift; EXTRA+=("$@"); break ;;
        *)             die "unknown option: $1 (see --help)" ;;
    esac
done

[[ $TOPN =~ ^[0-9]+$ ]] || die "--top must be a number"
if [[ -n $FORMAT && $FORMAT != *%v* && $VHOST -eq 1 ]]; then
    echo "note: custom format without %v — vhost tagging disabled" >&2
    VHOST=0
fi

# --- deps -------------------------------------------------------------------
if ((${BASH_VERSINFO[0]} < 4 || (${BASH_VERSINFO[0]} == 4 && ${BASH_VERSINFO[1]} < 4))); then
    die "bash >= 4.4 is required (mapfile -d)"
fi

# --- goaccess bootstrap -----------------------------------------------------
SUDO=""
if [[ $EUID -ne 0 ]] && command -v sudo >/dev/null 2>&1; then
    SUDO="sudo"
fi

if ! command -v goaccess >/dev/null 2>&1; then
    # goaccess lives in EPEL on RHEL-likes; enable it if absent.
    if command -v dnf >/dev/null 2>&1; then
        $SUDO dnf install -y epel-release || true
        $SUDO dnf install -y goaccess
    elif command -v yum >/dev/null 2>&1; then
        $SUDO yum install -y epel-release || true
        $SUDO yum install -y goaccess
    elif command -v apt-get >/dev/null 2>&1; then
        $SUDO apt-get update -qq
        $SUDO apt-get install -y goaccess
    else
        echo "ERROR: goaccess not found and no supported package manager (apt/dnf/yum)" >&2
        exit 1
    fi
fi

command -v goaccess >/dev/null 2>&1 || { echo "ERROR: goaccess installation failed" >&2; exit 1; }

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

# --- vhost helpers -----------------------------------------------------------
# Derive a vhost tag from the log file name: /path/example.com.log.1.gz -> example.com
vhost_of() {
    local base=${1##*/}
    base=${base%%.log*}
    base=${base%_log}
    base=${base%-log}
    printf '%s\n' "${base#www.}"
}

# Emit "vhost <original line>" for every line of every log (gz streams are
# decompressed on the fly). The tag feeds goaccess' %v (virtual host) field.
stream_logs() {
    local f v
    for f in "$@"; do
        v=$(vhost_of "$f")
        case $f in
            *.gz) gzip -cd -- "$f" 2>/dev/null | awk -v v="$v" '{print v, $0}' || true ;;
            *)    awk -v v="$v" '{print v, $0}' "$f" 2>/dev/null || true ;;
        esac
    done
}

# Plain concatenation (no vhost tagging).
cat_all() {
    local f
    for f in "$@"; do
        case $f in
            *.gz) gzip -cd -- "$f" 2>/dev/null || true ;;
            *)    cat -- "$f" 2>/dev/null || true ;;
        esac
    done
}

# --- time window --------------------------------------------------------------
FROM_LOG=$(log_ts "$SINCE"); TO_LOG=$(log_ts "$TO")
FROM_H=$(hum_ts "$SINCE");   TO_H=$(hum_ts "$TO")
FROM_E=$(date -d "$(normalize_spec "$SINCE")" +%s)
TO_E=$(date -d "$(normalize_spec "$TO")" +%s)
((FROM_E <= TO_E)) || die "empty time window: $FROM_H .. $TO_H"

# --- report -------------------------------------------------------------------
cat >&2 <<EOF
panel:      $PANEL
files:      ${#LOGS[@]}
window:     $FROM_H .. $TO_H   (-i $SINCE -t $TO)
vhosts:     $((VHOST))
log format: ${FORMAT:-auto}
output:     ${OUTPUT:-terminal}
EOF

[[ -n $OUTPUT ]] && EXTRA+=(-o "$OUTPUT")

if ((VHOST)); then
    # Combined format with the domain prepended as %v (goaccess "Virtual Hosts" panel).
    # After tagging, fields shift by one: the log date is now $5.
    GOA_ARGS=(--date-format=%d/%b/%Y --time-format=%H:%M:%S
              "--log-format=%v %h %^[%d:%t %^] \"%r\" %s %b \"%R\" \"%u\""
              "${EXTRA[@]}")
    [[ -n $FORMAT ]] && GOA_ARGS=(--log-format="$FORMAT" "${EXTRA[@]}")

    stream_logs "${LOGS[@]}" |
    awk -v from="$FROM_LOG" -v to="$TO_LOG" -v topn="$TOPN" '
        $5 >= from && $5 <= to { cnt[$1]++; n++; print }
        END {
            printf "lines in window: %d\n", n+0 > "/dev/stderr"
            if (n > 0) {
                print "top vhosts by requests:" > "/dev/stderr"
                cmd = "sort -rn | head -n " topn
                for (v in cnt) printf "%10d  %s\n", cnt[v], v | cmd
                close(cmd)
            }
        }' |
    goaccess "${GOA_ARGS[@]}" -
else
    # Classic combined logs without a per-domain tag.
    GOA_ARGS=(--log-format="${FORMAT:-COMBINED}" "${EXTRA[@]}")
    cat_all "${LOGS[@]}" |
    awk -v from="$FROM_LOG" -v to="$TO_LOG" '
        $4 >= from && $4 <= to { n++; print }
        END { printf "lines in window: %d\n", n+0 > "/dev/stderr" }' |
    goaccess "${GOA_ARGS[@]}" -
fi
