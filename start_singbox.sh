#!/usr/bin/env bash
set -euo pipefail
umask 077

DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
MODE="${1:-}"
UPDATE="${2:-}"
TMP=""

usage() {
    echo "Usage: $0 {tun|proxy} [update]" >&2
    exit 2
}

[[ "$MODE" == tun || "$MODE" == proxy ]] || usage
[[ $# -le 2 ]] || usage
[[ -z "$UPDATE" || "$UPDATE" == update ]] || usage

command -v sing-box >/dev/null || { echo "sing-box not found" >&2; exit 1; }

cleanup() {
    [[ -z "$TMP" ]] || rm -rf -- "$TMP"
}
trap cleanup EXIT

if [[ "$UPDATE" == update ]]; then
    for file in URL.txt vless_to_singbox.py; do
        [[ -f "$DIR/$file" && ! -L "$DIR/$file" ]] || {
            echo "Missing or invalid file: $file" >&2
            exit 1
        }
    done

    chmod 600 -- "$DIR/URL.txt"
    URL="$(< "$DIR/URL.txt")"
    [[ "$URL" == https://* && "$URL" != *[[:space:]]* ]] || {
        echo "URL.txt must contain one HTTPS URL" >&2
        exit 1
    }

    TMP="$(mktemp -d "$DIR/.update.XXXXXX")"
    curl --fail --silent --show-error --location \
        --proto '=https' --proto-redir '=https' \
        --connect-timeout 15 --max-time 90 --max-filesize 10485760 \
        --retry 2 -- "$URL" | base64 --decode > "$TMP/proxy_links.txt"
    [[ -s "$TMP/proxy_links.txt" ]] || { echo "Subscription is empty" >&2; exit 1; }

    python3 "$DIR/vless_to_singbox.py" "$TMP/proxy_links.txt" \
        --output-dir "$TMP" --force

    for file in config-proxy.json config-tun.json; do
        [[ -s "$TMP/$file" ]] || { echo "Generated file missing: $file" >&2; exit 1; }
        sing-box check -c "$TMP/$file"
    done

    # Refuse symlinks and special files at the destinations.
    FILES=(config-proxy.json config-tun.json proxy_links.txt)
    HAS_OLD=false
    for file in "${FILES[@]}"; do
        path="$DIR/$file"
        [[ ! -L "$path" && ( ! -e "$path" || -f "$path" ) ]] || {
            echo "Refusing to replace non-regular file: $path" >&2
            exit 1
        }
        [[ ! -e "$path" ]] || HAS_OLD=true
    done

    # Back up the originals only after the new files pass validation.
    if [[ "$HAS_OLD" == true ]]; then
        [[ ! -L "$DIR/bkp" ]] || { echo "bkp must not be a symlink" >&2; exit 1; }
        mkdir -p -- "$DIR/bkp"
        chmod 700 -- "$DIR/bkp"
        BACKUP="$(mktemp -d "$DIR/bkp/$(date +%Y%m%d-%H%M%S)-XXXXXX")"
        for file in "${FILES[@]}"; do
            [[ ! -f "$DIR/$file" ]] || cp -p -- "$DIR/$file" "$BACKUP/"
        done
        chmod 600 -- "$BACKUP"/*
        echo "Backup: $BACKUP"
    fi

    # All staged files are on the same filesystem, so each rename is atomic.
    for file in "${FILES[@]}"; do
        mv -f -- "$TMP/$file" "$DIR/$file"
    done
    rm -rf -- "$TMP"
    TMP=""
    echo "Update completed successfully."
fi

CONFIG="$DIR/config-$MODE.json"
sing-box check -c "$CONFIG"
if [[ "$MODE" == tun ]]; then
    if (( EUID == 0 )); then
        exec sing-box run -c "$CONFIG"
    else
        command -v sudo >/dev/null || { echo "sudo not found" >&2; exit 1; }
        exec sudo sing-box run -c "$CONFIG"
    fi
else
    exec sing-box run -c "$CONFIG"
fi
