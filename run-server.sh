#!/usr/bin/env sh

while true; do
    systemd-socket-activate -l 8069 -l 8096 -E CREDENTIALS_DIRECTORY -E OAUTH_REDIRECT_ROOT -E APP_STATE_FILE ./target/debug/token-manager-server
done
