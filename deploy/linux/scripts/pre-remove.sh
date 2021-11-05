#!/bin/sh

if command -V systemctl >/dev/null 2>&1; then
    systemctl stop cerbos || :
    systemctl disable cerbos || :
fi
