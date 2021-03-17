#!/bin/bash
PASSWORD_FILE=/opt/hxtool/data/.keyring_password
if [ ! -f "$PASSWORD_FILE" ]; then
    dd if=/dev/urandom of=$PASSWORD_FILE bs=1 count=32
fi
/usr/bin/dbus-run-session -- bash -r << EOF
cat $PASSWORD_FILE | gnome-keyring-daemon --unlock
python3 hxtool.py
EOF
