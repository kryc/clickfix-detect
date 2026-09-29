unit=/etc/systemd/system/example-agent.service
printf '[Unit]\nDescription=Example Agent\n[Service]\nExecStart=/tmp/example-agent\n' > "$unit"
systemctl daemon-reload
systemctl enable --now "$unit"
