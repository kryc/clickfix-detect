job=/tmp/example.cron
printf '*/5 * * * * /tmp/example-agent\n' > "$job"
sudo crontab "$job"
