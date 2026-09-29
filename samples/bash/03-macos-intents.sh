payload=/tmp/update.sh
printf '#!/bin/bash\necho staged\n' > "$payload"
chmod +x "$payload"
xattr -d com.apple.quarantine "$payload"
osascript -e 'do shell script "echo nested > /tmp/apple.txt"'
