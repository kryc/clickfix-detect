emit() { printf 'item:%s\n' "$1"; }
for value in one two; do
  if test -n "$value"; then emit "$value"; fi
done | grep item
