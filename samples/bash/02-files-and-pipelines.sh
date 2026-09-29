printf 'alpha\nbeta\ngamma\n' > /tmp/items.txt
cat /tmp/items.txt | grep beta | tee /tmp/matches.txt
wc -l < /tmp/matches.txt
