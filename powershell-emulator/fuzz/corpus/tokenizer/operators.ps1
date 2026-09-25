$value = ((0x41 + 1) -bxor 3) -shl 1
$items = 1..5 | ForEach-Object { [char]($_ + 64) }
