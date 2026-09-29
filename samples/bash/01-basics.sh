name=world
greet() {
  printf 'hello %s\n' "$1"
}
greet "$name"
printf 'args:%s\n' "$#"
