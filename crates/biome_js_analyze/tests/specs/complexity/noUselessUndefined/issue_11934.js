function f(x = undefined) {
  return arguments.length;
}
function g(a, b = undefined) {
  arguments[0] = 42;
  return a;
}
