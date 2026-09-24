setTimeout(() => {
  const e = new RangeError("late");
  e.code = "ERR_X";
  throw e;
}, 1);
