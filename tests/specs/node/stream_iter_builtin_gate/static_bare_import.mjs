import * as streamIter from "stream/iter";
import * as zlibIter from "zlib/iter";

export default streamIter;
console.log(
  "static bare import loaded",
  typeof streamIter.from,
  typeof zlibIter.compressGzip,
);
