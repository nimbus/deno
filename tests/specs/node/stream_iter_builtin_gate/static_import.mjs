import * as iter from "node:stream/iter";

export default iter;
console.log("static import loaded", typeof iter.from);
