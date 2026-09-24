const { Readable } = require("stream");
const r = new Readable({ read() {} });
r[Symbol.for("Stream.toAsyncStreamable")]();
