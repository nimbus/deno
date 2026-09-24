const e = new Error("with props");
e.status = 404;
e.details = { path: "/x", tags: ["a", "b"] };
throw e;
