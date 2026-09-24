const inner = new Error("inner");
throw new Error("outer", { cause: inner });
