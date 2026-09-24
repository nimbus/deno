process.on("exit", (c) => console.error("exit event", c, process.exitCode));
throw new Error("boom");
