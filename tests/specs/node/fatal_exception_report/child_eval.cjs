const { spawnSync } = require("node:child_process");

for (
  const code of [
    "throw 'x'",
    "throw {a:1}",
    "const e = new Error('child'); e.code = 'ECHILD'; throw e;",
  ]
) {
  const { status, stderr } = spawnSync(process.execPath, ["-e", code], {
    encoding: "utf8",
  });
  // The footer must show the version of this process.
  const report = stderr.replace(
    `Node.js ${process.version}`,
    "Node.js <version>",
  );
  process.stdout.write(`--- ${code}\nstatus ${status}\n${report}`);
}
