// Mirrors the layouts of Node's test-module-symlinked-peer-modules.js and
// test-esm-preserve-symlinks-main.js:
//
// ├── app
// │   ├── index.cjs
// │   └── node_modules
// │       ├── moduleA -> ../../moduleA
// │       └── moduleB/{index.js,package.json}
// ├── moduleA/{index.js,package.json}
// ├── index.cjs -> nested/entry.cjs
// ├── nested/entry.cjs
// ├── nested2/submodule.cjs
// └── submodule_link.cjs -> nested2/submodule.cjs
const fs = require("node:fs");
const path = require("node:path");

const root = process.cwd();
const moduleA = path.join(root, "moduleA");
const app = path.join(root, "app");
const moduleB = path.join(app, "node_modules", "moduleB");

fs.mkdirSync(moduleA);
fs.mkdirSync(path.join(app, "node_modules"), { recursive: true });
fs.mkdirSync(moduleB);
fs.symlinkSync(moduleA, path.join(app, "node_modules", "moduleA"), "dir");

fs.writeFileSync(
  path.join(moduleA, "package.json"),
  JSON.stringify({ name: "moduleA", main: "index.js" }),
);
fs.writeFileSync(
  path.join(moduleA, "index.js"),
  "module.exports = require('moduleB');",
);
fs.writeFileSync(
  path.join(moduleB, "package.json"),
  JSON.stringify({ name: "moduleB", main: "index.js" }),
);
fs.writeFileSync(path.join(moduleB, "index.js"), "module.exports = 'peer';");
fs.writeFileSync(
  path.join(app, "index.cjs"),
  [
    "const path = require('node:path');",
    "const resolved = require.resolve('moduleA');",
    "console.log('moduleA ->', path.relative(process.cwd(), resolved));",
    "console.log('moduleB =', require('moduleA'));",
    "",
  ].join("\n"),
);

fs.mkdirSync(path.join(root, "nested"));
fs.mkdirSync(path.join(root, "nested2"));
const entry = path.join(root, "nested", "entry.cjs");
const submodule = path.join(root, "nested2", "submodule.cjs");
fs.writeFileSync(
  entry,
  [
    "const path = require('node:path');",
    "console.log('main __dirname =', path.relative(process.cwd(), __dirname) || '.');",
    "// This require only resolves when the entry keeps its symlink path.",
    "console.log('submodule =', require('./submodule_link.cjs'));",
    "",
  ].join("\n"),
);
fs.writeFileSync(submodule, "module.exports = 'linked';");
fs.symlinkSync(entry, path.join(root, "index.cjs"));
fs.symlinkSync(submodule, path.join(root, "submodule_link.cjs"));
