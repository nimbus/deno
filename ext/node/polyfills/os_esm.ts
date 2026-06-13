// Copyright 2018-2026 the Deno authors. MIT license.
import { getBuiltinModule } from "node:module";
const mod = getBuiltinModule("os");

export const {
  constants,
  arch,
  cpus,
  endianness,
  freemem,
  getPriority,
  homedir,
  hostname,
  loadavg,
  networkInterfaces,
  machine,
  platform,
  release,
  setPriority,
  tmpdir,
  totalmem,
  type,
  uptime,
  userInfo,
  version,
  availableParallelism,
  EOL,
  devNull,
} = mod;

export default mod;
