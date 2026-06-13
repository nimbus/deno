// Copyright 2018-2026 the Deno authors. MIT license.
import { core } from "ext:core/mod.js";
import { getBuiltinModule } from "node:module";
const mod = core.loadExtScript("ext:deno_node/dgram.ts");
const defaultExport = getBuiltinModule("dgram");

export const { createSocket, Socket } = mod;

export default defaultExport;
