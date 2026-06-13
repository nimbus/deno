// Copyright 2018-2026 the Deno authors. MIT license.
import { core } from "ext:core/mod.js";
const mod = core.loadExtScript("ext:deno_node/vm.js");
const processGetBuiltinModule = globalThis.process?.getBuiltinModule;
const defaultExport =
  (typeof processGetBuiltinModule === "function"
    ? processGetBuiltinModule("vm")
    : undefined) ?? mod.default;

export const Module = defaultExport.Module;
export const Script = defaultExport.Script;
export const SourceTextModule = defaultExport.SourceTextModule;
export const SyntheticModule = defaultExport.SyntheticModule;
export const constants = defaultExport.constants;
export const createContext = defaultExport.createContext;
export const createScript = defaultExport.createScript;
export const runInContext = defaultExport.runInContext;
export const runInNewContext = defaultExport.runInNewContext;
export const runInThisContext = defaultExport.runInThisContext;
export const isContext = defaultExport.isContext;
export const compileFunction = defaultExport.compileFunction;
export const measureMemory = defaultExport.measureMemory;

export default defaultExport;
