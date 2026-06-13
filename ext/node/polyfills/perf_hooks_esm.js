// Copyright 2018-2026 the Deno authors. MIT license.
import { core } from "ext:core/mod.js";
const mod = core.loadExtScript("ext:deno_node/perf_hooks.js");
const processGetBuiltinModule = globalThis.process?.getBuiltinModule;
const defaultExport =
  (typeof processGetBuiltinModule === "function"
    ? processGetBuiltinModule("perf_hooks")
    : undefined) ?? mod.default;

export const constants = defaultExport.constants;
export const createHistogram = defaultExport.createHistogram;
export const enqueueNodePerformanceEntry = mod.enqueueNodePerformanceEntry;
export const eventLoopUtilization = defaultExport.eventLoopUtilization;
export const monitorEventLoopDelay = defaultExport.monitorEventLoopDelay;
export const performance = defaultExport.performance;
export const PerformanceEntry = defaultExport.PerformanceEntry;
export const PerformanceMark = defaultExport.PerformanceMark;
export const PerformanceMeasure = defaultExport.PerformanceMeasure;
export const PerformanceObserver = defaultExport.PerformanceObserver;
export const PerformanceObserverEntryList =
  defaultExport.PerformanceObserverEntryList;
export const PerformanceResourceTiming =
  defaultExport.PerformanceResourceTiming;
export const timerify = defaultExport.timerify;

export default defaultExport;
