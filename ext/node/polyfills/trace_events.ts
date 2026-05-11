// Copyright 2018-2026 the Deno authors. MIT license.

import {
  ERR_TRACE_EVENTS_CATEGORY_REQUIRED,
  ERR_TRACE_EVENTS_UNAVAILABLE,
} from "ext:deno_node/internal/errors.ts";
import {
  CategorySet,
  getEnabledCategories,
} from "ext:deno_node/internal_binding/trace_events.ts";
import { validateObject, validateStringArray } from "ext:deno_node/internal/validators.mjs";
import { customInspectSymbol } from "ext:deno_node/internal/util.mjs";
import { format } from "ext:deno_node/internal/util/inspect.mjs";

const kMaxTracingCount = 10;
const enabledTracingObjects = new Set<Tracing>();

class Tracing {
  #handle: CategorySet;
  #categories: string[];
  #enabled = false;

  constructor(categories: string[]) {
    this.#handle = new CategorySet(categories);
    this.#categories = categories;
  }

  enable() {
    if (!this.#enabled) {
      this.#enabled = true;
      this.#handle.enable();
      enabledTracingObjects.add(this);
      if (enabledTracingObjects.size > kMaxTracingCount) {
        globalThis.process?.emitWarning?.(
          "Possible trace_events memory leak detected. There are more than " +
            `${kMaxTracingCount} enabled Tracing objects.`,
        );
      }
    }
  }

  disable() {
    if (!this.#enabled) {
      return;
    }
    this.#enabled = false;
    this.#handle.disable();
    enabledTracingObjects.delete(this);
  }

  get enabled() {
    return this.#enabled;
  }

  get categories() {
    return this.#categories.join(",");
  }

  [customInspectSymbol](depth: number) {
    if (typeof depth === "number" && depth < 0) {
      return this;
    }
    return `Tracing ${format({
      enabled: this.enabled,
      categories: this.categories,
    })}`;
  }
}

function createTracing(options: { categories: string[] }) {
  validateObject(options, "options");
  validateStringArray(options.categories, "options.categories");
  if (options.categories.length <= 0) {
    throw new ERR_TRACE_EVENTS_CATEGORY_REQUIRED();
  }
  if (typeof globalThis.process === "undefined") {
    throw new ERR_TRACE_EVENTS_UNAVAILABLE();
  }
  return new Tracing(options.categories);
}

export { createTracing, getEnabledCategories };

export default {
  createTracing,
  getEnabledCategories,
};
