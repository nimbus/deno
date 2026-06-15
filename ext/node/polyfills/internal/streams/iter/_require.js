// deno-lint-ignore-file
// Copyright 2018-2026 the Deno authors. MIT license.

(function () {
const { core } = __bootstrap;

function loadDefault(specifier) {
  return core.loadExtScript(specifier).default;
}

function require(specifier) {
  switch (specifier) {
    case "buffer":
      return loadDefault("ext:deno_node/internal/buffer.mjs");
    case "internal/abort_controller":
      return core.loadExtScript("ext:deno_node/internal/abort_controller.js");
    case "internal/encoding":
      return core.loadExtScript("ext:deno_node/internal/encoding.js");
    case "internal/errors":
      return core.loadExtScript("ext:deno_node/internal/errors.ts");
    case "internal/process/task_queues":
      return core.loadExtScript("ext:deno_node/internal/process/task_queues.js");
    case "internal/streams/add-abort-signal":
      return core.loadExtScript("ext:deno_node/internal/streams/add-abort-signal.js");
    case "internal/streams/destroy":
      return core.loadExtScript("ext:deno_node/internal/streams/destroy.js");
    case "internal/streams/end-of-stream":
      return core.loadExtScript("ext:deno_node/internal/streams/end-of-stream.js");
    case "internal/streams/iter/broadcast":
      return core.loadExtScript("ext:deno_node/internal/streams/iter/broadcast.js");
    case "internal/streams/iter/classic":
      return core.loadExtScript("ext:deno_node/internal/streams/iter/classic.js");
    case "internal/streams/iter/consumers":
      return core.loadExtScript("ext:deno_node/internal/streams/iter/consumers.js");
    case "internal/streams/iter/duplex":
      return core.loadExtScript("ext:deno_node/internal/streams/iter/duplex.js");
    case "internal/streams/iter/from":
      return core.loadExtScript("ext:deno_node/internal/streams/iter/from.js");
    case "internal/streams/iter/pull":
      return core.loadExtScript("ext:deno_node/internal/streams/iter/pull.js");
    case "internal/streams/iter/push":
      return core.loadExtScript("ext:deno_node/internal/streams/iter/push.js");
    case "internal/streams/iter/ringbuffer":
      return core.loadExtScript("ext:deno_node/internal/streams/iter/ringbuffer.js");
    case "internal/streams/iter/share":
      return core.loadExtScript("ext:deno_node/internal/streams/iter/share.js");
    case "internal/streams/iter/types":
      return core.loadExtScript("ext:deno_node/internal/streams/iter/types.js");
    case "internal/streams/iter/utils":
      return core.loadExtScript("ext:deno_node/internal/streams/iter/utils.js");
    case "internal/streams/readable":
      return loadDefault("ext:deno_node/internal/streams/readable.js");
    case "internal/streams/writable":
      return loadDefault("ext:deno_node/internal/streams/writable.js");
    case "internal/util":
      return core.loadExtScript("ext:deno_node/internal/util.mjs");
    case "internal/util/types":
      return core.loadExtScript("ext:deno_node/internal/util/types.ts");
    case "internal/validators":
      return core.loadExtScript("ext:deno_node/internal/validators.mjs");
    default:
      throw new Error(`Unsupported stream/iter internal require: ${specifier}`);
  }
}

return { require };
})();
