// Copyright 2018-2026 the Deno authors. MIT license.
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

import { getOptions } from "ext:deno_node/internal_binding/node_options.ts";
import { primordials } from "ext:core/mod.js";
const {
  MapPrototypeGet,
  SafeMap,
  StringPrototypeSlice,
  StringPrototypeStartsWith,
} = primordials;

let optionsMap: Map<string, { value: string }>;
const dummyOptions = new SafeMap<string, { value: string }>();
let warnOnAllowUnauthorized = true;

function getOptionsFromBinding() {
  // If Deno.build is not defined, this is in warmup phase.
  if (!Deno.build) {
    return dummyOptions;
  }

  if (!optionsMap) {
    ({ options: optionsMap } = getOptions());
  }

  return optionsMap;
}

export function getOptionValue(optionName: string) {
  const options = getOptionsFromBinding();

  if (StringPrototypeStartsWith(optionName, "--no-")) {
    const option = MapPrototypeGet(
      options,
      "--" + StringPrototypeSlice(optionName, 5),
    );

    return option && !option.value;
  }

  return MapPrototypeGet(options, optionName)?.value;
}

export function getAllowUnauthorized() {
  const allowUnauthorized =
    globalThis.process?.env?.NODE_TLS_REJECT_UNAUTHORIZED === "0";

  if (allowUnauthorized && warnOnAllowUnauthorized) {
    warnOnAllowUnauthorized = false;
    globalThis.process?.emitWarning?.(
      "Setting the NODE_TLS_REJECT_UNAUTHORIZED " +
        "environment variable to '0' makes TLS connections " +
        "and HTTPS requests insecure by disabling " +
        "certificate verification.",
    );
  }

  return allowUnauthorized;
}
