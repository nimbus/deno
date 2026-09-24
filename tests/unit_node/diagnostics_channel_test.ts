// Copyright 2018-2026 the Deno authors. MIT license.

import dc from "node:diagnostics_channel";
import { assert, assertFalse, assertThrows } from "@std/assert";

Deno.test("[diagnostics_channel] an invalid subscription does not activate the channel", () => {
  const name = "diagnostics-channel-invalid-subscription";
  const channel = dc.channel(name);

  assertThrows(
    // deno-lint-ignore no-explicit-any
    () => dc.subscribe(name, null as any),
    TypeError,
    'The "subscription" argument must be of type function',
  );
  assertFalse(channel.hasSubscribers);
  assertFalse(dc.hasSubscribers(name));

  assertThrows(
    // deno-lint-ignore no-explicit-any
    () => channel.subscribe(null as any),
    TypeError,
    'The "subscription" argument must be of type function',
  );
  assertFalse(channel.hasSubscribers);
  assertFalse(dc.hasSubscribers(name));

  const subscriber = () => {};
  channel.subscribe(subscriber);
  assert(channel.hasSubscribers);
  assert(channel.unsubscribe(subscriber));
  assertFalse(channel.hasSubscribers);
});
