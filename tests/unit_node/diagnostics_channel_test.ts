// Copyright 2018-2026 the Deno authors. MIT license.

import { assertEquals } from "@std/assert";
import * as diagnosticsChannel from "node:diagnostics_channel";

Deno.test({
  name: "[diagnostics_channel] publish walks a stable subscriber snapshot",
  fn() {
    const channel = diagnosticsChannel.channel("diagnostics-channel-test");
    const seen: string[] = [];

    const first = () => {
      seen.push("first");
      channel.unsubscribe(first);
    };
    const second = () => {
      seen.push("second");
    };

    channel.subscribe(first);
    channel.subscribe(second);
    channel.publish({ value: 1 });

    assertEquals(seen, ["first", "second"]);
  },
});
