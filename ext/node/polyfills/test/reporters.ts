// Copyright 2018-2026 the Deno authors. MIT license.

async function* silentReporter(source: AsyncIterable<unknown>) {
  for await (const _event of source) {
    // The initial compat slice only requires reporters to be composable and to
    // consume the stream without surfacing synthetic failures.
  }
}

export const dot = silentReporter;
export const junit = silentReporter;
export const spec = silentReporter;
export const tap = silentReporter;
export const lcov = silentReporter;

export default {
  dot,
  junit,
  spec,
  tap,
  lcov,
};
