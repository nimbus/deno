// Copyright 2018-2026 the Deno authors. MIT license.

async function* consume(_source: AsyncIterable<unknown>) {
  for await (const _event of _source) {
    // The reporter API is stream-shaped; empty test runs should drain cleanly.
  }
}

export const dot = consume;
export const junit = consume;
export const lcov = consume;
export const spec = consume;
export const tap = consume;

export default {
  dot,
  junit,
  lcov,
  spec,
  tap,
};
