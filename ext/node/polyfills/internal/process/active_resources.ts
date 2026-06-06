// Copyright 2018-2026 the Deno authors. MIT license.

// deno-lint-ignore-file no-explicit-any

(function () {
const { primordials } = globalThis.__bootstrap;
const { ArrayPrototypePush, SafeSet, SafeSetIterator, Symbol } = primordials;

const activeRequests = new SafeSet();
const activeHandles = new SafeSet();

// Stream/handle owners (net.Socket, net.Server, ...) tag themselves with this
// symbol so process.getActiveResourcesInfo() can report Node's libuv provider
// name (e.g. "TCPSocketWrap", "TCPServerWrap") instead of the JS constructor
// name. Resources without a tag fall back to their constructor name.
const kResourceInfoName = Symbol("nimbus.node.resourceInfoName");

function resourceInfoName(resource: any): string {
  const tag = resource?.[kResourceInfoName];
  if (typeof tag === "string") {
    return tag;
  }
  const ctorName = resource?.constructor?.name;
  return typeof ctorName === "string" && ctorName.length > 0
    ? ctorName
    : "Unknown";
}

class FSReqCallback {}

function snapshot(set: Set<any>) {
  const resources = [];
  for (const resource of new SafeSetIterator(set)) {
    ArrayPrototypePush(resources, resource);
  }
  return resources;
}

function registerActiveRequest(request: any) {
  activeRequests.add(request);
  return request;
}

function unregisterActiveRequest(request: any) {
  activeRequests.delete(request);
}

function createFSReqCallback() {
  return registerActiveRequest(new FSReqCallback());
}

function getActiveRequests() {
  return snapshot(activeRequests);
}

function registerActiveHandle(handle: any) {
  activeHandles.add(handle);
  return handle;
}

function unregisterActiveHandle(handle: any) {
  activeHandles.delete(handle);
}

function getActiveHandles() {
  return snapshot(activeHandles);
}

return {
  createFSReqCallback,
  getActiveHandles,
  getActiveRequests,
  kResourceInfoName,
  registerActiveHandle,
  registerActiveRequest,
  resourceInfoName,
  unregisterActiveHandle,
  unregisterActiveRequest,
};
})();
