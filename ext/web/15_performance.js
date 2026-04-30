// Copyright 2018-2026 the Deno authors. MIT license.

import { primordials } from "ext:core/mod.js";
import { op_now, op_time_origin } from "ext:core/ops";
const {
  ArrayIsArray,
  ArrayPrototypeFilter,
  ArrayPrototypeIncludes,
  ArrayPrototypeIndexOf,
  ArrayPrototypePush,
  ArrayPrototypeSlice,
  ArrayPrototypeSplice,
  ObjectDefineProperties,
  ObjectKeys,
  ObjectPrototypeIsPrototypeOf,
  queueMicrotask,
  ReflectHas,
  Symbol,
  SymbolFor,
  TypeError,
  TypedArrayPrototypeGetBuffer,
  Uint8Array,
  Uint32Array,
} = primordials;

import * as webidl from "ext:deno_webidl/00_webidl.js";
import { structuredClone } from "./02_structured_clone.js";
import { createFilteredInspectProxy } from "./01_console.js";
import { EventTarget } from "./02_event.js";
import { DOMException } from "./01_dom_exception.js";

const illegalConstructorKey = Symbol("illegalConstructorKey");
const kEnumerableProperty = { __proto__: null, enumerable: true };
let performanceEntries = [];
let timeOrigin;
const performanceObservers = [];

const hrU8 = new Uint8Array(8);
const hr = new Uint32Array(TypedArrayPrototypeGetBuffer(hrU8));

function setTimeOrigin() {
  op_time_origin(hrU8);
  timeOrigin = hr[0] * 1000 + hr[1] / 1e6;
}

function now() {
  op_now(hrU8);
  return hr[0] * 1000 + hr[1] / 1e6;
}

webidl.converters["PerformanceMarkOptions"] = webidl
  .createDictionaryConverter(
    "PerformanceMarkOptions",
    [
      {
        key: "detail",
        converter: webidl.converters.any,
      },
      {
        key: "startTime",
        converter: webidl.converters.DOMHighResTimeStamp,
      },
    ],
  );

webidl.converters["DOMString or DOMHighResTimeStamp"] = (
  V,
  prefix,
  context,
  opts,
) => {
  if (webidl.type(V) === "Number" && V !== null) {
    return webidl.converters.DOMHighResTimeStamp(V, prefix, context, opts);
  }
  return webidl.converters.DOMString(V, prefix, context, opts);
};

webidl.converters["PerformanceMeasureOptions"] = webidl
  .createDictionaryConverter(
    "PerformanceMeasureOptions",
    [
      {
        key: "detail",
        converter: webidl.converters.any,
      },
      {
        key: "start",
        converter: webidl.converters["DOMString or DOMHighResTimeStamp"],
      },
      {
        key: "duration",
        converter: webidl.converters.DOMHighResTimeStamp,
      },
      {
        key: "end",
        converter: webidl.converters["DOMString or DOMHighResTimeStamp"],
      },
    ],
  );

webidl.converters["DOMString or PerformanceMeasureOptions"] = (
  V,
  prefix,
  context,
  opts,
) => {
  if (webidl.type(V) === "Object" && V !== null) {
    return webidl.converters["PerformanceMeasureOptions"](
      V,
      prefix,
      context,
      opts,
    );
  }
  return webidl.converters.DOMString(V, prefix, context, opts);
};

function findMostRecent(
  name,
  type,
) {
  for (let i = performanceEntries.length - 1; i >= 0; --i) {
    const entry = performanceEntries[i];
    if (entry.name === name && entry.entryType === type) {
      return entry;
    }
  }
}

function convertMarkToTimestamp(mark) {
  if (typeof mark === "string") {
    const entry = findMostRecent(mark, "mark");
    if (!entry) {
      throw new DOMException(
        `Cannot find mark: "${mark}"`,
        "SyntaxError",
      );
    }
    return entry.startTime;
  }
  if (mark < 0) {
    throw new TypeError(`Mark cannot be negative: received ${mark}`);
  }
  return mark;
}

function filterByNameType(
  name,
  type,
) {
  return ArrayPrototypeFilter(
    performanceEntries,
    (entry) =>
      (name ? entry.name === name : true) &&
      (type ? entry.entryType === type : true),
  );
}

const _name = Symbol("[[name]]");
const _entryType = Symbol("[[entryType]]");
const _startTime = Symbol("[[startTime]]");
const _duration = Symbol("[[duration]]");
class PerformanceEntry {
  [_name] = "";
  [_entryType] = "";
  [_startTime] = 0;
  [_duration] = 0;

  get name() {
    webidl.assertBranded(this, PerformanceEntryPrototype);
    return this[_name];
  }

  get entryType() {
    webidl.assertBranded(this, PerformanceEntryPrototype);
    return this[_entryType];
  }

  get startTime() {
    webidl.assertBranded(this, PerformanceEntryPrototype);
    return this[_startTime];
  }

  get duration() {
    webidl.assertBranded(this, PerformanceEntryPrototype);
    return this[_duration];
  }

  constructor(
    name = null,
    entryType = null,
    startTime = null,
    duration = null,
    key = undefined,
  ) {
    if (key !== illegalConstructorKey) {
      webidl.illegalConstructor();
    }
    this[webidl.brand] = webidl.brand;

    this[_name] = name;
    this[_entryType] = entryType;
    this[_startTime] = startTime;
    this[_duration] = duration;
  }

  toJSON() {
    webidl.assertBranded(this, PerformanceEntryPrototype);
    return {
      name: this[_name],
      entryType: this[_entryType],
      startTime: this[_startTime],
      duration: this[_duration],
    };
  }

  [SymbolFor("Deno.privateCustomInspect")](inspect, inspectOptions) {
    return inspect(
      createFilteredInspectProxy({
        object: this,
        evaluate: ObjectPrototypeIsPrototypeOf(
          PerformanceEntryPrototype,
          this,
        ),
        keys: [
          "name",
          "entryType",
          "startTime",
          "duration",
        ],
      }),
      inspectOptions,
    );
  }
}
webidl.configureInterface(PerformanceEntry);
const PerformanceEntryPrototype = PerformanceEntry.prototype;

const _detail = Symbol("[[detail]]");
class PerformanceMark extends PerformanceEntry {
  [_detail] = null;

  get detail() {
    webidl.assertBranded(this, PerformanceMarkPrototype);
    return this[_detail];
  }

  get entryType() {
    webidl.assertBranded(this, PerformanceMarkPrototype);
    return "mark";
  }

  constructor(
    name,
    options = { __proto__: null },
  ) {
    const prefix = "Failed to construct 'PerformanceMark'";
    webidl.requiredArguments(arguments.length, 1, prefix);

    name = webidl.converters.DOMString(name, prefix, "Argument 1");

    options = webidl.converters.PerformanceMarkOptions(
      options,
      prefix,
      "Argument 2",
    );

    const { detail = null, startTime = now() } = options;

    super(name, "mark", startTime, 0, illegalConstructorKey);
    this[webidl.brand] = webidl.brand;
    if (startTime < 0) {
      throw new TypeError(
        `Cannot construct PerformanceMark: startTime cannot be negative, received ${startTime}`,
      );
    }
    this[_detail] = structuredClone(detail);
  }

  toJSON() {
    webidl.assertBranded(this, PerformanceMarkPrototype);
    return {
      name: this.name,
      entryType: this.entryType,
      startTime: this.startTime,
      duration: this.duration,
      detail: this.detail,
    };
  }

  [SymbolFor("Deno.privateCustomInspect")](inspect, inspectOptions) {
    return inspect(
      createFilteredInspectProxy({
        object: this,
        evaluate: ObjectPrototypeIsPrototypeOf(PerformanceMarkPrototype, this),
        keys: [
          "name",
          "entryType",
          "startTime",
          "duration",
          "detail",
        ],
      }),
      inspectOptions,
    );
  }
}
webidl.configureInterface(PerformanceMark);
const PerformanceMarkPrototype = PerformanceMark.prototype;
class PerformanceMeasure extends PerformanceEntry {
  [_detail] = null;

  get detail() {
    webidl.assertBranded(this, PerformanceMeasurePrototype);
    return this[_detail];
  }

  get entryType() {
    webidl.assertBranded(this, PerformanceMeasurePrototype);
    return "measure";
  }

  constructor(
    name = null,
    startTime = null,
    duration = null,
    detail = null,
    key = undefined,
  ) {
    if (key !== illegalConstructorKey) {
      webidl.illegalConstructor();
    }

    super(name, "measure", startTime, duration, key);
    this[webidl.brand] = webidl.brand;
    this[_detail] = structuredClone(detail);
  }

  toJSON() {
    webidl.assertBranded(this, PerformanceMeasurePrototype);
    return {
      name: this.name,
      entryType: this.entryType,
      startTime: this.startTime,
      duration: this.duration,
      detail: this.detail,
    };
  }

  [SymbolFor("Deno.privateCustomInspect")](inspect, inspectOptions) {
    return inspect(
      createFilteredInspectProxy({
        object: this,
        evaluate: ObjectPrototypeIsPrototypeOf(
          PerformanceMeasurePrototype,
          this,
        ),
        keys: [
          "name",
          "entryType",
          "startTime",
          "duration",
          "detail",
        ],
      }),
      inspectOptions,
    );
  }
}
webidl.configureInterface(PerformanceMeasure);
const PerformanceMeasurePrototype = PerformanceMeasure.prototype;


const _cacheMode = Symbol("[[cacheMode]]");
const _requestedUrl = Symbol("[[requestedUrl]]");
const _timingInfo = Symbol("[[timingInfo]]");
const _initiatorType = Symbol("[[initiatorType]]");
const _deliveryType = Symbol("[[deliveryType]]");
const _responseStatus = Symbol("[[responseStatus]]");
class PerformanceResourceTiming extends PerformanceEntry {
  [_cacheMode] = "";
  [_requestedUrl] = "";
  [_timingInfo] = null;
  [_initiatorType] = "";
  [_deliveryType] = "";
  [_responseStatus] = 0;

  get name() {
    webidl.assertBranded(this, PerformanceResourceTimingPrototype);
    return this[_requestedUrl];
  }

  get startTime() {
    webidl.assertBranded(this, PerformanceResourceTimingPrototype);
    return this[_timingInfo].startTime;
  }

  get duration() {
    webidl.assertBranded(this, PerformanceResourceTimingPrototype);
    return this[_timingInfo].endTime - this[_timingInfo].startTime;
  }

  get initiatorType() {
    webidl.assertBranded(this, PerformanceResourceTimingPrototype);
    return this[_initiatorType];
  }

  get workerStart() {
    webidl.assertBranded(this, PerformanceResourceTimingPrototype);
    return this[_timingInfo].finalServiceWorkerStartTime;
  }

  get redirectStart() {
    webidl.assertBranded(this, PerformanceResourceTimingPrototype);
    return this[_timingInfo].redirectStartTime;
  }

  get redirectEnd() {
    webidl.assertBranded(this, PerformanceResourceTimingPrototype);
    return this[_timingInfo].redirectEndTime;
  }

  get fetchStart() {
    webidl.assertBranded(this, PerformanceResourceTimingPrototype);
    return this[_timingInfo].postRedirectStartTime;
  }

  get domainLookupStart() {
    webidl.assertBranded(this, PerformanceResourceTimingPrototype);
    return this[_timingInfo].finalConnectionTimingInfo?.domainLookupStartTime;
  }

  get domainLookupEnd() {
    webidl.assertBranded(this, PerformanceResourceTimingPrototype);
    return this[_timingInfo].finalConnectionTimingInfo?.domainLookupEndTime;
  }

  get connectStart() {
    webidl.assertBranded(this, PerformanceResourceTimingPrototype);
    return this[_timingInfo].finalConnectionTimingInfo?.connectionStartTime;
  }

  get connectEnd() {
    webidl.assertBranded(this, PerformanceResourceTimingPrototype);
    return this[_timingInfo].finalConnectionTimingInfo?.connectionEndTime;
  }

  get secureConnectionStart() {
    webidl.assertBranded(this, PerformanceResourceTimingPrototype);
    return this[_timingInfo].finalConnectionTimingInfo?.secureConnectionStartTime;
  }

  get nextHopProtocol() {
    webidl.assertBranded(this, PerformanceResourceTimingPrototype);
    return this[_timingInfo].finalConnectionTimingInfo?.ALPNNegotiatedProtocol;
  }

  get requestStart() {
    webidl.assertBranded(this, PerformanceResourceTimingPrototype);
    return this[_timingInfo].finalNetworkRequestStartTime;
  }

  get responseStart() {
    webidl.assertBranded(this, PerformanceResourceTimingPrototype);
    return this[_timingInfo].finalNetworkResponseStartTime;
  }

  get responseEnd() {
    webidl.assertBranded(this, PerformanceResourceTimingPrototype);
    return this[_timingInfo].endTime;
  }

  get encodedBodySize() {
    webidl.assertBranded(this, PerformanceResourceTimingPrototype);
    return this[_timingInfo].encodedBodySize;
  }

  get decodedBodySize() {
    webidl.assertBranded(this, PerformanceResourceTimingPrototype);
    return this[_timingInfo].decodedBodySize;
  }

  get transferSize() {
    webidl.assertBranded(this, PerformanceResourceTimingPrototype);
    if (this[_cacheMode] === "local") return 0;
    if (this[_cacheMode] === "validated") return 300;
    return this[_timingInfo].encodedBodySize + 300;
  }

  get deliveryType() {
    webidl.assertBranded(this, PerformanceResourceTimingPrototype);
    return this[_deliveryType];
  }

  get responseStatus() {
    webidl.assertBranded(this, PerformanceResourceTimingPrototype);
    return this[_responseStatus];
  }

  constructor(
    requestedUrl = "",
    initiatorType = "",
    timingInfo = null,
    cacheMode = "",
    responseStatus = 0,
    deliveryType = "",
    key = undefined,
  ) {
    if (key !== illegalConstructorKey) {
      webidl.illegalConstructor();
    }

    super(requestedUrl, "resource", timingInfo?.startTime ?? 0, 0, illegalConstructorKey);
    this[webidl.brand] = webidl.brand;
    this[_cacheMode] = cacheMode;
    this[_requestedUrl] = requestedUrl;
    this[_timingInfo] = timingInfo;
    this[_initiatorType] = initiatorType;
    this[_deliveryType] = deliveryType;
    this[_responseStatus] = responseStatus;
  }

  toJSON() {
    webidl.assertBranded(this, PerformanceResourceTimingPrototype);
    return {
      name: this.name,
      entryType: this.entryType,
      startTime: this.startTime,
      duration: this.duration,
      initiatorType: this.initiatorType,
      nextHopProtocol: this.nextHopProtocol,
      workerStart: this.workerStart,
      redirectStart: this.redirectStart,
      redirectEnd: this.redirectEnd,
      fetchStart: this.fetchStart,
      domainLookupStart: this.domainLookupStart,
      domainLookupEnd: this.domainLookupEnd,
      connectStart: this.connectStart,
      connectEnd: this.connectEnd,
      secureConnectionStart: this.secureConnectionStart,
      requestStart: this.requestStart,
      responseStart: this.responseStart,
      responseEnd: this.responseEnd,
      transferSize: this.transferSize,
      encodedBodySize: this.encodedBodySize,
      decodedBodySize: this.decodedBodySize,
      deliveryType: this.deliveryType,
      responseStatus: this.responseStatus,
    };
  }

  [SymbolFor("Deno.privateCustomInspect")](inspect, inspectOptions) {
    return inspect(
      createFilteredInspectProxy({
        object: this,
        evaluate: ObjectPrototypeIsPrototypeOf(
          PerformanceResourceTimingPrototype,
          this,
        ),
        keys: [
          "name",
          "entryType",
          "startTime",
          "duration",
          "initiatorType",
          "nextHopProtocol",
          "workerStart",
          "redirectStart",
          "redirectEnd",
          "fetchStart",
          "domainLookupStart",
          "domainLookupEnd",
          "connectStart",
          "connectEnd",
          "secureConnectionStart",
          "requestStart",
          "responseStart",
          "responseEnd",
          "transferSize",
          "encodedBodySize",
          "decodedBodySize",
          "deliveryType",
          "responseStatus",
        ],
      }),
      inspectOptions,
    );
  }
}
webidl.configureInterface(PerformanceResourceTiming);
const PerformanceResourceTimingPrototype = PerformanceResourceTiming.prototype;
ObjectDefineProperties(PerformanceResourceTiming.prototype, {
  initiatorType: kEnumerableProperty,
  nextHopProtocol: kEnumerableProperty,
  workerStart: kEnumerableProperty,
  redirectStart: kEnumerableProperty,
  redirectEnd: kEnumerableProperty,
  fetchStart: kEnumerableProperty,
  domainLookupStart: kEnumerableProperty,
  domainLookupEnd: kEnumerableProperty,
  connectStart: kEnumerableProperty,
  connectEnd: kEnumerableProperty,
  secureConnectionStart: kEnumerableProperty,
  requestStart: kEnumerableProperty,
  responseStart: kEnumerableProperty,
  responseEnd: kEnumerableProperty,
  transferSize: kEnumerableProperty,
  encodedBodySize: kEnumerableProperty,
  decodedBodySize: kEnumerableProperty,
  deliveryType: kEnumerableProperty,
  responseStatus: kEnumerableProperty,
  toJSON: kEnumerableProperty,
  [Symbol.toStringTag]: {
    __proto__: null,
    writable: false,
    enumerable: false,
    configurable: true,
    value: "PerformanceResourceTiming",
  },
});

function markResourceTiming(
  timingInfo,
  requestedUrl,
  initiatorType,
  _global,
  cacheMode,
  _bodyInfo,
  responseStatus,
  deliveryType = "",
) {
  const resource = new PerformanceResourceTiming(
    requestedUrl,
    initiatorType,
    timingInfo,
    cacheMode,
    responseStatus,
    deliveryType,
    illegalConstructorKey,
  );
  ArrayPrototypePush(performanceEntries, resource);
  queuePerformanceEntry(resource);
  return resource;
}

function queuePerformanceEntry(entry) {
  for (let i = 0; i < performanceObservers.length; i++) {
    const observer = performanceObservers[i];
    if (ArrayPrototypeIncludes(observer[_entryTypes], entry.entryType)) {
      ArrayPrototypePush(observer[_buffer], entry);
      if (!observer[_scheduled]) {
        observer[_scheduled] = true;
        queueMicrotask(() => {
          observer[_scheduled] = false;
          const entries = observer[_buffer];
          observer[_buffer] = [];
          if (entries.length > 0) {
            const entryList = new PerformanceObserverEntryList(
              entries,
              illegalConstructorKey,
            );
            observer[_callback](entryList, observer);
          }
        });
      }
    }
  }
}

const _entries = Symbol("[[entries]]");

class PerformanceObserverEntryList {
  [_entries] = [];

  constructor(entries, key = undefined) {
    if (key !== illegalConstructorKey) {
      webidl.illegalConstructor();
    }
    this[webidl.brand] = webidl.brand;
    this[_entries] = entries;
  }

  getEntries() {
    webidl.assertBranded(this, PerformanceObserverEntryListPrototype);
    return ArrayPrototypeSlice(this[_entries]);
  }

  getEntriesByType(type) {
    webidl.assertBranded(this, PerformanceObserverEntryListPrototype);
    const prefix =
      "Failed to execute 'getEntriesByType' on 'PerformanceObserverEntryList'";
    webidl.requiredArguments(arguments.length, 1, prefix);
    type = webidl.converters.DOMString(type, prefix, "Argument 1");
    return ArrayPrototypeFilter(
      this[_entries],
      (entry) => entry.entryType === type,
    );
  }

  getEntriesByName(name, type = undefined) {
    webidl.assertBranded(this, PerformanceObserverEntryListPrototype);
    const prefix =
      "Failed to execute 'getEntriesByName' on 'PerformanceObserverEntryList'";
    webidl.requiredArguments(arguments.length, 1, prefix);
    name = webidl.converters.DOMString(name, prefix, "Argument 1");
    if (type !== undefined) {
      type = webidl.converters.DOMString(type, prefix, "Argument 2");
    }
    return ArrayPrototypeFilter(
      this[_entries],
      (entry) =>
        entry.name === name && (type === undefined || entry.entryType === type),
    );
  }
}
webidl.configureInterface(PerformanceObserverEntryList);
const PerformanceObserverEntryListPrototype =
  PerformanceObserverEntryList.prototype;

const _callback = Symbol("[[callback]]");
const _entryTypes = Symbol("[[entryTypes]]");
const _buffer = Symbol("[[buffer]]");
const _scheduled = Symbol("[[scheduled]]");

class PerformanceObserver {
  static get supportedEntryTypes() {
    return ["mark", "measure", "resource"];
  }

  [_callback] = null;
  [_entryTypes] = [];
  [_buffer] = [];
  [_scheduled] = false;

  constructor(callback) {
    const prefix = "Failed to construct 'PerformanceObserver'";
    webidl.requiredArguments(arguments.length, 1, prefix);
    if (typeof callback !== "function") {
      throw new TypeError(
        `${prefix}: The callback provided as parameter 1 is not a function.`,
      );
    }
    this[webidl.brand] = webidl.brand;
    this[_callback] = callback;
  }

  observe(options = { __proto__: null }) {
    webidl.assertBranded(this, PerformanceObserverPrototype);
    const prefix = "Failed to execute 'observe' on 'PerformanceObserver'";

    if (options === undefined || options === null) {
      throw new TypeError(
        `${prefix}: 1 argument required, but only 0 present.`,
      );
    }

    const { entryTypes, type } = options;

    if (entryTypes !== undefined && type !== undefined) {
      throw new TypeError(
        `${prefix}: Cannot specify both 'entryTypes' and 'type'.`,
      );
    }

    if (entryTypes === undefined && type === undefined) {
      throw new TypeError(
        `${prefix}: Either 'entryTypes' or 'type' must be specified.`,
      );
    }

    let types;
    if (entryTypes !== undefined) {
      if (!ArrayIsArray(entryTypes)) {
        throw new TypeError(`${prefix}: 'entryTypes' must be an array.`);
      }
      types = ArrayPrototypeFilter(
        entryTypes,
        (t) =>
          ArrayPrototypeIncludes(PerformanceObserver.supportedEntryTypes, t),
      );
      if (types.length === 0) {
        return;
      }
    } else {
      if (
        !ArrayPrototypeIncludes(PerformanceObserver.supportedEntryTypes, type)
      ) {
        return;
      }
      types = [type];
    }

    this[_entryTypes] = types;
    this[_buffer] = [];

    if (!ArrayPrototypeIncludes(performanceObservers, this)) {
      ArrayPrototypePush(performanceObservers, this);
    }
  }

  disconnect() {
    webidl.assertBranded(this, PerformanceObserverPrototype);
    const index = ArrayPrototypeIndexOf(performanceObservers, this);
    if (index !== -1) {
      ArrayPrototypeSplice(performanceObservers, index, 1);
    }
    this[_entryTypes] = [];
    this[_buffer] = [];
  }

  takeRecords() {
    webidl.assertBranded(this, PerformanceObserverPrototype);
    const records = this[_buffer];
    this[_buffer] = [];
    return records;
  }
}
webidl.configureInterface(PerformanceObserver);
const PerformanceObserverPrototype = PerformanceObserver.prototype;

class Performance extends EventTarget {
  constructor(key = null) {
    if (key != illegalConstructorKey) {
      webidl.illegalConstructor();
    }

    super();
    this[webidl.brand] = webidl.brand;
  }

  get timeOrigin() {
    webidl.assertBranded(this, PerformancePrototype);
    return timeOrigin;
  }

  clearMarks(markName = undefined) {
    webidl.assertBranded(this, PerformancePrototype);
    if (markName !== undefined) {
      markName = webidl.converters.DOMString(
        markName,
        "Failed to execute 'clearMarks' on 'Performance'",
        "Argument 1",
      );

      performanceEntries = ArrayPrototypeFilter(
        performanceEntries,
        (entry) => !(entry.name === markName && entry.entryType === "mark"),
      );
    } else {
      performanceEntries = ArrayPrototypeFilter(
        performanceEntries,
        (entry) => entry.entryType !== "mark",
      );
    }
  }

  clearMeasures(measureName = undefined) {
    webidl.assertBranded(this, PerformancePrototype);
    if (measureName !== undefined) {
      measureName = webidl.converters.DOMString(
        measureName,
        "Failed to execute 'clearMeasures' on 'Performance'",
        "Argument 1",
      );

      performanceEntries = ArrayPrototypeFilter(
        performanceEntries,
        (entry) =>
          !(entry.name === measureName && entry.entryType === "measure"),
      );
    } else {
      performanceEntries = ArrayPrototypeFilter(
        performanceEntries,
        (entry) => entry.entryType !== "measure",
      );
    }
  }

  clearResourceTimings() {
    webidl.assertBranded(this, PerformancePrototype);
    performanceEntries = ArrayPrototypeFilter(
      performanceEntries,
      (entry) => entry.entryType !== "resource",
    );
  }

  setResourceTimingBufferSize(_maxSize) {
    webidl.assertBranded(this, PerformancePrototype);
    webidl.requiredArguments(
      arguments.length,
      1,
      "Failed to execute 'setResourceTimingBufferSize' on 'Performance'",
    );
    // This is a noop in Deno as we don't have resource timing entries
  }

  getEntries() {
    webidl.assertBranded(this, PerformancePrototype);
    return filterByNameType();
  }

  getEntriesByName(
    name,
    type = undefined,
  ) {
    webidl.assertBranded(this, PerformancePrototype);
    const prefix = "Failed to execute 'getEntriesByName' on 'Performance'";
    webidl.requiredArguments(arguments.length, 1, prefix);

    name = webidl.converters.DOMString(name, prefix, "Argument 1");

    if (type !== undefined) {
      type = webidl.converters.DOMString(type, prefix, "Argument 2");
    }

    return filterByNameType(name, type);
  }

  getEntriesByType(type) {
    webidl.assertBranded(this, PerformancePrototype);
    const prefix = "Failed to execute 'getEntriesByName' on 'Performance'";
    webidl.requiredArguments(arguments.length, 1, prefix);

    type = webidl.converters.DOMString(type, prefix, "Argument 1");

    return filterByNameType(undefined, type);
  }

  mark(
    markName,
    markOptions = { __proto__: null },
  ) {
    webidl.assertBranded(this, PerformancePrototype);
    const prefix = "Failed to execute 'mark' on 'Performance'";
    webidl.requiredArguments(arguments.length, 1, prefix);

    markName = webidl.converters.DOMString(markName, prefix, "Argument 1");

    markOptions = webidl.converters.PerformanceMarkOptions(
      markOptions,
      prefix,
      "Argument 2",
    );

    // 3.1.1.1 If the global object is a Window object and markName uses the
    // same name as a read only attribute in the PerformanceTiming interface,
    // throw a SyntaxError. - not implemented
    const entry = new PerformanceMark(markName, markOptions);
    ArrayPrototypePush(performanceEntries, entry);
    queuePerformanceEntry(entry);
    return entry;
  }

  measure(
    measureName,
    startOrMeasureOptions = { __proto__: null },
    endMark = undefined,
  ) {
    webidl.assertBranded(this, PerformancePrototype);
    const prefix = "Failed to execute 'measure' on 'Performance'";
    webidl.requiredArguments(arguments.length, 1, prefix);

    measureName = webidl.converters.DOMString(
      measureName,
      prefix,
      "Argument 1",
    );

    startOrMeasureOptions = webidl.converters
      ["DOMString or PerformanceMeasureOptions"](
        startOrMeasureOptions,
        prefix,
        "Argument 2",
      );

    if (endMark !== undefined) {
      endMark = webidl.converters.DOMString(endMark, prefix, "Argument 3");
    }

    if (
      startOrMeasureOptions && typeof startOrMeasureOptions === "object" &&
      ObjectKeys(startOrMeasureOptions).length > 0
    ) {
      if (endMark) {
        throw new TypeError('Options cannot be passed with "endMark"');
      }
      if (
        ReflectHas(startOrMeasureOptions, "start") &&
        ReflectHas(startOrMeasureOptions, "duration") &&
        ReflectHas(startOrMeasureOptions, "end")
      ) {
        throw new TypeError(
          'Cannot specify "start", "end", and "duration" together in options',
        );
      }
    }
    let endTime;
    if (endMark) {
      endTime = convertMarkToTimestamp(endMark);
    } else if (
      typeof startOrMeasureOptions === "object" &&
      ReflectHas(startOrMeasureOptions, "end")
    ) {
      endTime = convertMarkToTimestamp(startOrMeasureOptions.end);
    } else if (
      typeof startOrMeasureOptions === "object" &&
      ReflectHas(startOrMeasureOptions, "start") &&
      ReflectHas(startOrMeasureOptions, "duration")
    ) {
      const start = convertMarkToTimestamp(startOrMeasureOptions.start);
      const duration = convertMarkToTimestamp(startOrMeasureOptions.duration);
      endTime = start + duration;
    } else {
      endTime = now();
    }
    let startTime;
    if (
      typeof startOrMeasureOptions === "object" &&
      ReflectHas(startOrMeasureOptions, "start")
    ) {
      startTime = convertMarkToTimestamp(startOrMeasureOptions.start);
    } else if (
      typeof startOrMeasureOptions === "object" &&
      ReflectHas(startOrMeasureOptions, "end") &&
      ReflectHas(startOrMeasureOptions, "duration")
    ) {
      const end = convertMarkToTimestamp(startOrMeasureOptions.end);
      const duration = convertMarkToTimestamp(startOrMeasureOptions.duration);
      startTime = end - duration;
    } else if (typeof startOrMeasureOptions === "string") {
      startTime = convertMarkToTimestamp(startOrMeasureOptions);
    } else {
      startTime = 0;
    }
    const entry = new PerformanceMeasure(
      measureName,
      startTime,
      endTime - startTime,
      typeof startOrMeasureOptions === "object"
        ? startOrMeasureOptions.detail ?? null
        : null,
      illegalConstructorKey,
    );
    ArrayPrototypePush(performanceEntries, entry);
    queuePerformanceEntry(entry);
    return entry;
  }

  markResourceTiming(
    timingInfo,
    requestedUrl,
    initiatorType,
    global,
    cacheMode,
    bodyInfo,
    responseStatus,
    deliveryType = "",
  ) {
    webidl.assertBranded(this, PerformancePrototype);
    return markResourceTiming(
      timingInfo,
      requestedUrl,
      initiatorType,
      global,
      cacheMode,
      bodyInfo,
      responseStatus,
      deliveryType,
    );
  }

  now() {
    webidl.assertBranded(this, PerformancePrototype);
    return now();
  }

  toJSON() {
    webidl.assertBranded(this, PerformancePrototype);
    return {
      timeOrigin: this.timeOrigin,
    };
  }

  [SymbolFor("Deno.privateCustomInspect")](inspect, inspectOptions) {
    return inspect(
      createFilteredInspectProxy({
        object: this,
        evaluate: ObjectPrototypeIsPrototypeOf(PerformancePrototype, this),
        keys: ["timeOrigin"],
      }),
      inspectOptions,
    );
  }
}
webidl.configureInterface(Performance);
const PerformancePrototype = Performance.prototype;

webidl.converters["Performance"] = webidl.createInterfaceConverter(
  "Performance",
  PerformancePrototype,
);

const performance = new Performance(illegalConstructorKey);

export {
  Performance,
  performance,
  PerformanceEntry,
  PerformanceMark,
  PerformanceMeasure,
  PerformanceObserver,
  PerformanceObserverEntryList,
  PerformanceResourceTiming,
  setTimeOrigin,
};
