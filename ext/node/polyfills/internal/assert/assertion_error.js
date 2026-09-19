// Copyright 2018-2026 the Deno authors. MIT license.
// Copyright Node.js contributors. All rights reserved. MIT License.

(function () {
const { core, primordials } = __bootstrap;
const { inspect } = core.loadExtScript(
  "ext:deno_node/internal/util/inspect.mjs",
);
const { isError, removeColors } = core.loadExtScript(
  "ext:deno_node/internal/util.mjs",
);
const { isErrorStackTraceLimitWritable } = core.loadExtScript(
  "ext:deno_node/internal/errors.ts",
);
const colors = core.loadExtScript("ext:deno_node/internal/util/colors.ts");
const { myersDiff, printMyersDiff, printSimpleMyersDiff } = core
  .loadExtScript(
    "ext:deno_node/internal/assert/myers_diff.js",
  );
const { validateObject } = core.loadExtScript(
  "ext:deno_node/internal/validators.mjs",
);
const io = core.loadExtScript("ext:deno_io/12_io.js");
const { op_node_assertion_error_uses_myers_diff } = core.ops;

function getConsoleWidth() {
  try {
    return Deno.consoleSize().columns;
  } catch {
    return 80;
  }
}

const {
  ArrayPrototypeIncludes,
  ArrayPrototypeJoin,
  ArrayPrototypePop,
  ArrayPrototypeSlice,
  Error,
  ErrorCaptureStackTrace,
  ErrorPrototype,
  MathMax,
  ObjectAssign,
  ObjectDefineProperty,
  ObjectGetPrototypeOf,
  ObjectPrototypeHasOwnProperty,
  ObjectPrototypeIsPrototypeOf,
  ReflectGet,
  ReflectHas,
  ReflectSet,
  String,
  StringPrototypeRepeat,
  StringPrototypeEndsWith,
  StringPrototypeSlice,
  StringPrototypeSplit,
} = primordials;

const kReadableOperator = {
  deepStrictEqual: "Expected values to be strictly deep-equal:",
  partialDeepStrictEqual:
    "Expected values to be partially and strictly deep-equal:",
  strictEqual: "Expected values to be strictly equal:",
  strictEqualObject: 'Expected "actual" to be reference-equal to "expected":',
  deepEqual: "Expected values to be loosely deep-equal:",
  notDeepStrictEqual: 'Expected "actual" not to be strictly deep-equal to:',
  notStrictEqual: 'Expected "actual" to be strictly unequal to:',
  notStrictEqualObject:
    'Expected "actual" not to be reference-equal to "expected":',
  notDeepEqual: 'Expected "actual" not to be loosely deep-equal to:',
  notIdentical: "Values have same structure but are not reference-equal:",
  notDeepEqualUnequal: "Expected values not to be loosely deep-equal:",
};

const kMaxShortStringLength = 12;
const kMaxLongStringLength = 512;

const kMethodsWithCustomMessageDiff = [
  "deepStrictEqual",
  "strictEqual",
  "partialDeepStrictEqual",
];
// Node.js 20 has no `partialDeepStrictEqual`.
const kMethodsWithCustomMessageLineDiff = ["deepStrictEqual", "strictEqual"];

function copyError(source, copyCause) {
  const target = ObjectAssign(
    { __proto__: ObjectGetPrototypeOf(source) },
    source,
  );
  ObjectDefineProperty(target, "message", {
    __proto__: null,
    value: source.message,
  });
  // Node.js 20 does not copy the `cause`.
  if (copyCause && ObjectPrototypeHasOwnProperty(source, "cause")) {
    let { cause } = source;

    if (isError(cause)) {
      cause = copyError(cause, copyCause);
    }

    ObjectDefineProperty(target, "cause", { __proto__: null, value: cause });
  }
  return target;
}

function inspectValue(val) {
  // The util.inspect default values could be changed. This makes sure the
  // error messages contain the necessary information nevertheless.
  return inspect(val, {
    compact: false,
    customInspect: false,
    depth: 1000,
    maxArrayLength: Infinity,
    // Assert compares only enumerable properties (with a few exceptions).
    showHidden: false,
    // Assert does not detect proxies currently.
    showProxy: false,
    sorted: true,
    // Inspect getters as we also check them when comparing entries.
    getters: true,
  });
}

function getErrorMessage(operator, message) {
  return message || kReadableOperator[operator];
}

function checkOperator(actual, expected, operator) {
  // In case both values are objects or functions explicitly mark them as not
  // reference equal for the `strictEqual` operator.
  if (
    operator === "strictEqual" &&
    ((typeof actual === "object" &&
      actual !== null &&
      typeof expected === "object" &&
      expected !== null) ||
      (typeof actual === "function" && typeof expected === "function"))
  ) {
    operator = "strictEqualObject";
  }

  return operator;
}

function getColoredMyersDiff(actual, expected) {
  const header =
    `${colors.green}actual${colors.white} ${colors.red}expected${colors.white}`;
  const skipped = false;

  const diff = myersDiff(
    StringPrototypeSplit(actual, ""),
    StringPrototypeSplit(expected, ""),
  );
  let message = printSimpleMyersDiff(diff);

  if (skipped) {
    message += "...";
  }

  return { message, header, skipped };
}

function getStackedDiff(actual, expected) {
  const isStringComparison = typeof actual === "string" &&
    typeof expected === "string";

  let message =
    `\n${colors.green}+${colors.white} ${actual}\n${colors.red}- ${colors.white}${expected}`;
  const stringsLen = actual.length + expected.length;
  const maxTerminalLength = io.stderr.isTerminal() ? getConsoleWidth() : 80;
  const showIndicator = isStringComparison &&
    (stringsLen <= maxTerminalLength);

  if (showIndicator) {
    let indicatorIdx = -1;

    for (let i = 0; i < actual.length; i++) {
      if (actual[i] !== expected[i]) {
        // Skip the indicator for the first 2 characters because the diff is immediately apparent
        // It is 3 instead of 2 to account for the quotes
        if (i >= 3) {
          indicatorIdx = i;
        }
        break;
      }
    }

    if (indicatorIdx !== -1) {
      message += `\n${StringPrototypeRepeat(" ", indicatorIdx + 2)}^`;
    }
  }

  return { message };
}

function getSimpleDiff(originalActual, actual, originalExpected, expected) {
  let stringsLen = actual.length + expected.length;
  // Accounting for the quotes wrapping strings
  if (typeof originalActual === "string") {
    stringsLen -= 2;
  }
  if (typeof originalExpected === "string") {
    stringsLen -= 2;
  }
  if (
    stringsLen <= kMaxShortStringLength &&
    (originalActual !== 0 || originalExpected !== 0)
  ) {
    return { message: `${actual} !== ${expected}`, header: "" };
  }

  const isStringComparison = typeof originalActual === "string" &&
    typeof originalExpected === "string";
  // colored myers diff
  if (isStringComparison && colors.hasColors) {
    return getColoredMyersDiff(actual, expected);
  }

  return getStackedDiff(actual, expected);
}

function isSimpleDiff(actual, inspectedActual, expected, inspectedExpected) {
  if (inspectedActual.length > 1 || inspectedExpected.length > 1) {
    return false;
  }

  return typeof actual !== "object" || actual === null ||
    typeof expected !== "object" || expected === null;
}

function createErrDiff(
  actual,
  expected,
  operator,
  customMessage,
  diffType = "simple",
) {
  operator = checkOperator(actual, expected, operator);

  let skipped = false;
  let message = "";
  const inspectedActual = inspectValue(actual);
  const inspectedExpected = inspectValue(expected);
  const inspectedSplitActual = StringPrototypeSplit(inspectedActual, "\n");
  const inspectedSplitExpected = StringPrototypeSplit(
    inspectedExpected,
    "\n",
  );
  const showSimpleDiff = isSimpleDiff(
    actual,
    inspectedSplitActual,
    expected,
    inspectedSplitExpected,
  );
  let header =
    `${colors.green}+ actual${colors.white} ${colors.red}- expected${colors.white}`;

  if (showSimpleDiff) {
    const simpleDiff = getSimpleDiff(
      actual,
      inspectedSplitActual[0],
      expected,
      inspectedSplitExpected[0],
    );
    message = simpleDiff.message;
    if (typeof simpleDiff.header !== "undefined") {
      header = simpleDiff.header;
    }
    if (simpleDiff.skipped) {
      skipped = true;
    }
  } else if (inspectedActual === inspectedExpected) {
    // Handles the case where the objects are structurally the same but different references
    operator = "notIdentical";
    if (inspectedSplitActual.length > 50 && diffType !== "full") {
      message = `${
        ArrayPrototypeJoin(
          ArrayPrototypeSlice(inspectedSplitActual, 0, 50),
          "\n",
        )
      }\n...}`;
      skipped = true;
    } else {
      message = ArrayPrototypeJoin(inspectedSplitActual, "\n");
    }
    header = "";
  } else {
    const checkCommaDisparity = actual != null && typeof actual === "object";
    const diff = myersDiff(
      inspectedSplitActual,
      inspectedSplitExpected,
      checkCommaDisparity,
    );

    const myersDiffMessage = printMyersDiff(diff, operator);
    message = myersDiffMessage.message;

    if (operator === "partialDeepStrictEqual") {
      header = `${colors.gray}${
        colors.hasColors ? "" : "+ "
      }actual${colors.white} ${colors.red}- expected${colors.white}`;
    }

    if (myersDiffMessage.skipped) {
      skipped = true;
    }
  }

  const headerMessage = `${
    getErrorMessage(operator, customMessage)
  }\n${header}`;
  const skippedMessage = skipped ? "\n... Skipped lines" : "";

  return `${headerMessage}${skippedMessage}\n${message}\n`;
}

// Node.js 20 compares the inspected lines of both values position by
// position. Node.js 22.12 and later use the Myers diff algorithm
// (nodejs/node#54862). This is the Node.js 20.20 implementation.
function createLineErrDiff(actual, expected, operator, message = "") {
  let other = "";
  let res = "";
  let end = "";
  let skipped = false;
  const actualInspected = inspectValue(actual);
  const actualLines = StringPrototypeSplit(actualInspected, "\n");
  const expectedLines = StringPrototypeSplit(inspectValue(expected), "\n");

  let i = 0;
  let indicator = "";

  operator = checkOperator(actual, expected, operator);

  // If "actual" and "expected" fit on a single line and they are not strictly
  // equal, check further special handling.
  if (
    actualLines.length === 1 && expectedLines.length === 1 &&
    actualLines[0] !== expectedLines[0]
  ) {
    // Check for the visible length using the `removeColors()` function, if
    // appropriate.
    const c = inspect.defaultOptions.colors;
    const actualRaw = c ? removeColors(actualLines[0]) : actualLines[0];
    const expectedRaw = c ? removeColors(expectedLines[0]) : expectedLines[0];
    const inputLength = actualRaw.length + expectedRaw.length;
    // If the character length of "actual" and "expected" together is less than
    // kMaxShortStringLength and if neither is an object and at least one of
    // them is not `zero`, use the strict equal comparison to visualize the
    // output.
    if (inputLength <= kMaxShortStringLength) {
      if (
        (typeof actual !== "object" || actual === null) &&
        (typeof expected !== "object" || expected === null) &&
        (actual !== 0 || expected !== 0)
      ) { // -0 === +0
        return `${getErrorMessage(operator, message)}\n\n` +
          `${actualLines[0]} !== ${expectedLines[0]}\n`;
      }
    } else if (operator !== "strictEqualObject") {
      // If the stderr is a tty and the input length is lower than the current
      // columns per line, add a mismatch indicator below the output. If it is
      // not a tty, use a default value of 80 characters.
      const maxLength = io.stderr.isTerminal() ? getConsoleWidth() : 80;
      if (inputLength < maxLength) {
        while (actualRaw[i] === expectedRaw[i]) {
          i++;
        }
        // Ignore the first characters.
        if (i > 2) {
          // Add position indicator for the first mismatch in case it is a
          // single line and the input length is less than the column length.
          indicator = `\n  ${StringPrototypeRepeat(" ", i)}^`;
          i = 0;
        }
      }
    }
  }

  // Remove all ending lines that match (this optimizes the output for
  // readability by reducing the number of total changed lines).
  let a = actualLines[actualLines.length - 1];
  let b = expectedLines[expectedLines.length - 1];
  while (a === b) {
    if (i++ < 3) {
      end = `\n  ${a}${end}`;
    } else {
      other = a;
    }
    ArrayPrototypePop(actualLines);
    ArrayPrototypePop(expectedLines);
    if (actualLines.length === 0 || expectedLines.length === 0) {
      break;
    }
    a = actualLines[actualLines.length - 1];
    b = expectedLines[expectedLines.length - 1];
  }

  const maxLines = MathMax(actualLines.length, expectedLines.length);
  // Strict equal with identical objects that are not identical by reference.
  // E.g., assert.deepStrictEqual({ a: Symbol() }, { a: Symbol() })
  if (maxLines === 0) {
    // We have to get the result again. The lines were all removed before.
    const actualLines = StringPrototypeSplit(actualInspected, "\n");

    // Only remove lines in case it makes sense to collapse those.
    if (actualLines.length > 50) {
      actualLines[46] = `${colors.blue}...${colors.white}`;
      while (actualLines.length > 47) {
        ArrayPrototypePop(actualLines);
      }
    }

    return `${kReadableOperator.notIdentical}\n\n` +
      `${ArrayPrototypeJoin(actualLines, "\n")}\n`;
  }

  // There were at least five identical lines at the end. Mark a couple of
  // skipped.
  if (i >= 5) {
    end = `\n${colors.blue}...${colors.white}${end}`;
    skipped = true;
  }
  if (other !== "") {
    end = `\n  ${other}${end}`;
    other = "";
  }

  let printedLines = 0;
  let identical = 0;
  const msg = `${
    getErrorMessage(operator, message)
  }\n${colors.green}+ actual${colors.white} ${colors.red}- expected${colors.white}`;
  const skippedMsg = ` ${colors.blue}...${colors.white} Lines skipped`;

  let lines = actualLines;
  let plusMinus = `${colors.green}+${colors.white}`;
  let maxLength = expectedLines.length;
  if (actualLines.length < maxLines) {
    lines = expectedLines;
    plusMinus = `${colors.red}-${colors.white}`;
    maxLength = actualLines.length;
  }

  for (i = 0; i < maxLines; i++) {
    if (maxLength < i + 1) {
      // If more than two former lines are identical, print them. Collapse them
      // in case more than five lines were identical.
      if (identical > 2) {
        if (identical > 3) {
          if (identical > 4) {
            if (identical === 5) {
              res += `\n  ${lines[i - 3]}`;
              printedLines++;
            } else {
              res += `\n${colors.blue}...${colors.white}`;
              skipped = true;
            }
          }
          res += `\n  ${lines[i - 2]}`;
          printedLines++;
        }
        res += `\n  ${lines[i - 1]}`;
        printedLines++;
      }
      // No identical lines before.
      identical = 0;
      // Add the expected line to the cache.
      if (lines === actualLines) {
        res += `\n${plusMinus} ${lines[i]}`;
      } else {
        other += `\n${plusMinus} ${lines[i]}`;
      }
      printedLines++;
      // Only extra actual lines exist
      // Lines diverge
    } else {
      const expectedLine = expectedLines[i];
      let actualLine = actualLines[i];
      // If the lines diverge, specifically check for lines that only diverge by
      // a trailing comma. In that case it is actually identical and we should
      // mark it as such.
      let divergingLines = actualLine !== expectedLine &&
        (!StringPrototypeEndsWith(actualLine, ",") ||
          StringPrototypeSlice(actualLine, 0, -1) !== expectedLine);
      // If the expected line has a trailing comma but is otherwise identical,
      // add a comma at the end of the actual line. Otherwise the output could
      // look weird as in:
      //
      //   [
      //     1         // No comma at the end!
      // +   2
      //   ]
      //
      if (
        divergingLines &&
        StringPrototypeEndsWith(expectedLine, ",") &&
        StringPrototypeSlice(expectedLine, 0, -1) === actualLine
      ) {
        divergingLines = false;
        actualLine += ",";
      }
      if (divergingLines) {
        // If more than two former lines are identical, print them. Collapse
        // them in case more than five lines were identical.
        if (identical > 2) {
          if (identical > 3) {
            if (identical > 4) {
              if (identical === 5) {
                res += `\n  ${actualLines[i - 3]}`;
                printedLines++;
              } else {
                res += `\n${colors.blue}...${colors.white}`;
                skipped = true;
              }
            }
            res += `\n  ${actualLines[i - 2]}`;
            printedLines++;
          }
          res += `\n  ${actualLines[i - 1]}`;
          printedLines++;
        }
        // No identical lines before.
        identical = 0;
        // Add the actual line to the result and cache the expected diverging
        // line so consecutive diverging lines show up as +++--- and not +-+-+-.
        res += `\n${colors.green}+${colors.white} ${actualLine}`;
        other += `\n${colors.red}-${colors.white} ${expectedLine}`;
        printedLines += 2;
        // Lines are identical
      } else {
        // Add all cached information to the result before adding other things
        // and reset the cache.
        res += other;
        other = "";
        identical++;
        // The very first identical line since the last diverging line is be
        // added to the result.
        if (identical <= 2) {
          res += `\n  ${actualLine}`;
          printedLines++;
        }
      }
    }
    // Inspected object to big (Show ~50 rows max)
    if (printedLines > 50 && i < maxLines - 2) {
      return `${msg}${skippedMsg}\n${res}\n${colors.blue}...${colors.white}${other}\n` +
        `${colors.blue}...${colors.white}`;
    }
  }

  return `${msg}${skipped ? skippedMsg : ""}\n${res}${other}${end}${indicator}`;
}

function addEllipsis(string) {
  const lines = StringPrototypeSplit(string, "\n", 11);
  if (lines.length > 10) {
    lines.length = 10;
    return `${ArrayPrototypeJoin(lines, "\n")}\n...`;
  } else if (string.length > kMaxLongStringLength) {
    return `${StringPrototypeSlice(string, kMaxLongStringLength)}...`;
  }
  return string;
}

class AssertionError extends Error {
  // deno-lint-ignore constructor-super
  constructor(options) {
    validateObject(options, "options");
    const {
      message,
      operator,
      stackStartFn,
      details,
      // Compatibility with older versions.
      stackStartFunction,
    } = options;
    // Node.js 20 has no `diff` option and always shortens the message.
    const usesMyersDiff = op_node_assertion_error_uses_myers_diff();
    let diff = "simple";
    if (usesMyersDiff && options.diff !== undefined) {
      diff = options.diff;
    }
    const createDiff = usesMyersDiff ? createErrDiff : createLineErrDiff;
    const methodsWithCustomMessageDiff = usesMyersDiff
      ? kMethodsWithCustomMessageDiff
      : kMethodsWithCustomMessageLineDiff;
    let {
      actual,
      expected,
    } = options;

    const limit = ReflectGet(Error, "stackTraceLimit");
    if (isErrorStackTraceLimitWritable()) {
      ReflectSet(Error, "stackTraceLimit", 0);
    }

    if (message != null) {
      if (ArrayPrototypeIncludes(methodsWithCustomMessageDiff, operator)) {
        super(createDiff(actual, expected, operator, message, diff));
      } else {
        super(String(message));
      }
    } else {
      // Reset colors on each call to make sure we handle dynamically set environment
      // variables correct.
      colors.refresh();
      // Prevent the error stack from being visible by duplicating the error
      // in a very close way to the original in case both sides are actually
      // instances of Error.
      if (
        typeof actual === "object" && actual !== null &&
        typeof expected === "object" && expected !== null &&
        ReflectHas(actual, "stack") &&
        ObjectPrototypeIsPrototypeOf(ErrorPrototype, actual) &&
        ReflectHas(expected, "stack") &&
        ObjectPrototypeIsPrototypeOf(ErrorPrototype, expected)
      ) {
        actual = copyError(actual, usesMyersDiff);
        expected = copyError(expected, usesMyersDiff);
      }

      if (ArrayPrototypeIncludes(methodsWithCustomMessageDiff, operator)) {
        super(createDiff(actual, expected, operator, message, diff));
      } else if (
        operator === "notDeepStrictEqual" ||
        operator === "notStrictEqual"
      ) {
        // In case the objects are equal but the operator requires unequal, show
        // the first object and say A equals B
        let base = kReadableOperator[operator];
        const res = StringPrototypeSplit(inspectValue(actual), "\n");

        // In case "actual" is an object or a function, it should not be
        // reference equal.
        if (
          operator === "notStrictEqual" &&
          ((typeof actual === "object" && actual !== null) ||
            typeof actual === "function")
        ) {
          base = kReadableOperator.notStrictEqualObject;
        }

        // Only remove lines in case it makes sense to collapse those.
        if (res.length > 50 && diff !== "full") {
          res[46] = `${colors.blue}...${colors.white}`;
          while (res.length > 47) {
            ArrayPrototypePop(res);
          }
        }

        // Only print a single input.
        if (res.length === 1) {
          super(`${base}${res[0].length > 5 ? "\n\n" : " "}${res[0]}`);
        } else {
          super(`${base}\n\n${ArrayPrototypeJoin(res, "\n")}\n`);
        }
      } else {
        let res = inspectValue(actual);
        let other = inspectValue(expected);
        const knownOperator = kReadableOperator[operator];
        if (operator === "notDeepEqual" && res === other) {
          res = `${knownOperator}\n\n${res}`;
          if (res.length > 1024 && diff !== "full") {
            res = `${StringPrototypeSlice(res, 0, 1021)}...`;
          }
          super(res);
        } else {
          if (res.length > kMaxLongStringLength && diff !== "full") {
            res = `${StringPrototypeSlice(res, 0, 509)}...`;
          }
          if (other.length > kMaxLongStringLength && diff !== "full") {
            other = `${StringPrototypeSlice(other, 0, 509)}...`;
          }
          if (operator === "deepEqual") {
            res = `${knownOperator}\n\n${res}\n\nshould loosely deep-equal\n\n`;
          } else {
            const newOp = kReadableOperator[`${operator}Unequal`];
            if (newOp) {
              res = `${newOp}\n\n${res}\n\nshould not loosely deep-equal\n\n`;
            } else {
              other = ` ${operator} ${other}`;
            }
          }
          super(`${res}${other}`);
        }
      }
    }

    if (isErrorStackTraceLimitWritable()) {
      ReflectSet(Error, "stackTraceLimit", limit);
    }

    this.generatedMessage = !message;
    ObjectDefineProperty(this, "name", {
      __proto__: null,
      value: "AssertionError [ERR_ASSERTION]",
      enumerable: false,
      writable: true,
      configurable: true,
    });
    this.code = "ERR_ASSERTION";
    if (details) {
      this.actual = undefined;
      this.expected = undefined;
      this.operator = undefined;
      for (let i = 0; i < details.length; i++) {
        this["message " + i] = details[i].message;
        this["actual " + i] = details[i].actual;
        this["expected " + i] = details[i].expected;
        this["operator " + i] = details[i].operator;
        this["stack trace " + i] = details[i].stack;
      }
    } else {
      this.actual = actual;
      this.expected = expected;
      this.operator = operator;
    }
    ErrorCaptureStackTrace(this, stackStartFn || stackStartFunction);
    // Create error message including the error code in the name.
    this.stack; // eslint-disable-line no-unused-expressions
    // Reset the name.
    this.name = "AssertionError";
    if (usesMyersDiff) {
      this.diff = diff;
    }
  }

  toString() {
    return `${this.name} [${this.code}]: ${this.message}`;
  }

  [inspect.custom](_recurseTimes, ctx) {
    // Long strings should not be fully inspected.
    const tmpActual = this.actual;
    const tmpExpected = this.expected;

    if (typeof this.actual === "string") {
      this.actual = addEllipsis(this.actual);
    }
    if (typeof this.expected === "string") {
      this.expected = addEllipsis(this.expected);
    }

    // This limits the `actual` and `expected` property default inspection to
    // the minimum depth. Otherwise those values would be too verbose compared
    // to the actual error message which contains a combined view of these two
    // input values.
    const result = inspect(this, {
      ...ctx,
      customInspect: false,
      depth: 0,
    });

    // Reset the properties after inspection.
    this.actual = tmpActual;
    this.expected = tmpExpected;

    return result;
  }
}

return {
  AssertionError,
  default: AssertionError,
};
})();
