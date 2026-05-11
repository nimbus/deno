// Copyright 2018-2026 the Deno authors. MIT license.
// Copyright Node.js contributors. All rights reserved. MIT License.

import { op_node_fs_seek_sync } from "ext:core/ops";
import { primordials } from "ext:core/mod.js";
const {
  ArrayPrototypeForEach,
  ArrayPrototypeMap,
  ArrayPrototypePush,
  FunctionPrototypeBind,
  ObjectEntries,
  ObjectPrototypeToString,
  String,
  Symbol,
} = primordials;

import {
  ERR_WASI_ALREADY_STARTED,
  codes,
  genericNodeError,
  hideStackFrames,
} from "ext:deno_node/internal/errors.ts";
import { kEmptyObject } from "ext:deno_node/internal/util.mjs";
import {
  validateArray,
  validateBoolean,
  validateFunction,
  validateInt32,
  validateObject,
  validateString,
} from "ext:deno_node/internal/validators.mjs";
import { Buffer } from "node:buffer";
import {
  closeSync,
  constants as fsConstants,
  fstatSync,
  futimesSync,
  lstatSync,
  mkdirSync,
  openSync,
  readSync,
  readdirSync,
  rmdirSync,
  statSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import {
  dirname,
  join as joinPath,
  sep as pathSeparator,
} from "node:path";
import process from "node:process";

const kExitCode = Symbol("kExitCode");
const kSetMemory = Symbol("kSetMemory");
const kStarted = Symbol("kStarted");
const kInstance = Symbol("kInstance");
const kBindingName = Symbol("kBindingName");
const kMemory = Symbol("kMemory");
const kArgs = Symbol("kArgs");
const kEnv = Symbol("kEnv");
const kStdio = Symbol("kStdio");
const kFdPositions = Symbol("kFdPositions");
const kClosedFds = Symbol("kClosedFds");
const kFdTable = Symbol("kFdTable");
const kNextFd = Symbol("kNextFd");

const WASI_ESUCCESS = 0;
const WASI_EBADF = 8;
const WASI_EEXIST = 20;
const WASI_EINVAL = 28;
const WASI_EIO = 29;
const WASI_EISDIR = 31;
const WASI_ENOENT = 44;
const WASI_ENOTDIR = 54;
const WASI_ESPIPE = 70;
const WASI_ENOTCAPABLE = 76;
const WASI_FILETYPE_UNKNOWN = 0;
const WASI_FILETYPE_CHARACTER_DEVICE = 2;
const WASI_FILETYPE_DIRECTORY = 3;
const WASI_FILETYPE_REGULAR_FILE = 4;
const WASI_PREOPENTYPE_DIR = 0;
const WASI_DIRCOOKIE_START = 0n;
const WASI_FDFLAG_APPEND = 1 << 0;
const WASI_FILESTAT_SET_ATIM = 1 << 0;
const WASI_FILESTAT_SET_ATIM_NOW = 1 << 1;
const WASI_FILESTAT_SET_MTIM = 1 << 2;
const WASI_FILESTAT_SET_MTIM_NOW = 1 << 3;
const WASI_O_CREAT = 1 << 0;
const WASI_O_DIRECTORY = 1 << 1;
const WASI_O_EXCL = 1 << 2;
const WASI_O_TRUNC = 1 << 3;
const WASI_LOOKUP_SYMLINK_FOLLOW = 1 << 0;
const WASI_RIGHT_FD_READ = 1 << 1;
const WASI_RIGHT_FD_SEEK = 1 << 2;
const WASI_RIGHT_FD_FDSTAT_SET_FLAGS = 1 << 3;
const WASI_RIGHT_FD_TELL = 1 << 5;
const WASI_RIGHT_FD_WRITE = 1 << 6;
const WASI_RIGHT_PATH_CREATE_DIRECTORY = 1 << 9;
const WASI_RIGHT_PATH_CREATE_FILE = 1 << 10;
const WASI_RIGHT_PATH_OPEN = 1 << 13;
const WASI_RIGHT_FD_READDIR = 1 << 14;
const WASI_RIGHT_PATH_FILESTAT_GET = 1 << 18;
const WASI_RIGHT_FD_FILESTAT_GET = 1 << 21;
const WASI_RIGHT_FD_FILESTAT_SET_TIMES = 1 << 23;
const WASI_RIGHT_PATH_REMOVE_DIRECTORY = 1 << 25;
const WASI_RIGHT_PATH_UNLINK_FILE = 1 << 26;
const WASI_WHENCE_SET = 0;
const WASI_WHENCE_CUR = 1;
const WASI_WHENCE_END = 2;
const WASI_PRESTAT_SIZE = 8;
const WASI_DIRENT_SIZE = 24;
const WASI_FDSTAT_SIZE = 24;
const WASI_FILESTAT_SIZE = 64;

const DEFAULT_WASI_FILE_RIGHTS =
  BigInt(WASI_RIGHT_FD_READ) |
  BigInt(WASI_RIGHT_FD_SEEK) |
  BigInt(WASI_RIGHT_FD_FDSTAT_SET_FLAGS) |
  BigInt(WASI_RIGHT_FD_TELL) |
  BigInt(WASI_RIGHT_FD_WRITE) |
  BigInt(WASI_RIGHT_FD_FILESTAT_GET) |
  BigInt(WASI_RIGHT_FD_FILESTAT_SET_TIMES);

const DEFAULT_WASI_DIRECTORY_BASE_RIGHTS =
  BigInt(WASI_RIGHT_PATH_CREATE_DIRECTORY) |
  BigInt(WASI_RIGHT_PATH_CREATE_FILE) |
  BigInt(WASI_RIGHT_PATH_OPEN) |
  BigInt(WASI_RIGHT_FD_READDIR) |
  BigInt(WASI_RIGHT_PATH_FILESTAT_GET) |
  BigInt(WASI_RIGHT_PATH_REMOVE_DIRECTORY) |
  BigInt(WASI_RIGHT_PATH_UNLINK_FILE);

const DEFAULT_WASI_DIRECTORY_INHERITING_RIGHTS =
  DEFAULT_WASI_FILE_RIGHTS | BigInt(WASI_RIGHT_FD_READDIR);

type WasiFdEntry = {
  kind: "file" | "dir" | "preopen";
  hostPath: string;
  virtualPath: string;
  flags: number;
  rightsBase?: bigint;
  rightsInheriting?: bigint;
  hostFd?: number;
};

type WasiResolvedFdEntry =
  | WasiFdEntry
  | {
    kind: "stdio";
    hostFd: number;
    hostPath: string;
    virtualPath: string;
    flags: number;
  };

function formatReceived(value: unknown): string {
  if (typeof value === "function") {
    return ` Received function ${value.name || "(anonymous)"}`;
  }
  if (value === null) {
    return " Received null";
  }
  if (value !== undefined && typeof value === "object") {
    const ctorName = value.constructor?.name;
    if (typeof ctorName === "string" && ctorName.length > 0) {
      return ` Received an instance of ${ctorName}`;
    }
  }
  return ` Received type ${typeof value}`;
}

const validateUndefined = hideStackFrames((value, name: string) => {
  if (value !== undefined) {
    throw genericNodeError(
      `The "${name}" property must be undefined.${formatReceived(value)}`,
      { code: "ERR_INVALID_ARG_TYPE" },
    );
  }
});

function isWebAssemblyMemory(value: unknown): value is WebAssembly.Memory {
  return ObjectPrototypeToString(value) === "[object WebAssembly.Memory]";
}

const validateMemory = hideStackFrames((value, name: string) => {
  if (!isWebAssemblyMemory(value)) {
    throw genericNodeError(
      `The "${name}" property must be a WebAssembly.Memory object.${
        formatReceived(value)
      }`,
      { code: "ERR_INVALID_ARG_TYPE" },
    );
  }
});

const ensurePreopenExists = hideStackFrames((path: string) => {
  try {
    Deno.statSync(path);
  } catch {
    throw genericNodeError("uvwasi_init failed", {
      code: "UVWASI_ENOENT",
    });
  }
});

function wasiNotStartedError() {
  return genericNodeError("wasi.start() has not been called", {
    code: "ERR_WASI_NOT_STARTED",
  });
}

function wasiError(code: string) {
  return Object.assign(new Error(code), { code });
}

function toWasiErrno(code: string | undefined): number {
  switch (code) {
    case "EBADF":
      return WASI_EBADF;
    case "EEXIST":
      return WASI_EEXIST;
    case "EINVAL":
      return WASI_EINVAL;
    case "EISDIR":
      return WASI_EISDIR;
    case "ENOENT":
      return WASI_ENOENT;
    case "ENOTDIR":
      return WASI_ENOTDIR;
    case "ENOTCAPABLE":
      return WASI_ENOTCAPABLE;
    case "ESPIPE":
      return WASI_ESPIPE;
    default:
      return WASI_EIO;
  }
}

function ensureStarted(wasi: WASI): WebAssembly.Memory {
  if (!wasi[kStarted] || wasi[kMemory] === undefined) {
    throw wasiNotStartedError();
  }
  return wasi[kMemory]!;
}

function getMemoryBytes(wasi: WASI): Uint8Array {
  return new Uint8Array(ensureStarted(wasi).buffer);
}

function getMemoryView(wasi: WASI): DataView {
  return new DataView(ensureStarted(wasi).buffer);
}

function resolveFdEntry(
  wasi: WASI,
  fd: number,
): WasiResolvedFdEntry | undefined {
  if (wasi[kClosedFds].has(fd)) {
    return undefined;
  }
  switch (fd) {
    case 0:
    case 1:
    case 2:
      return {
        kind: "stdio",
        hostFd: wasi[kStdio][fd],
        hostPath: "",
        virtualPath: "",
        flags: 0,
      };
    default:
      return wasi[kFdTable].get(fd);
  }
}

function fdUsesPosition(entry: WasiResolvedFdEntry): boolean {
  return entry.kind === "stdio";
}

function trackedPosition(wasi: WASI, fd: number): number {
  const existing = wasi[kFdPositions].get(fd);
  if (existing !== undefined) {
    return existing;
  }
  wasi[kFdPositions].set(fd, 0);
  return 0;
}

function getStatsForEntry(entry: WasiResolvedFdEntry) {
  if (entry.kind === "file" || entry.kind === "stdio") {
    return fstatSync(entry.hostFd);
  }
  return statSync(entry.hostPath);
}

function getStatForPath(path: string, followSymlink: boolean) {
  return followSymlink ? statSync(path) : lstatSync(path);
}

function getFdFileTypeForStats(stats): number {
  if (stats.isDirectory()) {
    return WASI_FILETYPE_DIRECTORY;
  }
  if (stats.isFile()) {
    return WASI_FILETYPE_REGULAR_FILE;
  }
  return WASI_FILETYPE_CHARACTER_DEVICE;
}

function getFdFileType(entry: WasiResolvedFdEntry): number {
  if (entry.kind === "dir" || entry.kind === "preopen") {
    return WASI_FILETYPE_DIRECTORY;
  }
  return getFdFileTypeForStats(getStatsForEntry(entry));
}

function writeUint32(wasi: WASI, ptr: number, value: number) {
  getMemoryView(wasi).setUint32(ptr, value >>> 0, true);
}

function writeUint64(wasi: WASI, ptr: number, value: bigint | number) {
  const bigintValue = typeof value === "bigint" ? value : BigInt(value);
  getMemoryView(wasi).setBigUint64(ptr, bigintValue, true);
}

function readPathString(wasi: WASI, ptr: number, len: number): string {
  return Buffer.from(getMemoryBytes(wasi).subarray(ptr, ptr + len)).toString();
}

function rightsInclude(rights: bigint | number, bit: number): boolean {
  const bigintRights = typeof rights === "bigint" ? rights : BigInt(rights);
  return (bigintRights & BigInt(bit)) !== 0n;
}

function ensureEntryIsDirectory(
  entry: WasiResolvedFdEntry | undefined,
): WasiFdEntry | WasiResolvedFdEntry {
  if (entry === undefined) {
    throw wasiError("EBADF");
  }
  if (entry.kind === "file" || entry.kind === "stdio") {
    throw wasiError("ENOTDIR");
  }
  return entry;
}

function relativeSegments(rawPath: string): string[] {
  if (rawPath.startsWith("/")) {
    throw wasiError("ENOTCAPABLE");
  }

  const segments = [];
  for (const segment of rawPath.split("/")) {
    if (segment === "" || segment === ".") {
      continue;
    }
    if (segment === "..") {
      throw wasiError("ENOTCAPABLE");
    }
    segments.push(segment);
  }
  return segments;
}

function normalizeRights(
  rights: bigint | number,
  fallback: bigint,
): bigint {
  const mappedRights = typeof rights === "bigint" ? rights : BigInt(rights);
  return mappedRights === 0n ? fallback : mappedRights;
}

function ensureWithinBase(basePath: string, targetPath: string) {
  const baseRealPath = Deno.realPathSync(basePath);
  let candidatePath = targetPath;
  try {
    candidatePath = Deno.realPathSync(targetPath);
  } catch {
    candidatePath = Deno.realPathSync(dirname(targetPath));
  }

  if (
    candidatePath === baseRealPath ||
    candidatePath.startsWith(`${baseRealPath}${pathSeparator}`)
  ) {
    return;
  }

  throw wasiError("ENOTCAPABLE");
}

function resolvePathFromFd(
  wasi: WASI,
  fd: number,
  rawPath: string,
) {
  const baseEntry = ensureEntryIsDirectory(resolveFdEntry(wasi, fd));
  const segments = relativeSegments(rawPath);
  const hostPath = segments.length === 0
    ? baseEntry.hostPath
    : joinPath(baseEntry.hostPath, ...segments);
  ensureWithinBase(baseEntry.hostPath, hostPath);
  return {
    hostPath,
    virtualPath: segments.length === 0
      ? baseEntry.virtualPath
      : `${baseEntry.virtualPath.replace(/\/+$/u, "")}/${segments.join("/")}`,
  };
}

function allocateFd(wasi: WASI, entry: WasiFdEntry): number {
  const fd = wasi[kNextFd];
  wasi[kNextFd] += 1;
  wasi[kFdTable].set(fd, entry);
  return fd;
}

function writePrestat(
  wasi: WASI,
  statPtr: number,
  virtualPath: string,
) {
  const memoryBytes = getMemoryBytes(wasi);
  memoryBytes.fill(0, statPtr, statPtr + WASI_PRESTAT_SIZE);
  getMemoryView(wasi).setUint8(statPtr, WASI_PREOPENTYPE_DIR);
  getMemoryView(wasi).setUint32(
    statPtr + 4,
    Buffer.byteLength(virtualPath),
    true,
  );
}

function writeFilestat(
  wasi: WASI,
  statPtr: number,
  stats,
  fileType: number,
) {
  const memoryBytes = getMemoryBytes(wasi);
  memoryBytes.fill(0, statPtr, statPtr + WASI_FILESTAT_SIZE);
  const memoryView = getMemoryView(wasi);
  memoryView.setBigUint64(statPtr, BigInt(stats.dev ?? 0), true);
  memoryView.setBigUint64(statPtr + 8, BigInt(stats.ino ?? 0), true);
  memoryView.setUint8(statPtr + 16, fileType);
  memoryView.setBigUint64(statPtr + 24, BigInt(stats.nlink ?? 1), true);
  memoryView.setBigUint64(statPtr + 32, BigInt(stats.size ?? 0), true);
  memoryView.setBigUint64(
    statPtr + 40,
    BigInt(Math.trunc((stats.atimeMs ?? 0) * 1_000_000)),
    true,
  );
  memoryView.setBigUint64(
    statPtr + 48,
    BigInt(Math.trunc((stats.mtimeMs ?? 0) * 1_000_000)),
    true,
  );
  memoryView.setBigUint64(
    statPtr + 56,
    BigInt(Math.trunc((stats.ctimeMs ?? 0) * 1_000_000)),
    true,
  );
}

function wasiTimestampToDate(timestamp: bigint | number): Date {
  const bigintValue = typeof timestamp === "bigint" ? timestamp : BigInt(timestamp);
  return new Date(Number(bigintValue / 1_000_000n));
}

function setEntryTimes(
  entry: WasiResolvedFdEntry,
  atim: bigint | number,
  mtim: bigint | number,
  fstFlags: number,
) {
  const currentStats = getStatsForEntry(entry);
  const atime = (fstFlags & WASI_FILESTAT_SET_ATIM_NOW) !== 0
    ? new Date()
    : (fstFlags & WASI_FILESTAT_SET_ATIM) !== 0
    ? wasiTimestampToDate(atim)
    : currentStats.atime;
  const mtime = (fstFlags & WASI_FILESTAT_SET_MTIM_NOW) !== 0
    ? new Date()
    : (fstFlags & WASI_FILESTAT_SET_MTIM) !== 0
    ? wasiTimestampToDate(mtim)
    : currentStats.mtime;

  if (entry.kind === "file" || entry.kind === "stdio") {
    futimesSync(entry.hostFd, atime, mtime);
  } else {
    Deno.utimeSync(entry.hostPath, atime, mtime);
  }
}

function mapDirentType(dirent): number {
  if (typeof dirent.isDirectory === "function" && dirent.isDirectory()) {
    return WASI_FILETYPE_DIRECTORY;
  }
  if (typeof dirent.isFile === "function" && dirent.isFile()) {
    return WASI_FILETYPE_REGULAR_FILE;
  }
  return WASI_FILETYPE_UNKNOWN;
}

function openFlagsFromWasi(
  rightsBase: bigint | number,
  oflags: number,
  fdflags: number,
): number {
  let wantsRead = rightsInclude(rightsBase, WASI_RIGHT_FD_READ);
  let wantsWrite = rightsInclude(rightsBase, WASI_RIGHT_FD_WRITE);
  if (!wantsRead && !wantsWrite) {
    wantsRead = true;
    wantsWrite = true;
  }
  let openFlags = 0;
  if (wantsRead && wantsWrite) {
    openFlags |= fsConstants.O_RDWR;
  } else if (wantsWrite) {
    openFlags |= fsConstants.O_WRONLY;
  } else {
    openFlags |= fsConstants.O_RDONLY;
  }
  if ((oflags & WASI_O_CREAT) !== 0) {
    openFlags |= fsConstants.O_CREAT;
  }
  if ((oflags & WASI_O_EXCL) !== 0) {
    openFlags |= fsConstants.O_EXCL;
  }
  if ((oflags & WASI_O_TRUNC) !== 0) {
    openFlags |= fsConstants.O_TRUNC;
  }
  if ((fdflags & WASI_FDFLAG_APPEND) !== 0) {
    openFlags |= fsConstants.O_APPEND;
  }
  return openFlags;
}

function wasiReturnOnProcExit(this: WASI, rval: number) {
  ensureStarted(this);
  this[kExitCode] = rval;
  throw kExitCode;
}

function wasiProcExit(this: WASI, rval: number) {
  ensureStarted(this);
  Deno.exit(rval);
}

function wasiArgsSizesGet(
  this: WASI,
  argcPtr: number,
  argvBufSizePtr: number,
): number {
  ensureStarted(this);
  let argvBufSize = 0;
  ArrayPrototypeForEach(this[kArgs], (arg) => {
    argvBufSize += Buffer.byteLength(arg) + 1;
  });
  writeUint32(this, argcPtr, this[kArgs].length);
  writeUint32(this, argvBufSizePtr, argvBufSize);
  return WASI_ESUCCESS;
}

function wasiArgsGet(this: WASI, argvPtr: number, argvBufPtr: number): number {
  const memoryBytes = getMemoryBytes(this);
  const memoryView = getMemoryView(this);
  let cursor = argvBufPtr;
  ArrayPrototypeForEach(this[kArgs], (arg, index) => {
    memoryView.setUint32(argvPtr + (index * 4), cursor, true);
    const encoded = Buffer.from(arg);
    memoryBytes.set(encoded, cursor);
    cursor += encoded.length;
    memoryBytes[cursor] = 0;
    cursor += 1;
  });
  return WASI_ESUCCESS;
}

function wasiEnvironSizesGet(
  this: WASI,
  environCountPtr: number,
  environBufSizePtr: number,
): number {
  ensureStarted(this);
  let environBufSize = 0;
  ArrayPrototypeForEach(this[kEnv], (entry) => {
    environBufSize += Buffer.byteLength(entry) + 1;
  });
  writeUint32(this, environCountPtr, this[kEnv].length);
  writeUint32(this, environBufSizePtr, environBufSize);
  return WASI_ESUCCESS;
}

function wasiEnvironGet(
  this: WASI,
  environPtr: number,
  environBufPtr: number,
): number {
  const memoryBytes = getMemoryBytes(this);
  const memoryView = getMemoryView(this);
  let cursor = environBufPtr;
  ArrayPrototypeForEach(this[kEnv], (entry, index) => {
    memoryView.setUint32(environPtr + (index * 4), cursor, true);
    const encoded = Buffer.from(entry);
    memoryBytes.set(encoded, cursor);
    cursor += encoded.length;
    memoryBytes[cursor] = 0;
    cursor += 1;
  });
  return WASI_ESUCCESS;
}

function wasiFdClose(this: WASI, fd: number): number {
  ensureStarted(this);
  if (this[kClosedFds].has(fd)) {
    return WASI_EBADF;
  }
  const entry = resolveFdEntry(this, fd);
  if (entry === undefined) {
    return WASI_EBADF;
  }
  if (entry.kind === "file") {
    try {
      closeSync(entry.hostFd!);
    } catch {
      return WASI_EBADF;
    }
  }
  if (fd > 2) {
    this[kFdTable].delete(fd);
  }
  this[kClosedFds].add(fd);
  this[kFdPositions].delete(fd);
  return WASI_ESUCCESS;
}

function wasiFdFdstatGet(this: WASI, fd: number, statPtr: number): number {
  ensureStarted(this);
  const entry = resolveFdEntry(this, fd);
  if (entry === undefined) {
    return WASI_EBADF;
  }
  try {
    const memoryBytes = getMemoryBytes(this);
    memoryBytes.fill(0, statPtr, statPtr + WASI_FDSTAT_SIZE);
    const memoryView = getMemoryView(this);
    memoryView.setUint8(statPtr, getFdFileType(entry) ?? WASI_FILETYPE_UNKNOWN);
    memoryView.setUint16(statPtr + 2, entry.flags ?? 0, true);
    memoryView.setBigUint64(statPtr + 8, entry.rightsBase ?? 0n, true);
    memoryView.setBigUint64(statPtr + 16, entry.rightsInheriting ?? 0n, true);
    return WASI_ESUCCESS;
  } catch {
    return WASI_EBADF;
  }
}

function wasiFdFdstatSetFlags(this: WASI, fd: number, flags: number): number {
  ensureStarted(this);
  const entry = resolveFdEntry(this, fd);
  if (entry === undefined) {
    return WASI_EBADF;
  }
  if (entry.kind !== "stdio") {
    entry.flags = flags;
  }
  return WASI_ESUCCESS;
}

function wasiFdRead(
  this: WASI,
  fd: number,
  iovsPtr: number,
  iovsLen: number,
  nreadPtr: number,
): number {
  ensureStarted(this);
  const entry = resolveFdEntry(this, fd);
  if (entry === undefined || (entry.kind !== "file" && entry.kind !== "stdio")) {
    return WASI_EBADF;
  }

  const memoryBytes = getMemoryBytes(this);
  const memoryView = getMemoryView(this);
  const usePosition = fdUsesPosition(entry);
  let position = usePosition ? trackedPosition(this, fd) : null;
  let totalRead = 0;

  try {
    for (let index = 0; index < iovsLen; index += 1) {
      const ptr = memoryView.getUint32(iovsPtr + (index * 8), true);
      const len = memoryView.getUint32(iovsPtr + (index * 8) + 4, true);
      const target = memoryBytes.subarray(ptr, ptr + len);
      const bytesRead = readSync(entry.hostFd, target, 0, len, position);
      totalRead += bytesRead;
      if (position !== null) {
        position += bytesRead;
      }
      if (bytesRead < len) {
        break;
      }
    }
    writeUint32(this, nreadPtr, totalRead);
    if (position !== null) {
      this[kFdPositions].set(fd, position);
    }
    return WASI_ESUCCESS;
  } catch {
    return WASI_EBADF;
  }
}

function wasiFdSeek(
  this: WASI,
  fd: number,
  offset: bigint | number,
  whence: number,
  newOffsetPtr: number,
): number {
  ensureStarted(this);
  const entry = resolveFdEntry(this, fd);
  if (entry === undefined) {
    return WASI_EBADF;
  }
  if (entry.kind !== "file" && entry.kind !== "stdio") {
    return WASI_ESPIPE;
  }

  try {
    const offsetBigInt = typeof offset === "bigint" ? offset : BigInt(offset);
    if (entry.kind === "file") {
      const nextPosition = op_node_fs_seek_sync(
        entry.hostFd!,
        Number(offsetBigInt),
        whence,
      );
      writeUint64(this, newOffsetPtr, nextPosition);
      return WASI_ESUCCESS;
    }
    let base = 0n;
    switch (whence) {
      case WASI_WHENCE_SET:
        base = 0n;
        break;
      case WASI_WHENCE_CUR:
        base = BigInt(trackedPosition(this, fd));
        break;
      case WASI_WHENCE_END:
        base = BigInt(fstatSync(entry.hostFd).size);
        break;
      default:
        return WASI_EINVAL;
    }

    const nextPosition = base + offsetBigInt;
    if (nextPosition < 0n) {
      return WASI_EINVAL;
    }

    this[kFdPositions].set(fd, Number(nextPosition));
    getMemoryView(this).setBigUint64(newOffsetPtr, nextPosition, true);
    return WASI_ESUCCESS;
  } catch {
    return WASI_EBADF;
  }
}

function wasiFdTell(this: WASI, fd: number, offsetPtr: number): number {
  ensureStarted(this);
  const entry = resolveFdEntry(this, fd);
  if (entry === undefined) {
    return WASI_EBADF;
  }
  if (entry.kind !== "file" && entry.kind !== "stdio") {
    return WASI_ESPIPE;
  }
  if (entry.kind === "file") {
    writeUint64(this, offsetPtr, op_node_fs_seek_sync(entry.hostFd!, 0, WASI_WHENCE_CUR));
    return WASI_ESUCCESS;
  }
  writeUint64(this, offsetPtr, trackedPosition(this, fd));
  return WASI_ESUCCESS;
}

function wasiFdWrite(
  this: WASI,
  fd: number,
  iovsPtr: number,
  iovsLen: number,
  nwrittenPtr: number,
): number {
  ensureStarted(this);
  const entry = resolveFdEntry(this, fd);
  if (entry === undefined || (entry.kind !== "file" && entry.kind !== "stdio")) {
    return WASI_EBADF;
  }

  const memoryBytes = getMemoryBytes(this);
  const memoryView = getMemoryView(this);
  const usePosition = fdUsesPosition(entry);
  let position = usePosition ? trackedPosition(this, fd) : null;
  let totalWritten = 0;

  try {
    for (let index = 0; index < iovsLen; index += 1) {
      const ptr = memoryView.getUint32(iovsPtr + (index * 8), true);
      const len = memoryView.getUint32(iovsPtr + (index * 8) + 4, true);
      const source = memoryBytes.subarray(ptr, ptr + len);
      const bytesWritten = entry.kind === "stdio" && entry.hostFd === 1
        ? (process.stdout.write(Buffer.from(source)), len)
        : entry.kind === "stdio" && entry.hostFd === 2
        ? (process.stderr.write(Buffer.from(source)), len)
        : writeSync(entry.hostFd, source, 0, len, position);
      totalWritten += bytesWritten;
      if (position !== null) {
        position += bytesWritten;
      }
      if (bytesWritten < len) {
        break;
      }
    }
    writeUint32(this, nwrittenPtr, totalWritten);
    if (position !== null) {
      this[kFdPositions].set(fd, position);
    }
    return WASI_ESUCCESS;
  } catch (_error) {
    return WASI_EBADF;
  }
}

function wasiFdFilestatGet(
  this: WASI,
  fd: number,
  statPtr: number,
): number {
  ensureStarted(this);
  const entry = resolveFdEntry(this, fd);
  if (entry === undefined) {
    return WASI_EBADF;
  }
  try {
    writeFilestat(this, statPtr, getStatsForEntry(entry), getFdFileType(entry));
    return WASI_ESUCCESS;
  } catch {
    return WASI_EBADF;
  }
}

function wasiFdFilestatSetTimes(
  this: WASI,
  fd: number,
  atim: bigint | number,
  mtim: bigint | number,
  fstFlags: number,
): number {
  ensureStarted(this);
  const entry = resolveFdEntry(this, fd);
  if (entry === undefined) {
    return WASI_EBADF;
  }
  try {
    setEntryTimes(entry, atim, mtim, fstFlags);
    return WASI_ESUCCESS;
  } catch (error) {
    return toWasiErrno((error as { code?: string }).code);
  }
}

function wasiFdPrestatGet(this: WASI, fd: number, prestatPtr: number): number {
  ensureStarted(this);
  const entry = resolveFdEntry(this, fd);
  if (entry === undefined || entry.kind !== "preopen") {
    return WASI_EBADF;
  }
  writePrestat(this, prestatPtr, entry.virtualPath);
  return WASI_ESUCCESS;
}

function wasiFdPrestatDirName(
  this: WASI,
  fd: number,
  pathPtr: number,
  pathLen: number,
): number {
  ensureStarted(this);
  const entry = resolveFdEntry(this, fd);
  if (entry === undefined || entry.kind !== "preopen") {
    return WASI_EBADF;
  }
  const encoded = Buffer.from(entry.virtualPath);
  if (pathLen < encoded.length) {
    return WASI_EINVAL;
  }
  getMemoryBytes(this).set(encoded, pathPtr);
  return WASI_ESUCCESS;
}

function wasiFdReaddir(
  this: WASI,
  fd: number,
  bufPtr: number,
  bufLen: number,
  cookie: bigint | number,
  bufUsedPtr: number,
): number {
  ensureStarted(this);
  const entry = resolveFdEntry(this, fd);
  if (entry === undefined) {
    return WASI_EBADF;
  }
  if (entry.kind !== "dir" && entry.kind !== "preopen") {
    return WASI_ENOTDIR;
  }

  try {
    const dirents = readdirSync(entry.hostPath, { withFileTypes: true });
    const memoryBytes = getMemoryBytes(this);
    const memoryView = getMemoryView(this);
    let cursor = 0;
    const startIndex = Number(
      typeof cookie === "bigint" ? cookie : BigInt(cookie),
    );

    for (let index = startIndex; index < dirents.length; index += 1) {
      const dirent = dirents[index];
      const nameBytes = Buffer.from(dirent.name);
      const entrySize = WASI_DIRENT_SIZE + nameBytes.length;
      if (cursor + entrySize > bufLen) {
        break;
      }
      const offset = bufPtr + cursor;
      memoryBytes.fill(0, offset, offset + WASI_DIRENT_SIZE);
      memoryView.setBigUint64(offset, BigInt(index + 1), true);
      memoryView.setBigUint64(offset + 8, BigInt(index + 1), true);
      memoryView.setUint32(offset + 16, nameBytes.length, true);
      memoryView.setUint8(offset + 20, mapDirentType(dirent));
      memoryBytes.set(nameBytes, offset + WASI_DIRENT_SIZE);
      cursor += entrySize;
    }

    writeUint32(this, bufUsedPtr, cursor);
    return WASI_ESUCCESS;
  } catch (error) {
    return toWasiErrno((error as { code?: string }).code);
  }
}

function wasiPathOpen(
  this: WASI,
  fd: number,
  _dirFlags: number,
  pathPtr: number,
  pathLen: number,
  oflags: number,
  rightsBase: bigint | number,
  rightsInheriting: bigint | number,
  fdflags: number,
  openedFdPtr: number,
): number {
  ensureStarted(this);

  try {
    const rawPath = readPathString(this, pathPtr, pathLen);
    const { hostPath, virtualPath } = resolvePathFromFd(
      this,
      fd,
      rawPath,
    );
    const wantsDirectory = (oflags & WASI_O_DIRECTORY) !== 0;
    const followSymlink = (_dirFlags & WASI_LOOKUP_SYMLINK_FOLLOW) !== 0;
    let stats = null;
    try {
      stats = getStatForPath(hostPath, followSymlink);
    } catch (error) {
      const errorCode = (error as { code?: string }).code;
      if (errorCode !== "ENOENT" || wantsDirectory || (oflags & WASI_O_CREAT) === 0) {
        return toWasiErrno(errorCode);
      }
    }

    if (wantsDirectory || stats?.isDirectory()) {
      if (stats === null || !stats.isDirectory()) {
        return WASI_ENOTDIR;
      }
      writeUint32(
        this,
        openedFdPtr,
        allocateFd(this, {
          kind: "dir",
          hostPath,
          virtualPath,
          flags: fdflags,
          rightsBase: normalizeRights(rightsBase, DEFAULT_WASI_DIRECTORY_BASE_RIGHTS),
          rightsInheriting: normalizeRights(
            rightsInheriting,
            DEFAULT_WASI_DIRECTORY_INHERITING_RIGHTS,
          ),
        }),
      );
      return WASI_ESUCCESS;
    }

    const hostFd = openSync(hostPath, openFlagsFromWasi(rightsBase, oflags, fdflags), 0o666);
    const openedFd = allocateFd(this, {
      kind: "file",
      hostFd,
      hostPath,
      virtualPath,
      flags: fdflags,
      rightsBase: normalizeRights(rightsBase, DEFAULT_WASI_FILE_RIGHTS),
      rightsInheriting: normalizeRights(rightsInheriting, 0n),
    });
    writeUint32(this, openedFdPtr, openedFd);
    return WASI_ESUCCESS;
  } catch (error) {
    return toWasiErrno((error as { code?: string }).code);
  }
}

function wasiFdRenumber(this: WASI, fromFd: number, toFd: number): number {
  ensureStarted(this);
  const fromEntry = resolveFdEntry(this, fromFd);
  const toEntry = resolveFdEntry(this, toFd);
  if (fromEntry === undefined || toEntry === undefined || fromEntry.kind === "stdio") {
    return WASI_EBADF;
  }

  try {
    if (toEntry.kind === "file") {
      closeSync(toEntry.hostFd!);
    }
    this[kFdTable].set(toFd, fromEntry);
    this[kFdTable].delete(fromFd);
    const fromPosition = this[kFdPositions].get(fromFd);
    this[kFdPositions].delete(fromFd);
    if (fromPosition !== undefined) {
      this[kFdPositions].set(toFd, fromPosition);
    }
    this[kClosedFds].add(fromFd);
    this[kClosedFds].delete(toFd);
    return WASI_ESUCCESS;
  } catch {
    return WASI_EBADF;
  }
}

function wasiPathCreateDirectory(
  this: WASI,
  fd: number,
  pathPtr: number,
  pathLen: number,
): number {
  ensureStarted(this);
  try {
    const { hostPath } = resolvePathFromFd(this, fd, readPathString(this, pathPtr, pathLen));
    mkdirSync(hostPath);
    return WASI_ESUCCESS;
  } catch (error) {
    return toWasiErrno((error as { code?: string }).code);
  }
}

function wasiPathFilestatGet(
  this: WASI,
  fd: number,
  flags: number,
  pathPtr: number,
  pathLen: number,
  statPtr: number,
): number {
  ensureStarted(this);
  try {
    const rawPath = readPathString(this, pathPtr, pathLen);
    const { hostPath } = resolvePathFromFd(this, fd, rawPath);
    const stats = getStatForPath(
      hostPath,
      (flags & WASI_LOOKUP_SYMLINK_FOLLOW) !== 0,
    );
    writeFilestat(this, statPtr, stats, getFdFileTypeForStats(stats));
    return WASI_ESUCCESS;
  } catch (error) {
    return toWasiErrno((error as { code?: string }).code);
  }
}

function wasiPathRemoveDirectory(
  this: WASI,
  fd: number,
  pathPtr: number,
  pathLen: number,
): number {
  ensureStarted(this);
  try {
    const { hostPath } = resolvePathFromFd(this, fd, readPathString(this, pathPtr, pathLen));
    rmdirSync(hostPath);
    return WASI_ESUCCESS;
  } catch (error) {
    return toWasiErrno((error as { code?: string }).code);
  }
}

function wasiPathUnlinkFile(
  this: WASI,
  fd: number,
  pathPtr: number,
  pathLen: number,
): number {
  ensureStarted(this);
  try {
    const rawPath = readPathString(this, pathPtr, pathLen);
    const { hostPath } = resolvePathFromFd(this, fd, rawPath);
    unlinkSync(hostPath);
    return WASI_ESUCCESS;
  } catch (error) {
    return toWasiErrno((error as { code?: string }).code);
  }
}

class WASI {
  wasiImport: Record<string, (...args: unknown[]) => unknown>;
  [kExitCode]: number;
  [kStarted]: boolean;
  [kInstance]: WebAssembly.Instance | undefined;
  [kBindingName]: string;
  [kMemory]: WebAssembly.Memory | undefined;
  [kSetMemory]: (memory: WebAssembly.Memory) => void;
  [kArgs]: string[];
  [kEnv]: string[];
  [kStdio]: [number, number, number];
  [kFdPositions]: Map<number, number>;
  [kClosedFds]: Set<number>;
  [kFdTable]: Map<number, WasiFdEntry>;
  [kNextFd]: number;

  constructor(options = kEmptyObject) {
    validateObject(options, "options");

    validateString(options.version, "options.version");
    switch (options.version) {
      case "unstable":
        this[kBindingName] = "wasi_unstable";
        break;
      case "preview1":
        this[kBindingName] = "wasi_snapshot_preview1";
        break;
      default:
        throw new codes.ERR_INVALID_ARG_VALUE(
          "options.version",
          options.version,
          "unsupported WASI version",
        );
    }

    if (options.args !== undefined) {
      validateArray(options.args, "options.args");
    }
    const args = ArrayPrototypeMap(options.args || [], String);

    const env: string[] = [];
    if (options.env !== undefined) {
      validateObject(options.env, "options.env");
      ArrayPrototypeForEach(
        ObjectEntries(options.env),
        ({ 0: key, 1: value }) => {
          if (value !== undefined) {
            ArrayPrototypePush(env, `${key}=${value}`);
          }
        },
      );
    }

    const fdTable = new Map<number, WasiFdEntry>();
    let nextFd = 3;
    if (options.preopens !== undefined) {
      validateObject(options.preopens, "options.preopens");
      ArrayPrototypeForEach(
        ObjectEntries(options.preopens),
        ({ 0: key, 1: value }) => {
          const mappedKey = String(key);
          const mappedValue = String(value);
          ensurePreopenExists(mappedValue);
          fdTable.set(nextFd, {
            kind: "preopen",
            hostPath: mappedValue,
            virtualPath: mappedKey,
            flags: 0,
            rightsBase: DEFAULT_WASI_DIRECTORY_BASE_RIGHTS,
            rightsInheriting: DEFAULT_WASI_DIRECTORY_INHERITING_RIGHTS,
          });
          nextFd += 1;
        },
      );
    }

    const { stdin = 0, stdout = 1, stderr = 2 } = options;
    validateInt32(stdin, "options.stdin", 0);
    validateInt32(stdout, "options.stdout", 0);
    validateInt32(stderr, "options.stderr", 0);

    let returnOnExit = true;
    if (options.returnOnExit !== undefined) {
      validateBoolean(options.returnOnExit, "options.returnOnExit");
      returnOnExit = options.returnOnExit;
    }

    this[kSetMemory] = (memory) => {
      this[kMemory] = memory;
    };

    this.wasiImport = {
      args_get: FunctionPrototypeBind(wasiArgsGet, this),
      args_sizes_get: FunctionPrototypeBind(wasiArgsSizesGet, this),
      environ_get: FunctionPrototypeBind(wasiEnvironGet, this),
      environ_sizes_get: FunctionPrototypeBind(wasiEnvironSizesGet, this),
      fd_close: FunctionPrototypeBind(wasiFdClose, this),
      fd_fdstat_get: FunctionPrototypeBind(wasiFdFdstatGet, this),
      fd_fdstat_set_flags: FunctionPrototypeBind(wasiFdFdstatSetFlags, this),
      fd_filestat_get: FunctionPrototypeBind(wasiFdFilestatGet, this),
      fd_filestat_set_times: FunctionPrototypeBind(wasiFdFilestatSetTimes, this),
      fd_prestat_dir_name: FunctionPrototypeBind(wasiFdPrestatDirName, this),
      fd_prestat_get: FunctionPrototypeBind(wasiFdPrestatGet, this),
      fd_read: FunctionPrototypeBind(wasiFdRead, this),
      fd_readdir: FunctionPrototypeBind(wasiFdReaddir, this),
      fd_renumber: FunctionPrototypeBind(wasiFdRenumber, this),
      fd_seek: FunctionPrototypeBind(wasiFdSeek, this),
      fd_tell: FunctionPrototypeBind(wasiFdTell, this),
      fd_write: FunctionPrototypeBind(wasiFdWrite, this),
      path_create_directory: FunctionPrototypeBind(wasiPathCreateDirectory, this),
      path_filestat_get: FunctionPrototypeBind(wasiPathFilestatGet, this),
      path_open: FunctionPrototypeBind(wasiPathOpen, this),
      path_remove_directory: FunctionPrototypeBind(wasiPathRemoveDirectory, this),
      path_unlink_file: FunctionPrototypeBind(wasiPathUnlinkFile, this),
      proc_exit: returnOnExit
        ? FunctionPrototypeBind(wasiReturnOnProcExit, this)
        : FunctionPrototypeBind(wasiProcExit, this),
    };
    this[kStarted] = false;
    this[kExitCode] = 0;
    this[kInstance] = undefined;
    this[kMemory] = undefined;
    this[kArgs] = args;
    this[kEnv] = env;
    this[kStdio] = [stdin, stdout, stderr];
    this[kFdPositions] = new Map();
    this[kClosedFds] = new Set();
    this[kFdTable] = fdTable;
    this[kNextFd] = nextFd;
  }

  finalizeBindings(
    instance,
    {
      memory = instance?.exports?.memory,
    } = kEmptyObject,
  ) {
    if (this[kStarted]) {
      throw new ERR_WASI_ALREADY_STARTED();
    }

    validateObject(instance, "instance");
    validateObject(instance.exports, "instance.exports");
    validateMemory(memory, "instance.exports.memory");

    this[kSetMemory](memory);
    this[kInstance] = instance;
    this[kStarted] = true;
  }

  start(instance) {
    this.finalizeBindings(instance);

    const { _start, _initialize } = this[kInstance]!.exports;
    validateFunction(_start, "instance.exports._start");
    validateUndefined(_initialize, "instance.exports._initialize");

    try {
      _start();
    } catch (err) {
      if (err !== kExitCode) {
        throw err;
      }
    }

    return this[kExitCode];
  }

  initialize(instance) {
    this.finalizeBindings(instance);

    const { _start, _initialize } = this[kInstance]!.exports;
    validateUndefined(_start, "instance.exports._start");
    if (_initialize !== undefined) {
      validateFunction(_initialize, "instance.exports._initialize");
      _initialize();
    }
  }

  getImportObject() {
    return { [this[kBindingName]]: this.wasiImport };
  }
}

export { WASI };

export default { WASI };
