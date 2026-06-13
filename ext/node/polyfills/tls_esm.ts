// Copyright 2018-2026 the Deno authors. MIT license.

import { internals } from "ext:core/mod.js";
const processGetBuiltinModule = globalThis.process?.getBuiltinModule;
const defaultExport =
  (typeof processGetBuiltinModule === "function"
    ? processGetBuiltinModule("tls")
    : undefined) ?? internals.__getDenoNodeTlsDefaultExport();

export const CryptoStream = defaultExport.CryptoStream;
export const SecurePair = defaultExport.SecurePair;
export const Server = defaultExport.Server;
export const TLSSocket = defaultExport.TLSSocket;
export const checkServerIdentity = defaultExport.checkServerIdentity;
export const connect = defaultExport.connect;
export const createSecureContext = defaultExport.createSecureContext;
export const createServer = defaultExport.createServer;
export const convertALPNProtocols = defaultExport.convertALPNProtocols;
export const getCiphers = defaultExport.getCiphers;
export const getCACertificates = defaultExport.getCACertificates;
export const setDefaultCACertificates = defaultExport.setDefaultCACertificates;
export const createSecurePair = defaultExport.createSecurePair;
export const rootCertificates = defaultExport.rootCertificates;
export const DEFAULT_CIPHERS = defaultExport.DEFAULT_CIPHERS;
export const DEFAULT_ECDH_CURVE = defaultExport.DEFAULT_ECDH_CURVE;
export const DEFAULT_MAX_VERSION = defaultExport.DEFAULT_MAX_VERSION;
export const DEFAULT_MIN_VERSION = defaultExport.DEFAULT_MIN_VERSION;
export const CLIENT_RENEG_LIMIT = defaultExport.CLIENT_RENEG_LIMIT;
export const CLIENT_RENEG_WINDOW = defaultExport.CLIENT_RENEG_WINDOW;

export default defaultExport;
