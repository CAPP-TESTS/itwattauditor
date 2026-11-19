import * as crypto from 'crypto';
import { X509Certificate } from 'crypto';
import { HUAWEI_CBG_ROOT_CA_PEM } from './huaweiRoots';

/**
 * Verification of the HMS Safety Detect SysIntegrity results, for the Huawei devices without Google
 * Mobile Services: their Android key attestation is signed with the public AOSP software attestation key,
 * so it can't prove anything. SysIntegrity is evaluated by HMS Core on the device (with the TEE on the
 * devices which support it) and returned as a JWS signed by the Huawei SysIntegrity server, following the
 * HMS Core SysIntegrity server sample:
 * 1. the certificate chain of the x5c header must be rooted at the HUAWEI CBG Root CA;
 * 2. the leaf certificate must be issued to sysintegrity.platform.hicloud.com;
 * 3. the JWS signature (RS256 or PS256) must be valid with the leaf public key;
 * 4. the payload must contain the expected nonce, package name and app signing certificate, a recent
 *    timestamp and basicIntegrity true.
 * Please note that, like Play Integrity, the result is a verdict of a remote service: it is not bound to
 * the keys of the app, so it doesn't prove that they are stored in secure hardware.
 * {@link https://github.com/HMS-Core/hms-safetydetect-demo-android/tree/master/SafetyDetect-SysIntegrity-Sample}
 */

export const SYSINTEGRITY_HOSTNAME = 'sysintegrity.platform.hicloud.com';
const SUPPORTED_ALGORITHMS = ['RS256', 'PS256'];
// Maximum age of a SysIntegrity result, and tolerated clock skew
const MAX_AGE_MS = 10 * 60 * 1000;
const MAX_CLOCK_SKEW_MS = 2 * 60 * 1000;

/**
 * Payload of a SysIntegrity result.
 */
export type SysIntegrityPayload = {
  nonce?: string;
  apkPackageName?: string;
  apkDigestSha256?: string;
  apkCertificateDigestSha256?: string[];
  basicIntegrity?: boolean;
  timestampMs?: number | string;
  advice?: string;
  [key: string]: unknown;
};

export type SysIntegrityOptions = {
  /** The nonce the app has passed to the SysIntegrity API. */
  expectedNonce: Buffer;
  /** The allowed package names of the app. */
  packageNames: string[];
  /** The allowed SHA-256 digests (hex) of the app signing certificates, at least one is required. */
  signatureDigests: string[];
  /** Trusted root public keys, the HUAWEI CBG Root CA by default. */
  rootPublicKeys?: crypto.KeyObject[];
  /** The current time. */
  now?: Date;
};

export type VerifiedSysIntegrity = {
  alg: string;
  payload: SysIntegrityPayload;
};

export class SysIntegrityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SysIntegrityError';
  }
}

/**
 * @returns the public key of the HUAWEI CBG Root CA.
 */
export const getHuaweiRootPublicKeys = () => [
  new X509Certificate(HUAWEI_CBG_ROOT_CA_PEM).publicKey,
];

const decodeJson = (segment: string, what: string) => {
  try {
    return JSON.parse(Buffer.from(segment, 'base64url').toString('utf-8'));
  } catch {
    throw new SysIntegrityError(`Invalid SysIntegrity ${what}`);
  }
};

/**
 * Decodes a SysIntegrity JWS without verifying it, for the reports.
 * @param jws - The SysIntegrity result.
 * @returns the header and the payload, undefined if the JWS can't be decoded.
 */
export const decodeSysIntegrity = (jws: string) => {
  try {
    const [header, payload] = jws.split('.');
    return {
      header: decodeJson(header ?? '', 'header'),
      payload: decodeJson(payload ?? '', 'payload') as SysIntegrityPayload,
    };
  } catch {
    return undefined;
  }
};

const isSignedBy = (certificate: X509Certificate, publicKey: crypto.KeyObject) => {
  try {
    return certificate.verify(publicKey);
  } catch {
    return false;
  }
};

/**
 * Verifies the x5c certificate chain, from the leaf to the last certificate, which must be issued by
 * a trusted root (the root itself may be included or not).
 */
const verifyChain = (
  x5c: unknown,
  rootPublicKeys: crypto.KeyObject[],
  now: Date
) => {
  if (
    !Array.isArray(x5c) ||
    x5c.length === 0 ||
    x5c.length > 5 ||
    !x5c.every((c) => typeof c === 'string')
  ) {
    throw new SysIntegrityError('Invalid x5c certificate chain');
  }
  const chain = x5c.map(
    (c: string) => new X509Certificate(Buffer.from(c, 'base64'))
  );
  for (const certificate of chain) {
    if (new Date(certificate.validFrom) > now || new Date(certificate.validTo) < now) {
      throw new SysIntegrityError(`Certificate expired or not yet valid: ${certificate.subject}`);
    }
  }
  for (let i = 0; i < chain.length - 1; i++) {
    if (!isSignedBy(chain[i]!, chain[i + 1]!.publicKey)) {
      throw new SysIntegrityError('Invalid x5c certificate chain signature');
    }
  }
  const last = chain[chain.length - 1]!;
  if (!rootPublicKeys.some((key) => isSignedBy(last, key))) {
    throw new SysIntegrityError('The certificate chain is not issued by the HUAWEI CBG Root CA');
  }
  return chain;
};

const verifySignature = (
  alg: string,
  signingInput: string,
  signature: Buffer,
  publicKey: crypto.KeyObject
) =>
  crypto.verify(
    'sha256',
    Buffer.from(signingInput, 'utf-8'),
    alg === 'PS256'
      ? {
          key: publicKey,
          padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
          saltLength: crypto.constants.RSA_PSS_SALTLEN_AUTO,
        }
      : { key: publicKey, padding: crypto.constants.RSA_PKCS1_PADDING },
    signature
  );

const base64ToHex = (value: string) => Buffer.from(value, 'base64').toString('hex');

/**
 * Verifies a SysIntegrity result.
 * @param jws - The JWS returned by the SysIntegrity API.
 * @param options - The {@link SysIntegrityOptions}.
 * @returns the {@link VerifiedSysIntegrity}.
 * @throws {SysIntegrityError} - If the result is not valid or the device doesn't meet basic integrity.
 */
export const verifySysIntegrity = (
  jws: unknown,
  options: SysIntegrityOptions
): VerifiedSysIntegrity => {
  if (typeof jws !== 'string' || jws.split('.').length !== 3) {
    throw new SysIntegrityError('The SysIntegrity result must be a compact JWS');
  }
  const [headerSegment, payloadSegment, signatureSegment] = jws.split('.') as [string, string, string];
  const header = decodeJson(headerSegment, 'header');
  const payload = decodeJson(payloadSegment, 'payload') as SysIntegrityPayload;
  const now = options.now ?? new Date();

  // 1-3. Certificate chain, hostname and signature
  if (!SUPPORTED_ALGORITHMS.includes(header.alg)) {
    throw new SysIntegrityError(`Unsupported SysIntegrity algorithm: ${header.alg}`);
  }
  const [leaf] = verifyChain(
    header.x5c,
    options.rootPublicKeys ?? getHuaweiRootPublicKeys(),
    now
  );
  if (leaf!.checkHost(SYSINTEGRITY_HOSTNAME) === undefined) {
    throw new SysIntegrityError(`The signing certificate is not issued to ${SYSINTEGRITY_HOSTNAME}`);
  }
  if (
    !verifySignature(
      header.alg,
      `${headerSegment}.${payloadSegment}`,
      Buffer.from(signatureSegment, 'base64url'),
      leaf!.publicKey
    )
  ) {
    throw new SysIntegrityError('Invalid SysIntegrity signature');
  }

  // 4. Payload
  if (
    typeof payload.nonce !== 'string' ||
    !Buffer.from(payload.nonce, 'base64').equals(options.expectedNonce)
  ) {
    throw new SysIntegrityError('SysIntegrity nonce mismatch');
  }
  const timestamp = Number(payload.timestampMs);
  if (
    !Number.isFinite(timestamp) ||
    now.getTime() - timestamp > MAX_AGE_MS ||
    timestamp - now.getTime() > MAX_CLOCK_SKEW_MS
  ) {
    throw new SysIntegrityError('SysIntegrity result is too old or from the future');
  }
  if (!payload.apkPackageName || !options.packageNames.includes(payload.apkPackageName)) {
    throw new SysIntegrityError(`Invalid package name: ${payload.apkPackageName}`);
  }
  const allowedDigests = new Set(options.signatureDigests.map((d) => d.toLowerCase()));
  if (allowedDigests.size === 0) {
    throw new SysIntegrityError(
      'App signing certificate digests are required to accept a SysIntegrity result'
    );
  }
  if (
    !Array.isArray(payload.apkCertificateDigestSha256) ||
    !payload.apkCertificateDigestSha256.some(
      (digest) => typeof digest === 'string' && allowedDigests.has(base64ToHex(digest))
    )
  ) {
    throw new SysIntegrityError('Invalid app signing certificate');
  }
  if (payload.basicIntegrity !== true) {
    throw new SysIntegrityError(
      `The device does not meet basic integrity${payload.advice ? ` (advice: ${payload.advice})` : ''}`
    );
  }
  return { alg: header.alg, payload };
};

/**
 * Describes a SysIntegrity result for the reports, without verifying it.
 */
export const describeSysIntegrity = (jws: unknown) => {
  if (typeof jws !== 'string') return undefined;
  const decoded = decodeSysIntegrity(jws);
  if (!decoded) return { decodeError: 'Invalid JWS' };
  const { header, payload } = decoded;
  return {
    alg: header.alg,
    certificates: Array.isArray(header.x5c)
      ? header.x5c.map((c: string) => {
          try {
            const certificate = new X509Certificate(Buffer.from(c, 'base64'));
            return { subject: certificate.subject, issuer: certificate.issuer, validTo: certificate.validTo };
          } catch {
            return { parseError: true };
          }
        })
      : undefined,
    payload: {
      ...payload,
      apkCertificateDigestSha256Hex: Array.isArray(payload.apkCertificateDigestSha256)
        ? payload.apkCertificateDigestSha256.map((d) => (typeof d === 'string' ? base64ToHex(d) : d))
        : undefined,
    },
  };
};

/**
 * The nonce of the SysIntegrity request sent with the registration: it binds the result to the challenge
 * issued by the backend and to the hardware key being registered.
 * @param challenge - The challenge of the registration.
 * @param hardwareKey - The public key of the hardware key.
 * @returns SHA-256(challenge UTF-8 bytes || SubjectPublicKeyInfo DER of the hardware key).
 */
export const registrationNonce = (challenge: string, hardwareKey: crypto.KeyObject) =>
  crypto
    .createHash('sha256')
    .update(Buffer.from(challenge, 'utf-8'))
    .update(hardwareKey.export({ format: 'der', type: 'spki' }))
    .digest();

/**
 * The nonce of the SysIntegrity request sent with an assertion: it binds the result to the client data.
 * @param clientData - The client data signed with the hardware key.
 * @returns SHA-256(client data UTF-8 bytes).
 */
export const assertionNonce = (clientData: string) =>
  crypto.createHash('sha256').update(Buffer.from(clientData, 'utf-8')).digest();
