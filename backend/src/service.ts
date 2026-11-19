import * as crypto from 'crypto';
import { getConfig, getGrapheneOsAllowlist, type Config } from './config';
import { describeChain } from './report';
import {
  assertionNonce,
  describeSysIntegrity,
  registrationNonce,
  verifySysIntegrity,
} from './huaweiSysIntegrity';
import {
  issueChallenge,
  signRegistration,
  verifyChallenge,
  verifyRegistration,
} from './tokens';
import {
  hasHardwareRoot,
  parseCertificateChain,
  spkiBase64,
  verifyAssertion,
  verifyAttestation,
  type AttestationVerificationOptions,
} from './verification';

/**
 * Framework independent implementation of the endpoints, wrapped by the Vercel functions in `api/`
 * and by the local development server.
 */

export type JsonResponse = { status: number; body: unknown };

/**
 * Dependencies of the service, overridden by the tests.
 */
export type ServiceDeps = {
  config: Config;
  verificationOptions?: Partial<AttestationVerificationOptions>;
  /** Trusted roots of the SysIntegrity results, the HUAWEI CBG Root CA by default. */
  huaweiRootPublicKeys?: crypto.KeyObject[];
  now?: () => number;
};

const getDeps = async (deps?: ServiceDeps) => {
  const resolved = deps ?? { config: getConfig() };
  const allowlist = resolved.verificationOptions?.trustedSelfSignedBootKeys
    ? undefined
    : await getGrapheneOsAllowlist();
  const options: Omit<AttestationVerificationOptions, 'challenge'> = {
    packageNames: resolved.config.packageNames,
    signatureDigests: resolved.config.signatureDigests,
    trustedSelfSignedBootKeys: allowlist?.getKeys() ?? new Set(),
    ...resolved.verificationOptions,
  };
  return { ...resolved, options, now: resolved.now ?? Date.now };
};

const errorMessage = (e: unknown) => (e instanceof Error ? e.message : `${e}`);

const asObject = (body: unknown): Record<string, unknown> =>
  typeof body === 'object' && body !== null ? (body as Record<string, unknown>) : {};

/**
 * GET /api/challenge: issues a challenge for the registration or an assertion.
 */
export const getChallenge = async (deps?: ServiceDeps): Promise<JsonResponse> => {
  const { config, now } = await getDeps(deps);
  return {
    status: 200,
    body: issueChallenge(config.secret, config.challengeTtlSeconds, now()),
  };
};

/**
 * POST /api/register: verifies the key attestation of the hardware key, generated with a challenge
 * issued by {@link getChallenge}, as done by the Wallet Provider when the wallet instance is created.
 * Body: `{ challenge, certificates }`, the chain as base64 DER certificates from the hardware key to
 * the root (with the app attest key certificate right after the hardware key one).
 * On success it returns the registration token, which pins the hardware key, the attest key and the
 * device state, to be sent with the assertions.
 */
export const register = async (
  body: unknown,
  deps?: ServiceDeps
): Promise<JsonResponse> => {
  const { config, options, now } = await getDeps(deps);
  const { challenge, certificates, sysIntegrity } = asObject(body);
  let chain;
  try {
    verifyChallenge(config.secret, challenge, now());
    chain = parseCertificateChain(certificates);
  } catch (e) {
    return { status: 400, body: { ok: false, error: errorMessage(e) } };
  }
  const report = {
    ...describeChain(chain),
    sysIntegrity: describeSysIntegrity(sysIntegrity),
  };
  try {
    const verified = await verifyAttestation(chain, {
      ...options,
      challenge: challenge as string,
      now: new Date(now()),
    });
    const rootOfTrust = verified.record.rootOfTrust!;
    const registration = signRegistration(config.secret, {
      hardwareKey: spkiBase64(verified.publicKey),
      attestKey: verified.attestKeyPublicKey && spkiBase64(verified.attestKeyPublicKey),
      verifiedBootState: rootOfTrust.verifiedBootState,
      verifiedBootKey: rootOfTrust.verifiedBootKey,
      os: verified.os,
      iat: Math.floor(now() / 1000),
    });
    return {
      status: 200,
      body: {
        ok: true,
        result: 'Registration accepted',
        os: verified.os,
        attestKeyPinned: verified.attestKeyPublicKey !== undefined,
        // Without attest key the Wallet Provider requires Play Integrity for every assertion
        fallbackAvailable: verified.attestKeyPublicKey !== undefined,
        registration,
        report,
      },
    };
  } catch (e) {
    const keyAttestationError = errorMessage(e);
    // SysIntegrity replaces only a key attestation which can't provide hardware evidence (e.g. the AOSP
    // software attestation of the Huawei devices without GMS), never a hardware one rejected by the policy
    if (
      config.huaweiSysIntegrity &&
      sysIntegrity !== undefined &&
      !hasHardwareRoot(chain, options.rootPublicKeys)
    ) {
      return registerWithSysIntegrity(
        challenge as string,
        chain,
        sysIntegrity,
        keyAttestationError,
        report,
        { config, options, now, huaweiRootPublicKeys: deps?.huaweiRootPublicKeys }
      );
    }
    return {
      status: 422,
      body: { ok: false, result: 'Registration rejected', error: keyAttestationError, report },
    };
  }
};

/**
 * Registers a Huawei device without GMS through the HMS SysIntegrity result, when its key attestation
 * can't be verified (e.g. signed with the public AOSP software attestation key). The hardware key is the
 * attested key of the chain, which can't be trusted to be in secure hardware: it is bound to the result
 * by the SysIntegrity nonce, SHA-256(challenge || SPKI of the hardware key).
 */
const registerWithSysIntegrity = (
  challenge: string,
  chain: ReturnType<typeof parseCertificateChain>,
  sysIntegrity: unknown,
  keyAttestationError: string,
  report: Record<string, unknown>,
  deps: {
    config: Config;
    options: Omit<AttestationVerificationOptions, 'challenge'>;
    now: () => number;
    huaweiRootPublicKeys?: crypto.KeyObject[];
  }
): JsonResponse => {
  const hardwareKey = chain[0]!.publicKey;
  try {
    const verified = verifySysIntegrity(sysIntegrity, {
      expectedNonce: registrationNonce(challenge, hardwareKey),
      packageNames: deps.options.packageNames,
      signatureDigests: deps.options.signatureDigests,
      rootPublicKeys: deps.huaweiRootPublicKeys,
      now: new Date(deps.now()),
    });
    const registration = signRegistration(deps.config.secret, {
      hardwareKey: spkiBase64(hardwareKey),
      verifiedBootState: -1,
      verifiedBootKey: '',
      os: 'huawei',
      method: 'huawei_sysintegrity',
      iat: Math.floor(deps.now() / 1000),
    });
    return {
      status: 200,
      body: {
        ok: true,
        result: 'Registration accepted through the Huawei SysIntegrity result',
        os: 'huawei',
        method: 'huawei_sysintegrity',
        sysIntegrityAlg: verified.alg,
        // The key attestation was not accepted: the hardware key is not proven to be in secure hardware
        hardwareKeyProven: false,
        keyAttestationError,
        registration,
        report,
      },
    };
  } catch (e) {
    return {
      status: 422,
      body: {
        ok: false,
        result: 'Registration rejected',
        error: `Key attestation: ${keyAttestationError}. SysIntegrity: ${errorMessage(e)}`,
        report,
      },
    };
  }
};

/**
 * POST /api/assert: verifies an integrity assertion through the fresh hardware key attestation, as done
 * by the Wallet Provider for the Wallet Instance Attestation and Key Attestation requests when the Play
 * Integrity token is missing or not valid.
 * Body: `{ registration, clientData, signature, certificates }`:
 * - clientData: a JSON string with the `challenge` issued by {@link getChallenge};
 * - signature: the base64 DER ECDSA signature of clientData made with the hardware key;
 * - certificates: the fresh key attestation chain, generated with the SHA-256 hex digest of clientData
 *   as challenge and signed by the registered app attest key.
 */
export const assert = async (
  body: unknown,
  deps?: ServiceDeps
): Promise<JsonResponse> => {
  const { config, options, now } = await getDeps(deps);
  const { registration, clientData, signature, certificates, sysIntegrity } = asObject(body);
  let claims;
  let chain;
  try {
    claims = verifyRegistration(config.secret, registration);
    if (typeof clientData !== 'string' || typeof signature !== 'string') {
      throw new Error('clientData and signature must be strings');
    }
    verifyChallenge(config.secret, JSON.parse(clientData).challenge, now());
    // The fresh key attestation is optional for the devices registered with SysIntegrity
    chain =
      claims.method === 'huawei_sysintegrity' && certificates === undefined
        ? undefined
        : parseCertificateChain(certificates);
  } catch (e) {
    return { status: 400, body: { ok: false, error: errorMessage(e) } };
  }
  const report = {
    ...(chain ? describeChain(chain) : {}),
    sysIntegrity: describeSysIntegrity(sysIntegrity),
  };
  const requestHash = crypto.createHash('sha256').update(clientData).digest('hex');
  if (claims.method === 'huawei_sysintegrity') {
    return assertWithSysIntegrity(claims.hardwareKey, clientData, signature as string, sysIntegrity, {
      config,
      options,
      now,
      requestHash,
      report,
      huaweiRootPublicKeys: deps?.huaweiRootPublicKeys,
    });
  }
  if (!chain) {
    return { status: 400, body: { ok: false, error: 'Missing fresh key attestation' } };
  }
  try {
    const verified = await verifyAssertion(
      {
        publicKey: crypto.createPublicKey({
          key: Buffer.from(claims.hardwareKey, 'base64'),
          format: 'der',
          type: 'spki',
        }),
        attestKeyPublicKey: claims.attestKey
          ? crypto.createPublicKey({
              key: Buffer.from(claims.attestKey, 'base64'),
              format: 'der',
              type: 'spki',
            })
          : undefined,
        verifiedBootState: claims.verifiedBootState,
        verifiedBootKey: claims.verifiedBootKey,
      },
      { clientData, signature: signature as string, hardwareKeyAttestation: chain },
      { ...options, now: new Date(now()) }
    );
    return {
      status: 200,
      body: {
        ok: true,
        result: 'Assertion accepted through the hardware key attestation',
        method: 'key_attestation',
        os: verified.os,
        requestHash,
        report,
      },
    };
  } catch (e) {
    return {
      status: 422,
      body: {
        ok: false,
        result: 'Assertion rejected',
        error: errorMessage(e),
        requestHash,
        report,
      },
    };
  }
};

/**
 * Verifies an assertion of a Huawei device registered with SysIntegrity: the client data must be signed
 * by the registered hardware key and a new SysIntegrity result, with SHA-256(client data) as nonce, must
 * be valid. It is the counterpart of the Play Integrity verdict, as the device can't provide a key
 * attestation which can be trusted.
 */
const assertWithSysIntegrity = (
  hardwareKey: string,
  clientData: string,
  signature: string,
  sysIntegrity: unknown,
  deps: {
    config: Config;
    options: Omit<AttestationVerificationOptions, 'challenge'>;
    now: () => number;
    requestHash: string;
    report: Record<string, unknown>;
    huaweiRootPublicKeys?: crypto.KeyObject[];
  }
): JsonResponse => {
  const { requestHash, report } = deps;
  try {
    if (!deps.config.huaweiSysIntegrity) {
      throw new Error('The Huawei SysIntegrity results are not accepted (HUAWEI_SYSINTEGRITY)');
    }
    const publicKey = crypto.createPublicKey({
      key: Buffer.from(hardwareKey, 'base64'),
      format: 'der',
      type: 'spki',
    });
    if (!crypto.createVerify('SHA256').update(clientData).verify(publicKey, signature, 'base64')) {
      throw new Error('Invalid hardware signature of the client data');
    }
    const verified = verifySysIntegrity(sysIntegrity, {
      expectedNonce: assertionNonce(clientData),
      packageNames: deps.options.packageNames,
      signatureDigests: deps.options.signatureDigests,
      rootPublicKeys: deps.huaweiRootPublicKeys,
      now: new Date(deps.now()),
    });
    return {
      status: 200,
      body: {
        ok: true,
        result: 'Assertion accepted through the Huawei SysIntegrity result',
        method: 'huawei_sysintegrity',
        os: 'huawei',
        sysIntegrityAlg: verified.alg,
        requestHash,
        report,
      },
    };
  } catch (e) {
    return {
      status: 422,
      body: { ok: false, result: 'Assertion rejected', error: errorMessage(e), requestHash, report },
    };
  }
};

/**
 * GET /api/status: configuration and allowlist status, without secrets.
 */
export const getStatus = async (deps?: ServiceDeps): Promise<JsonResponse> => {
  const resolved = deps ?? { config: getConfig() };
  const allowlist = resolved.verificationOptions?.trustedSelfSignedBootKeys
    ? undefined
    : await getGrapheneOsAllowlist();
  return {
    status: 200,
    body: {
      ok: true,
      packageNames: resolved.config.packageNames,
      signatureDigests: resolved.config.signatureDigests,
      challengeTtlSeconds: resolved.config.challengeTtlSeconds,
      huaweiSysIntegrity: resolved.config.huaweiSysIntegrity,
      grapheneOsAllowlist: allowlist && {
        timestamp: allowlist.getTimestamp(),
        keys: allowlist.getKeys().size,
      },
    },
  };
};
