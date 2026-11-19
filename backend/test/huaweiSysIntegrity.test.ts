import 'reflect-metadata';
import { before, describe, it } from 'node:test';
import * as assert from 'node:assert/strict';
import * as crypto from 'crypto';
import * as x509 from '@peculiar/x509';
import { VerifiedBootState } from '@peculiar/asn1-android';
import { getConfig } from '../src/config';
import {
  assert as assertEndpoint,
  getChallenge,
  register,
  type ServiceDeps,
} from '../src/service';
import {
  SYSINTEGRITY_HOSTNAME,
  assertionNonce,
  getHuaweiRootPublicKeys,
  registrationNonce,
  verifySysIntegrity,
} from '../src/huaweiSysIntegrity';
import { parseCertificateChain, verifyAttestation } from '../src/verification';
import {
  NOW,
  PACKAGE_NAME,
  SIGNATURE_DIGEST,
  createAttestation,
  createTestRoot,
  stockParams,
  testOptions,
  type TestRoot,
} from './helpers';

const RSA = {
  name: 'RSASSA-PKCS1-v1_5',
  hash: 'SHA-256',
  publicExponent: new Uint8Array([1, 0, 1]),
  modulusLength: 2048,
};
const SECRET = 'test-secret-with-at-least-32-characters';

type HuaweiPki = {
  root: crypto.KeyObject;
  x5c: string[];
  leafKey: crypto.KeyObject;
};

const generateRsa = async () =>
  (await crypto.webcrypto.subtle.generateKey(RSA, true, [
    'sign',
    'verify',
  ])) as crypto.webcrypto.CryptoKeyPair;

/**
 * Creates a synthetic SysIntegrity PKI: root, intermediate and the signing certificate of the
 * SysIntegrity service, issued to the given hostname.
 */
const createHuaweiPki = async (hostname = SYSINTEGRITY_HOSTNAME): Promise<HuaweiPki> => {
  const rootKeys = await generateRsa();
  const root = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: '01',
    name: 'CN=Test Huawei CBG Root CA',
    notBefore: new Date('2017-01-01T00:00:00Z'),
    notAfter: new Date('2042-01-01T00:00:00Z'),
    keys: rootKeys,
    signingAlgorithm: RSA,
    extensions: [new x509.BasicConstraintsExtension(true, undefined, true)],
  });
  const caKeys = await generateRsa();
  const ca = await x509.X509CertificateGenerator.create({
    serialNumber: '02',
    subject: 'CN=Test Huawei CBG Application Integration CA',
    issuer: root.subject,
    notBefore: new Date('2020-01-01T00:00:00Z'),
    notAfter: new Date('2035-01-01T00:00:00Z'),
    publicKey: caKeys.publicKey,
    signingKey: rootKeys.privateKey,
    signingAlgorithm: RSA,
    extensions: [new x509.BasicConstraintsExtension(true, 0, true)],
  });
  const leafKeys = await generateRsa();
  const leaf = await x509.X509CertificateGenerator.create({
    serialNumber: '03',
    subject: `CN=${hostname}`,
    issuer: ca.subject,
    notBefore: new Date('2025-01-01T00:00:00Z'),
    notAfter: new Date('2028-01-01T00:00:00Z'),
    publicKey: leafKeys.publicKey,
    signingKey: caKeys.privateKey,
    signingAlgorithm: RSA,
    extensions: [new x509.SubjectAlternativeNameExtension([{ type: 'dns', value: hostname }])],
  });
  const toKey = (c: x509.X509Certificate) =>
    crypto.createPublicKey({ key: Buffer.from(c.publicKey.rawData), format: 'der', type: 'spki' });
  return {
    root: toKey(root),
    x5c: [leaf, ca].map((c) => Buffer.from(c.rawData).toString('base64')),
    leafKey: crypto.KeyObject.from(leafKeys.privateKey),
  };
};

/**
 * Signs a SysIntegrity result as the Huawei service does.
 */
const signSysIntegrity = (
  pki: HuaweiPki,
  payload: Record<string, unknown>,
  alg: 'RS256' | 'PS256' = 'PS256'
) => {
  const encode = (value: unknown) =>
    Buffer.from(JSON.stringify(value)).toString('base64url');
  const signingInput = `${encode({ alg, x5c: pki.x5c })}.${encode(payload)}`;
  const signature = crypto.sign(
    'sha256',
    Buffer.from(signingInput),
    alg === 'PS256'
      ? { key: pki.leafKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }
      : pki.leafKey
  );
  return `${signingInput}.${signature.toString('base64url')}`;
};

const payloadFor = (nonce: Buffer, overrides: Record<string, unknown> = {}) => ({
  advice: '',
  apkCertificateDigestSha256: [Buffer.from(SIGNATURE_DIGEST, 'hex').toString('base64')],
  apkDigestSha256: Buffer.alloc(32, 1).toString('base64'),
  apkPackageName: PACKAGE_NAME,
  basicIntegrity: true,
  nonce: nonce.toString('base64'),
  timestampMs: NOW.getTime() - 5000,
  ...overrides,
});

describe('verifySysIntegrity', () => {
  let pki: HuaweiPki;
  const nonce = crypto.randomBytes(32);

  before(async () => {
    pki = await createHuaweiPki();
  });

  const options = (overrides = {}) => ({
    expectedNonce: nonce,
    packageNames: [PACKAGE_NAME],
    signatureDigests: [SIGNATURE_DIGEST],
    rootPublicKeys: [pki.root],
    now: NOW,
    ...overrides,
  });

  for (const alg of ['RS256', 'PS256'] as const) {
    it(`accepts a valid ${alg} result`, () => {
      const result = verifySysIntegrity(signSysIntegrity(pki, payloadFor(nonce), alg), options());
      assert.equal(result.alg, alg);
      assert.equal(result.payload.basicIntegrity, true);
    });
  }

  it('pins the real HUAWEI CBG Root CA by default', () => {
    const [root] = getHuaweiRootPublicKeys();
    assert.equal(root?.asymmetricKeyType, 'rsa');
    assert.throws(
      () => verifySysIntegrity(signSysIntegrity(pki, payloadFor(nonce)), { ...options(), rootPublicKeys: undefined }),
      /not issued by the HUAWEI CBG Root CA/
    );
  });

  const rejections: [string, () => string, RegExp][] = [
    ['another nonce', () => signSysIntegrity(pki, payloadFor(crypto.randomBytes(32))), /nonce mismatch/],
    ['an old result', () => signSysIntegrity(pki, payloadFor(nonce, { timestampMs: NOW.getTime() - 11 * 60 * 1000 })), /too old/],
    ['another package', () => signSysIntegrity(pki, payloadFor(nonce, { apkPackageName: 'com.example' })), /Invalid package name/],
    ['another signing certificate', () => signSysIntegrity(pki, payloadFor(nonce, { apkCertificateDigestSha256: [Buffer.alloc(32).toString('base64')] })), /Invalid app signing certificate/],
    ['a device without basic integrity', () => signSysIntegrity(pki, payloadFor(nonce, { basicIntegrity: false, advice: 'RESTORE_TO_FACTORY_ROM' })), /basic integrity \(advice: RESTORE_TO_FACTORY_ROM\)/],
    ['a tampered payload', () => {
      const [header, , signature] = signSysIntegrity(pki, payloadFor(nonce, { basicIntegrity: false })).split('.');
      const forged = Buffer.from(JSON.stringify(payloadFor(nonce))).toString('base64url');
      return `${header}.${forged}.${signature}`;
    }, /Invalid SysIntegrity signature/],
    ['an unsupported algorithm', () => {
      const [, payload, signature] = signSysIntegrity(pki, payloadFor(nonce)).split('.');
      const header = Buffer.from(JSON.stringify({ alg: 'none', x5c: pki.x5c })).toString('base64url');
      return `${header}.${payload}.${signature}`;
    }, /Unsupported SysIntegrity algorithm/],
    ['a value which is not a JWS', () => 'not-a-jws', /compact JWS/],
  ];

  for (const [name, jws, error] of rejections) {
    it(`rejects ${name}`, () => {
      assert.throws(() => verifySysIntegrity(jws(), options()), error);
    });
  }

  it('rejects a result signed for another hostname', async () => {
    const other = await createHuaweiPki('attacker.example');
    assert.throws(
      () => verifySysIntegrity(signSysIntegrity(other, payloadFor(nonce)), options({ rootPublicKeys: [other.root] })),
      /not issued to sysintegrity\.platform\.hicloud\.com/
    );
  });

  it('requires the app signing certificate digests', () => {
    assert.throws(
      () => verifySysIntegrity(signSysIntegrity(pki, payloadFor(nonce)), options({ signatureDigests: [] })),
      /digests are required/
    );
  });
});

/**
 * Creates a root like the AOSP software attestation root, which signs the key attestations of the
 * Huawei devices without GMS.
 */
const createSoftwareRoot = async (): Promise<TestRoot> => {
  const keys = (await crypto.webcrypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify']
  )) as crypto.webcrypto.CryptoKeyPair;
  const certificate = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: '01',
    name: 'CN=Android Keystore Software Attestation Root',
    notBefore: new Date('2016-01-01T00:00:00Z'),
    notAfter: new Date('2036-01-01T00:00:00Z'),
    keys,
    signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
  });
  return {
    keys,
    certificate,
    publicKey: crypto.createPublicKey({
      key: Buffer.from(certificate.publicKey.rawData),
      format: 'der',
      type: 'spki',
    }),
  };
};

describe('Huawei registration and assertion', () => {
  // The trusted hardware root (Google) and the AOSP software root of the Huawei devices
  let root: TestRoot;
  let softwareRoot: TestRoot;
  let pki: HuaweiPki;

  before(async () => {
    root = await createTestRoot();
    softwareRoot = await createSoftwareRoot();
    pki = await createHuaweiPki();
  });

  const deps = (env: Record<string, string> = { HUAWEI_SYSINTEGRITY: 'true' }): ServiceDeps => {
    const { challenge: _, ...options } = testOptions(root);
    return {
      config: getConfig({ SERVER_SECRET: SECRET, ...env }),
      verificationOptions: options,
      huaweiRootPublicKeys: [pki.root],
      now: () => NOW.getTime(),
    };
  };

  type Body = Record<string, unknown>;

  /**
   * Registers a device whose key attestation is signed by the AOSP software root (unlocked and
   * unverified, as reported by the Huawei devices), with a SysIntegrity result bound to the challenge
   * and the key. With the hardware root, the chain is a Google one rejected by the policy.
   */
  const registerHuawei = async (
    serviceDeps = deps(),
    nonce?: (challenge: string, key: crypto.KeyObject) => Buffer,
    attestationRoot: TestRoot = softwareRoot
  ) => {
    const { challenge } = (await getChallenge(serviceDeps)).body as { challenge: string };
    const attestation = await createAttestation(
      attestationRoot,
      stockParams({ challenge, deviceLocked: false, verifiedBootState: VerifiedBootState.unverified }),
      { attestKey: null }
    );
    const hardwareKey = parseCertificateChain(attestation.encoded)[0]!.publicKey;
    const sysIntegrity = signSysIntegrity(
      pki,
      payloadFor((nonce ?? registrationNonce)(challenge, hardwareKey))
    );
    const response = (await register(
      { challenge, certificates: attestation.encoded, sysIntegrity },
      serviceDeps
    )) as { status: number; body: Body };
    return { attestation, response };
  };

  const assertion = async (
    privateKey: crypto.KeyObject,
    registration: string,
    nonce: (clientData: string) => Buffer = assertionNonce,
    serviceDeps = deps()
  ) => {
    const { challenge } = (await getChallenge(serviceDeps)).body as { challenge: string };
    const clientData = JSON.stringify({ challenge });
    return {
      registration,
      clientData,
      signature: crypto.createSign('SHA256').update(clientData).sign(privateKey, 'base64'),
      sysIntegrity: signSysIntegrity(pki, payloadFor(nonce(clientData))),
    };
  };

  it('registers a device through SysIntegrity when its key attestation is rejected', async () => {
    const { attestation, response } = await registerHuawei();
    assert.equal(response.status, 200, JSON.stringify(response.body));
    assert.equal(response.body.method, 'huawei_sysintegrity');
    assert.equal(response.body.hardwareKeyProven, false);
    assert.match(response.body.keyAttestationError as string, /Software attestation/);

    const body = await assertion(attestation.privateKey, response.body.registration as string);
    const result = await assertEndpoint(body, deps());
    assert.equal(result.status, 200, JSON.stringify(result.body));
    assert.equal((result.body as Body).method, 'huawei_sysintegrity');
  });

  it('does not accept SysIntegrity unless enabled', async () => {
    const { response } = await registerHuawei(deps({}));
    assert.equal(response.status, 422);
    assert.match(response.body.error as string, /Software attestation/);
  });

  it('never overrides a hardware key attestation rejected by the policy', async () => {
    const { response } = await registerHuawei(deps(), undefined, root);
    assert.equal(response.status, 422);
    assert.match(response.body.error as string, /^Bootloader is unlocked$/);
  });

  it('binds the registration result to the registered key', async () => {
    const otherKey = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey;
    const { response } = await registerHuawei(deps(), (challenge) => registrationNonce(challenge, otherKey));
    assert.equal(response.status, 422);
    assert.match(response.body.error as string, /SysIntegrity: SysIntegrity nonce mismatch/);
  });

  it('binds the assertion result to the client data', async () => {
    const { attestation, response } = await registerHuawei();
    const body = await assertion(
      attestation.privateKey,
      response.body.registration as string,
      () => crypto.randomBytes(32)
    );
    const result = await assertEndpoint(body, deps());
    assert.equal(result.status, 422);
    assert.match((result.body as Body).error as string, /nonce mismatch/);
  });

  it('rejects an assertion signed with another key', async () => {
    const { response } = await registerHuawei();
    const other = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey;
    const result = await assertEndpoint(
      await assertion(other, response.body.registration as string),
      deps()
    );
    assert.equal(result.status, 422);
    assert.match((result.body as Body).error as string, /Invalid hardware signature/);
  });

  it('rejects the assertions when SysIntegrity is disabled after the registration', async () => {
    const { attestation, response } = await registerHuawei();
    const result = await assertEndpoint(
      await assertion(attestation.privateKey, response.body.registration as string),
      deps({})
    );
    assert.equal(result.status, 422);
    assert.match((result.body as Body).error as string, /not accepted/);
  });
});

describe('software attestation', () => {
  it('rejects a chain of the AOSP software attestation root with an explicit reason', async () => {
    const keys = (await crypto.webcrypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify']
    )) as crypto.webcrypto.CryptoKeyPair;
    const softRoot = await x509.X509CertificateGenerator.createSelfSigned({
      serialNumber: '01',
      name: 'CN=Android Keystore Software Attestation Root',
      notBefore: new Date('2016-01-01T00:00:00Z'),
      notAfter: new Date('2036-01-01T00:00:00Z'),
      keys,
      signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
    });
    const root: TestRoot = {
      keys,
      certificate: softRoot,
      publicKey: crypto.createPublicKey({ key: Buffer.from(softRoot.publicKey.rawData), format: 'der', type: 'spki' }),
    };
    const attestation = await createAttestation(root, stockParams(), { attestKey: null });
    await assert.rejects(
      verifyAttestation(parseCertificateChain(attestation.encoded), testOptions(root)),
      /Software attestation: the chain is signed with the public AOSP software attestation key/
    );
  });
});
