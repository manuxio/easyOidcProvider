/**
 * Phase 4-bis: TOTP seeds read from an AD attribute (src/twofactor/ldapSeedSource.ts),
 * over a fake directory standing in for LdapDirectory.readUserAttribute.
 *
 * The source adds no connection logic of its own, so what is pinned is the
 * translation: the attribute named by TWO_FACTOR_LDAP_ATTRIBUTE is asked for
 * the platform username, a missing value is "not enrolled" (undefined), and
 * ANY failure of the directory is TwoFactorSeedUnavailable — never "no seed".
 */
import { describe, expect, it } from 'vitest';

import { LdapUnavailableError, type LdapDirectory } from '../../src/identity/ldap.js';
import { createSilentLogger } from '../../src/logger.js';
import { createLdapSeedSource, TwoFactorSeedUnavailable } from '../../src/twofactor/index.js';
import { createCapturingLogger } from '../helpers/captureLogger.js';

const SEED = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';

/** The one method the seed source calls, scripted, with every call recorded. */
class FakeAttributeDirectory {
  readonly calls: Array<{ username: string; attribute: string }> = [];
  readonly values = new Map<string, string>();
  failWith?: unknown;

  async readUserAttribute(username: string, attribute: string): Promise<string | undefined> {
    this.calls.push({ username, attribute });
    if (this.failWith !== undefined) throw this.failWith;
    return this.values.get(username);
  }
}

function sourceOver(directory: FakeAttributeDirectory, logger = createSilentLogger()) {
  return createLdapSeedSource({
    directory: directory as unknown as LdapDirectory,
    attribute: 'extensionAttribute7',
    logger,
  });
}

describe('the LDAP seed source', () => {
  it('is named after the attribute it reads', () => {
    expect(sourceOver(new FakeAttributeDirectory()).name).toBe('ldap:extensionAttribute7');
  });

  it('reads the configured attribute of the username and returns the value as is', async () => {
    const directory = new FakeAttributeDirectory();
    directory.values.set('mario.rossi', SEED);
    await expect(sourceOver(directory).lookup('mario.rossi')).resolves.toBe(SEED);
    expect(directory.calls).toEqual([{ username: 'mario.rossi', attribute: 'extensionAttribute7' }]);
  });

  it('answers undefined when the attribute is absent: not enrolled, not an outage', async () => {
    const capture = createCapturingLogger();
    const source = sourceOver(new FakeAttributeDirectory(), capture.logger);
    await expect(source.lookup('luigi.verdi')).resolves.toBeUndefined();
    expect(capture.matching('two-factor seed lookup completed')[0]).toMatchObject({
      level: 'debug',
      component: 'two-factor.ldap',
      attribute: 'extensionAttribute7',
      username: 'luigi.verdi',
      found: false,
    });
  });

  it('never logs the seed itself', async () => {
    const capture = createCapturingLogger();
    const directory = new FakeAttributeDirectory();
    directory.values.set('mario.rossi', SEED);
    await sourceOver(directory, capture.logger).lookup('mario.rossi');
    expect(capture.matching('two-factor seed lookup completed')[0]).toMatchObject({ found: true });
    expect(capture.text()).not.toContain(SEED);
  });

  it('turns a directory outage into TwoFactorSeedUnavailable, keeping the cause', async () => {
    const directory = new FakeAttributeDirectory();
    const outage = new LdapUnavailableError('attribute lookup', new Error('connect ETIMEDOUT'));
    directory.failWith = outage;

    const failure = await sourceOver(directory).lookup('mario.rossi').catch((error: unknown) => error) as TwoFactorSeedUnavailable;
    expect(failure).toBeInstanceOf(TwoFactorSeedUnavailable);
    expect(failure.name).toBe('TwoFactorSeedUnavailable');
    expect(failure.source).toBe('ldap');
    expect(failure.message).toBe('LDAP attribute lookup failed: connect ETIMEDOUT');
    expect(failure.cause).toBe(outage);
  });

  it('turns any other error into TwoFactorSeedUnavailable too', async () => {
    const directory = new FakeAttributeDirectory();
    directory.failWith = new TypeError('cannot read properties of undefined');
    await expect(sourceOver(directory).lookup('mario.rossi')).rejects.toMatchObject({
      name: 'TwoFactorSeedUnavailable',
      message: 'cannot read properties of undefined',
    });
  });

  it('turns a thrown non-Error into its string form', async () => {
    const directory = new FakeAttributeDirectory();
    directory.failWith = 'directory said no';
    await expect(sourceOver(directory).lookup('mario.rossi')).rejects.toThrow('directory said no');
  });

  it('owns nothing: close resolves and the directory keeps working', async () => {
    const directory = new FakeAttributeDirectory();
    directory.values.set('mario.rossi', SEED);
    const source = sourceOver(directory);
    await expect(source.close()).resolves.toBeUndefined();
    await expect(source.close()).resolves.toBeUndefined();
    await expect(source.lookup('mario.rossi')).resolves.toBe(SEED);
  });
});
