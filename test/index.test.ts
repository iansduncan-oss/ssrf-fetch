import { describe, it, expect, vi, afterEach } from 'vitest';
import { addressIsBlocked, safeFetch } from '../src/index.js';

describe('addressIsBlocked', () => {
  it('blocks loopback / private / link-local / CGNAT IPv4', () => {
    for (const ip of [
      '127.0.0.1',
      '10.1.2.3',
      '172.16.0.1',
      '172.31.255.255',
      '192.168.1.1',
      '169.254.169.254', // cloud metadata
      '100.64.0.1', // CGNAT
      '0.0.0.0',
    ]) {
      expect(addressIsBlocked(ip), ip).toBe(true);
    }
  });

  it('allows public IPv4', () => {
    for (const ip of ['1.1.1.1', '8.8.8.8', '93.184.216.34']) {
      expect(addressIsBlocked(ip), ip).toBe(false);
    }
  });

  it('blocks loopback / link-local / ULA IPv6 and v4-mapped internals', () => {
    for (const ip of ['::1', '::', 'fe80::1', 'fc00::1', 'fd12::1', '::ffff:127.0.0.1']) {
      expect(addressIsBlocked(ip), ip).toBe(true);
    }
  });

  it('blocks unknown address families', () => {
    expect(addressIsBlocked('not-an-ip')).toBe(true);
  });
});

describe('safeFetch', () => {
  afterEach(() => vi.restoreAllMocks());

  it('rejects non-http(s) protocols before resolving', async () => {
    await expect(safeFetch('file:///etc/passwd')).rejects.toThrow(/blocked protocol/);
    await expect(safeFetch('gopher://x')).rejects.toThrow(/blocked protocol/);
  });

  it('rejects a hostname that resolves to an internal address', async () => {
    const dns = await import('node:dns/promises');
    vi.spyOn(dns.default, 'lookup').mockResolvedValue([
      { address: '169.254.169.254', family: 4 },
    ] as never);
    await expect(safeFetch('http://metadata.evil.test/latest')).rejects.toThrow(/blocked host/);
  });

  it('rejects when ANY resolved address is internal (multi-record)', async () => {
    const dns = await import('node:dns/promises');
    vi.spyOn(dns.default, 'lookup').mockResolvedValue([
      { address: '93.184.216.34', family: 4 },
      { address: '10.0.0.5', family: 4 }, // one internal → whole host blocked
    ] as never);
    await expect(safeFetch('http://split.evil.test/')).rejects.toThrow(/blocked host/);
  });
});
