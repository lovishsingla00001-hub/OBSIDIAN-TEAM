/**
 * @fileoverview Secure URL validation, SSRF protection, homepage fetching, TLS inspection, and well-known path probing engine.
 *
 * TEAM: Obsidian
 * ROLE: Engine Lead
 * CURRENT TASK: Well-Known Path GET Probing
 */

const http = require('http');
const https = require('https');
const tls = require('tls');
const { URL } = require('url');
const dns = require('dns').promises;
const net = require('net');

/** Standard browser-like User-Agent string */
const USER_AGENT =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 SiteCheck/1.0';

/** Maximum timeout per HTTP/HTTPS/TLS request in milliseconds (8 seconds) */
const DEFAULT_TIMEOUT_MS = 8000;

/** Maximum redirect hops allowed */
const MAX_REDIRECTS = 5;

/** Maximum allowed response body size (2 MB) */
const MAX_BODY_BYTES = 2 * 1024 * 1024;

/** Exactly four permitted well-known paths (strict legal boundary) */
const WELL_KNOWN_PATHS = [
  '/.git/HEAD',
  '/.env',
  '/robots.txt',
  '/sitemap.xml',
];

/**
 * Normalizes and validates an input URL.
 *
 * - Accepts bare domains (e.g., 'example.com' -> 'https://example.com')
 * - Accepts 'https://example.com' and 'http://example.com'
 * - Rejects non-HTTP/HTTPS protocols
 * - Rejects URLs containing credentials (user:pass)
 * - Rejects localhost and *.localhost domains
 *
 * @param {string} inputUrl - The raw input URL or domain string.
 * @returns {URL} Parsed and normalized WHATWG URL object.
 * @throws {Error} If the URL format is invalid, uses forbidden protocols, or contains credentials.
 */
function normalizeUrl(inputUrl) {
  if (typeof inputUrl !== 'string' || !inputUrl.trim()) {
    throw new Error('Invalid URL: Input must be a non-empty string');
  }

  let trimmed = inputUrl.trim();

  // Determine if input has an explicit protocol/scheme or is a bare domain / host:port
  let toParse = trimmed;
  if (/^https?:\/\//i.test(trimmed)) {
    toParse = trimmed;
  } else {
    // Check if input contains userinfo '@' before any path delimiter (e.g. user:pass@example.com)
    const slashIdx = trimmed.indexOf('/');
    const atIdx = trimmed.indexOf('@');
    if (atIdx !== -1 && (slashIdx === -1 || atIdx < slashIdx)) {
      toParse = 'https://' + trimmed;
    } else if (/^[a-zA-Z0-9.-]+:[0-9]+(\/|$)/.test(trimmed)) {
      // Target is in host:port format (e.g., example.com:8443) -> default to https://
      toParse = 'https://' + trimmed;
    } else if (/^[a-zA-Z][a-zA-Z0-9+.-]*:/i.test(trimmed)) {
      // Explicit non-HTTP scheme (e.g., ftp://, file://, javascript:, data:)
      toParse = trimmed;
    } else {
      // Bare domain (e.g., example.com or example.com/path) -> default to https://
      toParse = 'https://' + trimmed;
    }
  }

  let parsed;
  try {
    parsed = new URL(toParse);
  } catch (err) {
    throw new Error('Invalid URL: Malformed URL format');
  }

  // Enforce HTTP / HTTPS protocols only
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error(`Invalid protocol '${parsed.protocol}': Only HTTP and HTTPS are permitted`);
  }

  // Reject URLs containing credentials
  if (parsed.username || parsed.password) {
    throw new Error('Invalid URL: URLs containing user credentials are not allowed');
  }

  // Validate hostname exists
  if (!parsed.hostname) {
    throw new Error('Invalid URL: Missing hostname');
  }

  const lowerHost = parsed.hostname.toLowerCase();

  // Reject localhost and localhost subdomains
  if (lowerHost === 'localhost' || lowerHost.endsWith('.localhost')) {
    throw new Error('Access to localhost is prohibited');
  }

  return parsed;
}

/**
 * Expands and parses an IPv6 address string into an array of 8 16-bit integers.
 * Handles IPv4-mapped IPv6 (::ffff:192.168.1.1) and zero compression (::).
 *
 * @param {string} ip
 * @returns {number[] | null} Array of 8 16-bit numbers, or null if invalid.
 */
function parseIpv6Chunks(ip) {
  let clean = ip.replace(/^\[|\]$/g, '').toLowerCase();

  // Check for IPv4-mapped IPv6 embedded notation (e.g., ::ffff:192.168.1.1)
  const lastColon = clean.lastIndexOf(':');
  if (lastColon !== -1 && clean.slice(lastColon + 1).includes('.')) {
    const v4Part = clean.slice(lastColon + 1);
    const v4Octets = v4Part.split('.').map(Number);
    if (v4Octets.length !== 4 || v4Octets.some(o => isNaN(o) || o < 0 || o > 255)) {
      return null;
    }
    const hex1 = ((v4Octets[0] << 8) | v4Octets[1]).toString(16);
    const hex2 = ((v4Octets[2] << 8) | v4Octets[3]).toString(16);
    clean = clean.slice(0, lastColon) + ':' + hex1 + ':' + hex2;
  }

  const parts = clean.split('::');
  if (parts.length > 2) return null; // More than one '::' is invalid

  let chunks = [];
  if (parts.length === 2) {
    const left = parts[0] ? parts[0].split(':') : [];
    const right = parts[1] ? parts[1].split(':') : [];
    const missing = 8 - (left.length + right.length);
    if (missing < 1) return null;
    chunks = [...left, ...Array(missing).fill('0'), ...right];
  } else {
    chunks = clean.split(':');
  }

  if (chunks.length !== 8) return null;

  const numbers = [];
  for (const chunk of chunks) {
    if (!/^[0-9a-f]{1,4}$/.test(chunk)) return null;
    numbers.push(parseInt(chunk, 16));
  }
  return numbers;
}

/**
 * Checks whether an IP address belongs to private, loopback, link-local,
 * multicast, or reserved ranges (IPv4 and IPv6).
 *
 * @param {string} ip - IPv4 or IPv6 address.
 * @returns {boolean} True if the IP is private or reserved; false if public.
 */
function isPrivateOrReservedIp(ip) {
  const ipType = net.isIP(ip);
  if (ipType === 0) {
    return true; // Malformed IP; fail closed
  }

  if (ipType === 4) {
    const octets = ip.split('.').map(Number);
    if (octets.length !== 4 || octets.some(o => isNaN(o) || o < 0 || o > 255)) {
      return true; // Fail closed
    }

    const [o0, o1, o2] = octets;

    // 0.0.0.0/8 - Current network
    if (o0 === 0) return true;

    // 10.0.0.0/8 - Private-Use (RFC 1918)
    if (o0 === 10) return true;

    // 100.64.0.0/10 - Shared Address Space / CGNAT (RFC 6598)
    if (o0 === 100 && o1 >= 64 && o1 <= 127) return true;

    // 127.0.0.0/8 - Loopback (RFC 1122)
    if (o0 === 127) return true;

    // 169.254.0.0/16 - Link-Local (RFC 3927) & Cloud Metadata Services
    if (o0 === 169 && o1 === 254) return true;

    // 172.16.0.0/12 - Private-Use (RFC 1918)
    if (o0 === 172 && o1 >= 16 && o1 <= 31) return true;

    // 192.0.0.0/24 - IETF Protocol Assignments
    if (o0 === 192 && o1 === 0 && o2 === 0) return true;

    // 192.0.2.0/24 - Documentation (TEST-NET-1)
    if (o0 === 192 && o1 === 0 && o2 === 2) return true;

    // 192.88.99.0/24 - 6to4 Relay Anycast (RFC 7526)
    if (o0 === 192 && o1 === 88 && o2 === 99) return true;

    // 192.168.0.0/16 - Private-Use (RFC 1918)
    if (o0 === 192 && o1 === 168) return true;

    // 198.18.0.0/15 - Benchmarking (RFC 2544)
    if (o0 === 198 && (o1 === 18 || o1 === 19)) return true;

    // 198.51.100.0/24 - Documentation (TEST-NET-2)
    if (o0 === 198 && o1 === 51 && o2 === 100) return true;

    // 203.0.113.0/24 - Documentation (TEST-NET-3)
    if (o0 === 203 && o1 === 0 && o2 === 113) return true;

    // 224.0.0.0/4 - Multicast (RFC 5771)
    if (o0 >= 224 && o0 <= 239) return true;

    // 240.0.0.0/4 - Reserved for future use / Broadcast (RFC 1112)
    if (o0 >= 240) return true;

    return false;
  }

  if (ipType === 6) {
    const chunks = parseIpv6Chunks(ip);
    if (!chunks) return true; // Malformed; fail closed

    // :: (Unspecified address)
    if (chunks.every(c => c === 0)) return true;

    // ::1 (Loopback)
    if (chunks.slice(0, 7).every(c => c === 0) && chunks[7] === 1) return true;

    // ::ffff:0:0/96 (IPv4-mapped IPv6)
    if (chunks.slice(0, 5).every(c => c === 0) && chunks[5] === 0xffff) {
      const v4 = `${chunks[6] >> 8}.${chunks[6] & 0xff}.${chunks[7] >> 8}.${chunks[7] & 0xff}`;
      return isPrivateOrReservedIp(v4);
    }

    // fc00::/7 - Unique Local Addresses (ULA / RFC 4193)
    if ((chunks[0] & 0xfe00) === 0xfc00) return true;

    // fe80::/10 - Link-Local Unicast (RFC 4291)
    if ((chunks[0] & 0xffc0) === 0xfe80) return true;

    // ff00::/8 - Multicast (RFC 4291)
    if ((chunks[0] & 0xff00) === 0xff00) return true;

    // 2001:db8::/32 - Documentation (RFC 3849)
    if (chunks[0] === 0x2001 && chunks[1] === 0x0db8) return true;

    // 2001:10::/28 & 2001:20::/28 - ORCHID (RFC 4843 & RFC 7343)
    if (chunks[0] === 0x2001 && ((chunks[1] & 0xfff0) === 0x0010 || (chunks[1] & 0xfff0) === 0x0020)) return true;

    // 64:ff9b::/96 - IPv4/IPv6 Translation (RFC 6052)
    if (chunks[0] === 0x0064 && chunks[1] === 0xff9b && chunks.slice(2, 6).every(c => c === 0)) {
      const v4 = `${chunks[6] >> 8}.${chunks[6] & 0xff}.${chunks[7] >> 8}.${chunks[7] & 0xff}`;
      return isPrivateOrReservedIp(v4);
    }

    // 100::/64 - Discard-Only (RFC 6666)
    if (chunks[0] === 0x0100 && chunks.slice(1, 4).every(c => c === 0)) return true;

    return false;
  }

  return true; // Unknown address type; fail closed
}

/**
 * Resolves a hostname via DNS and validates that none of the resolved IPs
 * point to private, loopback, or reserved destinations.
 *
 * @param {string} hostname - Domain or IP string to validate.
 * @returns {Promise<{ primaryIp: string, family: number, allIps: string[] }>}
 * @throws {Error} If DNS resolution fails or resolves to restricted IP addresses.
 */
async function validateDestination(hostname) {
  if (!hostname || typeof hostname !== 'string') {
    throw new Error('Destination validation error: Invalid hostname');
  }

  const cleanHost = hostname.replace(/^\[|\]$/g, '').toLowerCase();

  // If hostname is directly an IP literal
  if (net.isIP(cleanHost)) {
    if (isPrivateOrReservedIp(cleanHost)) {
      throw new Error('Security Error: Target resolves to a restricted or private IP address');
    }
    return {
      primaryIp: cleanHost,
      family: net.isIP(cleanHost),
      allIps: [cleanHost],
    };
  }

  // Resolve DNS before connecting
  let records;
  try {
    records = await dns.lookup(cleanHost, { all: true });
  } catch (err) {
    throw new Error(`DNS resolution failed for hostname '${cleanHost}': ${err.code || 'Host not found'}`);
  }

  if (!records || records.length === 0) {
    throw new Error(`DNS resolution failed: No IP addresses found for '${cleanHost}'`);
  }

  // Validate every resolved IP address
  for (const record of records) {
    if (isPrivateOrReservedIp(record.address)) {
      // Do not expose internal IP address in client-facing error message
      throw new Error('Security Error: Target resolves to a restricted or private IP address');
    }
  }

  return {
    primaryIp: records[0].address,
    family: records[0].family,
    allIps: records.map(r => r.address),
  };
}

/**
 * Validates a redirect destination independently.
 *
 * Enforces:
 * 1. Protocol must remain HTTP or HTTPS.
 * 2. Destination hostname must match the originally submitted hostname (same-host restriction).
 * 3. Redirect target must not resolve to any internal or private IP address.
 *
 * @param {URL} originalUrl - The original validated URL.
 * @param {string} redirectLocation - The Location header value from redirect response.
 * @returns {Promise<{ redirectUrl: URL, primaryIp: string, family: number }>}
 * @throws {Error} If redirect violates hostname boundaries, protocols, or SSRF rules.
 */
async function validateRedirect(originalUrl, redirectLocation) {
  if (!redirectLocation || typeof redirectLocation !== 'string') {
    throw new Error('Invalid redirect: Missing Location header');
  }

  let redirectUrl;
  try {
    redirectUrl = new URL(redirectLocation, originalUrl);
  } catch (err) {
    throw new Error('Invalid redirect: Malformed Location header');
  }

  // Protocol check
  if (redirectUrl.protocol !== 'http:' && redirectUrl.protocol !== 'https:') {
    throw new Error(`Invalid redirect protocol '${redirectUrl.protocol}': Only HTTP and HTTPS are permitted`);
  }

  // Credentials check
  if (redirectUrl.username || redirectUrl.password) {
    throw new Error('Invalid redirect: URLs containing user credentials are not allowed');
  }

  // Same hostname restriction: SiteCheck is restricted to the originally submitted hostname
  if (redirectUrl.hostname.toLowerCase() !== originalUrl.hostname.toLowerCase()) {
    throw new Error(
      `Redirect rejected: Cross-hostname redirect from '${originalUrl.hostname}' to '${redirectUrl.hostname}' is prohibited`
    );
  }

  // Validate destination IP before following redirect
  const destination = await validateDestination(redirectUrl.hostname);

  return {
    redirectUrl,
    primaryIp: destination.primaryIp,
    family: destination.family,
  };
}

/**
 * Custom DNS lookup helper to bind connections to the pre-validated IP address,
 * completely preventing Time-of-Check to Time-of-Use (TOCTOU) DNS rebinding attacks.
 *
 * @param {string} pinnedIp - The validated public IP address.
 * @param {number} family - 4 or 6.
 * @returns {Function} Custom lookup function compatible with http.Agent / https.Agent options.lookup.
 */
function createPinnedLookup(pinnedIp, family) {
  return function pinnedLookup(hostname, options, callback) {
    if (typeof options === 'function') {
      callback = options;
      options = {};
    }

    if (options && options.all) {
      return callback(null, [{ address: pinnedIp, family }]);
    }
    return callback(null, pinnedIp, family);
  };
}

/**
 * Combined normalization and destination validation helper.
 *
 * @param {string} inputUrl - Raw user input URL or domain.
 * @returns {Promise<{ parsedUrl: URL, primaryIp: string, family: number, allIps: string[] }>}
 */
async function validateUrlAndDestination(inputUrl) {
  const parsedUrl = normalizeUrl(inputUrl);
  const destination = await validateDestination(parsedUrl.hostname);

  return {
    parsedUrl,
    primaryIp: destination.primaryIp,
    family: destination.family,
    allIps: destination.allIps,
  };
}

/**
 * Performs a single HTTP or HTTPS GET request using pinned DNS lookup.
 * Does NOT execute scripts, download external resources, or follow redirects automatically.
 *
 * @param {URL} targetUrl - Target URL to request.
 * @param {string} primaryIp - Pre-validated public IP address.
 * @param {number} family - IP family (4 or 6).
 * @param {Object} [options] - Configuration options.
 * @param {number} [options.timeoutMs] - Request timeout in milliseconds (default 8000ms).
 * @param {number} [options.maxBodyBytes] - Maximum response body size in bytes (default 2 MB).
 * @param {Object} [options.headers] - Additional HTTP request headers.
 * @returns {Promise<{ statusCode: number, headers: Record<string, string>, body: string, isRedirect: boolean, location: string | null }>}
 */
function fetchSingleGet(targetUrl, primaryIp, family, options = {}) {
  return new Promise((resolve, reject) => {
    const isHttps = targetUrl.protocol === 'https:';
    const client = isHttps ? https : http;

    const timeoutMs = options.timeoutMs !== undefined ? options.timeoutMs : DEFAULT_TIMEOUT_MS;
    const maxBodyBytes = options.maxBodyBytes !== undefined ? options.maxBodyBytes : MAX_BODY_BYTES;
    const pinnedLookup = createPinnedLookup(primaryIp, family);

    const reqOptions = {
      protocol: targetUrl.protocol,
      hostname: targetUrl.hostname,
      port: targetUrl.port || (isHttps ? 443 : 80),
      path: targetUrl.pathname + targetUrl.search,
      method: 'GET',
      headers: {
        'User-Agent': USER_AGENT,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Connection': 'close',
        ...(options.headers || {}),
      },
      lookup: pinnedLookup,
      timeout: timeoutMs,
    };

    let settled = false;

    function fail(err) {
      if (!settled) {
        settled = true;
        reject(err);
      }
    }

    const req = client.request(reqOptions, (res) => {
      const statusCode = res.statusCode || 0;
      const isRedirect = statusCode >= 300 && statusCode < 400 && Boolean(res.headers.location);
      const location = res.headers.location || null;

      // Normalize all response headers to a plain JavaScript object with lowercase keys
      const headers = {};
      for (const [key, val] of Object.entries(res.headers)) {
        headers[key.toLowerCase()] = Array.isArray(val) ? val.join(', ') : (val || '');
      }

      // If response is a redirect, drain response stream immediately without reading large body
      if (isRedirect) {
        res.resume();
        res.on('end', () => {
          if (!settled) {
            settled = true;
            resolve({
              statusCode,
              headers,
              body: '',
              isRedirect: true,
              location,
            });
          }
        });
        return;
      }

      let totalBytes = 0;
      const chunks = [];

      res.on('data', (chunk) => {
        totalBytes += chunk.length;
        if (totalBytes > maxBodyBytes) {
          res.destroy();
          req.destroy(new Error(`Response body exceeded maximum size limit of ${maxBodyBytes} bytes`));
        } else {
          chunks.push(chunk);
        }
      });

      res.on('end', () => {
        if (!settled) {
          settled = true;
          const body = Buffer.concat(chunks).toString('utf8');
          resolve({
            statusCode,
            headers,
            body,
            isRedirect: false,
            location: null,
          });
        }
      });

      res.on('error', (err) => {
        fail(err);
      });
    });

    req.setTimeout(timeoutMs, () => {
      req.destroy(new Error(`Request timed out after ${timeoutMs}ms`));
    });

    req.on('timeout', () => {
      req.destroy(new Error(`Request timed out after ${timeoutMs}ms`));
    });

    req.on('error', (err) => {
      fail(err);
    });

    req.end();
  });
}

/**
 * Fetches the homepage of a target website with full SSRF protection and manual redirect tracking.
 *
 * Requirements enforced:
 * - GET method only.
 * - Max 8-second timeout per request.
 * - Max 5 redirect hops.
 * - Max 2 MB response body.
 * - Pinned DNS lookup on each request.
 * - Validates every redirect destination independently.
 * - Rejects cross-hostname redirects.
 * - Accurately calculates usedHttps and redirectedToHttps.
 *
 * @param {string} url - Target website URL or domain.
 * @param {Object} [options]
 * @param {number} [options.timeoutMs]
 * @param {number} [options.maxRedirects]
 * @param {number} [options.maxBodyBytes]
 * @returns {Promise<{ statusCode: number, finalUrl: string, headers: Record<string, string>, html: string, usedHttps: boolean, redirectedToHttps: boolean }>}
 */
async function fetchHomepage(url, options = {}) {
  // Check if initial input explicitly specified http:// protocol
  const initialExplicitlyHttp = typeof url === 'string' && /^http:\/\//i.test(url.trim());
  const maxRedirects = options.maxRedirects !== undefined ? options.maxRedirects : MAX_REDIRECTS;

  let { parsedUrl: currentUrl, primaryIp, family } = await validateUrlAndDestination(url);
  const initialHost = currentUrl.hostname.toLowerCase();

  let redirectCount = 0;

  while (true) {
    const response = await fetchSingleGet(currentUrl, primaryIp, family, options);

    if (response.isRedirect && response.location) {
      redirectCount++;
      if (redirectCount > maxRedirects) {
        throw new Error(`Too many redirects: Exceeded maximum limit of ${maxRedirects} hops`);
      }

      // Validate redirect destination independently
      const redirectValidation = await validateRedirect(currentUrl, response.location);

      // Verify that redirect stays strictly on the initial hostname
      if (redirectValidation.redirectUrl.hostname.toLowerCase() !== initialHost) {
        throw new Error(
          `Redirect rejected: Cross-hostname redirect from '${initialHost}' to '${redirectValidation.redirectUrl.hostname}' is prohibited`
        );
      }

      currentUrl = redirectValidation.redirectUrl;
      primaryIp = redirectValidation.primaryIp;
      family = redirectValidation.family;
      continue;
    }

    const usedHttps = currentUrl.protocol === 'https:';
    // redirectedToHttps is true only if initial URL explicitly used HTTP and redirect chain ended on HTTPS
    const redirectedToHttps = initialExplicitlyHttp && usedHttps && redirectCount > 0;

    return {
      statusCode: response.statusCode,
      finalUrl: currentUrl.toString(),
      headers: response.headers,
      html: response.body,
      usedHttps,
      redirectedToHttps,
    };
  }
}

/**
 * Inspects the TLS certificate presented by the destination server on port 443.
 *
 * Requirements:
 * 1. Only inspect for HTTPS targets; HTTP-only returns null.
 * 2. Uses Node.js tls.connect() strictly with certificate verification enabled (never rejectUnauthorized: false).
 * 3. Connects only to port 443.
 * 4. Applies full SSRF protection: resolves DNS, checks all IPs, pins socket to validated public IP, preserves TLS SNI servername.
 * 5. Retrieves peer certificate, calculates daysUntilExpiry via Math.ceil((certExpiry - Date.now()) / (24 * 60 * 60 * 1000)).
 * 6. Returns { valid: boolean, daysUntilExpiry: number } or null if inspection cannot be completed.
 *
 * @param {string|URL} targetUrl - Target URL or hostname.
 * @param {Object} [options]
 * @param {number} [options.timeoutMs]
 * @returns {Promise<{ valid: boolean, daysUntilExpiry: number } | null>}
 */
async function inspectTls(targetUrl, options = {}) {
  let urlObj;
  if (targetUrl instanceof URL) {
    urlObj = targetUrl;
  } else if (typeof targetUrl === 'string') {
    try {
      urlObj = normalizeUrl(targetUrl);
    } catch {
      return null;
    }
  } else {
    return null;
  }

  // 1. HTTP-only destinations return tls: null
  if (urlObj.protocol !== 'https:') {
    return null;
  }

  const hostname = urlObj.hostname;
  const timeoutMs = options.timeoutMs !== undefined ? options.timeoutMs : DEFAULT_TIMEOUT_MS;

  // 4. SSRF protection: Resolve DNS and validate destination IP
  const destination = await validateDestination(hostname);
  const pinnedIp = destination.primaryIp;

  return new Promise((resolve) => {
    let settled = false;

    function finish(result) {
      if (!settled) {
        settled = true;
        resolve(result);
      }
    }

    const connectOptions = {
      host: pinnedIp,          // Connect directly to pre-vetted public IP
      port: 443,               // Standard HTTPS port only
      servername: hostname,    // Preserve original hostname for TLS SNI
      timeout: timeoutMs,
      // Certificate verification is NEVER disabled (rejectUnauthorized remains true/default)
    };

    let socket;
    try {
      socket = tls.connect(connectOptions);
    } catch {
      return finish(null);
    }

    socket.setTimeout(timeoutMs, () => {
      socket.destroy();
      finish(null);
    });

    socket.on('secureConnect', () => {
      try {
        const cert = socket.getPeerCertificate();
        if (!cert || Object.keys(cert).length === 0 || !cert.valid_to) {
          socket.destroy();
          return finish(null);
        }

        const validTo = new Date(cert.valid_to).getTime();
        const validFrom = cert.valid_from ? new Date(cert.valid_from).getTime() : 0;
        const now = Date.now();

        const daysUntilExpiry = Math.ceil((validTo - now) / (24 * 60 * 60 * 1000));

        // Validate date window
        const datesValid = !isNaN(validTo) && now >= validFrom && now <= validTo;

        // Check hostname match against certificate Subject / SAN
        const hostMismatch = Boolean(tls.checkServerIdentity(hostname, cert));

        // Full validity check: authorized by trusted CA, valid dates, and hostname matches
        const valid = Boolean(socket.authorized && datesValid && !hostMismatch);

        socket.destroy();
        return finish({
          valid,
          daysUntilExpiry,
        });
      } catch {
        socket.destroy();
        return finish(null);
      }
    });

    socket.on('error', (err) => {
      try {
        // Node provides the presented certificate on err.cert when handshake is aborted
        // due to verification failures (expired cert, self-signed, hostname mismatch)
        if (err && err.cert && err.cert.valid_to) {
          const validTo = new Date(err.cert.valid_to).getTime();
          const daysUntilExpiry = !isNaN(validTo)
            ? Math.ceil((validTo - Date.now()) / (24 * 60 * 60 * 1000))
            : 0;

          socket.destroy();
          return finish({
            valid: false,
            daysUntilExpiry,
          });
        }
      } catch {
        // Fall through to null
      }

      socket.destroy();
      return finish(null);
    });
  });
}

/**
 * Issues a single GET request to a well-known path using pinned DNS lookup.
 * Does NOT buffer, log, or store response bodies. Immediately drains and destroys the stream.
 * Does not automatically follow redirects. Rejects cross-hostname redirects.
 *
 * @param {URL} baseOrigin - Origin of final validated URL.
 * @param {string} path - Exactly one of the permitted well-known paths.
 * @param {string} primaryIp - Pre-vetted public IP address.
 * @param {number} family - 4 or 6.
 * @param {Object} [options]
 * @param {number} [options.timeoutMs]
 * @returns {Promise<{ status: number }>}
 */
function probeSingleWellKnownPath(baseOrigin, path, primaryIp, family, options = {}) {
  return new Promise((resolve) => {
    let settled = false;

    function finish(status) {
      if (!settled) {
        settled = true;
        resolve({ status });
      }
    }

    const isHttps = baseOrigin.protocol === 'https:';
    const client = isHttps ? https : http;
    const timeoutMs = options.timeoutMs !== undefined ? options.timeoutMs : DEFAULT_TIMEOUT_MS;
    const pinnedLookup = createPinnedLookup(primaryIp, family);

    const targetUrl = new URL(path, baseOrigin);

    const reqOptions = {
      protocol: targetUrl.protocol,
      hostname: targetUrl.hostname,
      port: targetUrl.port || (isHttps ? 443 : 80),
      path: targetUrl.pathname + targetUrl.search,
      method: 'GET',
      headers: {
        'User-Agent': USER_AGENT,
        'Accept': '*/*',
        'Connection': 'close',
      },
      lookup: pinnedLookup,
      timeout: timeoutMs,
    };

    let req;
    try {
      req = client.request(reqOptions, (res) => {
        const statusCode = res.statusCode || 0;

        // Check if response is a redirect
        if (statusCode >= 300 && statusCode < 400 && res.headers.location) {
          try {
            const redirectUrl = new URL(res.headers.location, targetUrl);
            // Enforce same-hostname restriction: reject cross-hostname redirects
            if (redirectUrl.hostname.toLowerCase() !== targetUrl.hostname.toLowerCase()) {
              res.resume();
              res.destroy();
              return finish(0); // Documented consistent status for rejected cross-hostname redirect
            }
            // Check destination IP
            if (isPrivateOrReservedIp(redirectUrl.hostname)) {
              res.resume();
              res.destroy();
              return finish(0);
            }
          } catch {
            res.resume();
            res.destroy();
            return finish(0);
          }
        }

        // Sensitive response handling:
        // Collect ONLY the HTTP status code. NEVER read, buffer, parse, log, or store response bodies.
        res.resume();
        res.on('end', () => {
          finish(statusCode);
        });
        res.on('error', () => {
          finish(statusCode);
        });
      });
    } catch {
      return finish(0);
    }

    req.setTimeout(timeoutMs, () => {
      req.destroy();
      finish(0);
    });

    req.on('timeout', () => {
      req.destroy();
      finish(0);
    });

    req.on('error', () => {
      req.destroy();
      finish(0);
    });

    req.end();
  });
}

/**
 * Probes the fixed small list of four well-known paths:
 * 1. /.git/HEAD
 * 2. /.env
 * 3. /robots.txt
 * 4. /sitemap.xml
 *
 * Requirements enforced:
 * - GET method only.
 * - Concurrently requested (Promise.all).
 * - Exactly four requests (one per path).
 * - No retries, no automatic redirect following.
 * - Pinned DNS lookup & SSRF validation.
 * - Sensitive handling: Zero response body data is read, buffered, logged, or stored.
 * - Returns exactly:
 *   {
 *     '/.git/HEAD': { status: number },
 *     '/.env': { status: number },
 *     '/robots.txt': { status: number },
 *     '/sitemap.xml': { status: number }
 *   }
 *
 * @param {string|URL} finalUrl - Target website final URL.
 * @param {Object} [options]
 * @param {number} [options.timeoutMs]
 * @returns {Promise<import('../src/core/types').WellKnownPaths>}
 */
async function fetchWellKnownPaths(finalUrl, options = {}) {
  let urlObj;
  if (finalUrl instanceof URL) {
    urlObj = finalUrl;
  } else if (typeof finalUrl === 'string') {
    urlObj = normalizeUrl(finalUrl);
  } else {
    throw new Error('fetchWellKnownPaths: Invalid URL input');
  }

  // Base origin for well-known paths
  const baseOrigin = new URL(urlObj.origin);

  // Validate destination and resolve pinned IP before issuing requests
  const destination = await validateDestination(baseOrigin.hostname);
  const primaryIp = destination.primaryIp;
  const family = destination.family;

  // Execute the exactly four permitted requests concurrently
  const probePromises = WELL_KNOWN_PATHS.map(async (path) => {
    const probeResult = await probeSingleWellKnownPath(baseOrigin, path, primaryIp, family, options);
    return [path, probeResult];
  });

  const results = await Promise.all(probePromises);

  const wellKnownPaths = {
    '/.git/HEAD': { status: 0 },
    '/.env': { status: 0 },
    '/robots.txt': { status: 0 },
    '/sitemap.xml': { status: 0 },
  };

  for (const [path, result] of results) {
    wellKnownPaths[path] = result;
  }

  return wellKnownPaths;
}

/**
 * Main entry point for gathering public outward-facing site signals.
 * Assembles and returns the frozen SiteContext (ctx) contract.
 *
 * Execution order:
 * 1. Normalize and validate the submitted URL.
 * 2. Perform homepage GET and process permitted redirects.
 * 3. Determine final URL.
 * 4. Inspect TLS if final URL uses HTTPS.
 * 5. Concurrently fetch the four permitted well-known paths against the final URL's origin.
 * 6. Assemble and return the frozen SiteContext object.
 *
 * @param {string} url - Target website URL to audit.
 * @param {Object} [options] - Optional network and timeout configuration.
 * @returns {Promise<import('../src/core/types').SiteContext>} Frozen SiteContext contract.
 */
async function fetchSiteContext(url, options = {}) {
  // 1. Normalize and validate the submitted URL
  const normalizedUrl = normalizeUrl(url);
  const initialUrl = typeof url === 'string' && url.trim().length > 0 ? url.trim() : normalizedUrl.href;

  // 2. Perform homepage GET and process permitted redirects (fails safely if unresolvable/SSRF)
  const homepage = await fetchHomepage(url, options);

  // 3. Final URL established after redirect chain
  const finalUrl = homepage.finalUrl;

  // 4. Inspect TLS if final destination uses HTTPS
  let tlsInfo = null;
  if (homepage.usedHttps) {
    try {
      tlsInfo = await inspectTls(finalUrl, options);
    } catch {
      // TLS inspection failure defaults to null per contract specification
      tlsInfo = null;
    }
  }

  // 5. Fetch the four permitted well-known paths against final origin (individual failures record status 0)
  let wellKnownPaths;
  try {
    wellKnownPaths = await fetchWellKnownPaths(finalUrl, options);
  } catch {
    wellKnownPaths = {
      '/.git/HEAD': { status: 0 },
      '/.env': { status: 0 },
      '/robots.txt': { status: 0 },
      '/sitemap.xml': { status: 0 },
    };
  }

  // 6. Assemble the exact frozen ctx contract (strictly 9 properties, serializable JSON)
  const ctx = {
    url: initialUrl,
    finalUrl,
    statusCode: homepage.statusCode,
    headers: homepage.headers,
    html: homepage.html,
    usedHttps: homepage.usedHttps,
    redirectedToHttps: homepage.redirectedToHttps,
    tls: tlsInfo,
    wellKnownPaths,
  };

  return ctx;
}

module.exports = {
  USER_AGENT,
  DEFAULT_TIMEOUT_MS,
  MAX_REDIRECTS,
  MAX_BODY_BYTES,
  WELL_KNOWN_PATHS,
  normalizeUrl,
  isPrivateOrReservedIp,
  validateDestination,
  validateRedirect,
  createPinnedLookup,
  validateUrlAndDestination,
  fetchSingleGet,
  fetchHomepage,
  inspectTls,
  probeSingleWellKnownPath,
  fetchWellKnownPaths,
  fetchSiteContext,
};
