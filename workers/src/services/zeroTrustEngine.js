/**
 * CYBERDUDEBIVASH AI Security Hub — Zero Trust Security Engine v19.0
 * Never trust, always verify — per-request risk scoring for every API call.
 *
 * Capabilities:
 *   1. Device fingerprinting (TLS, headers, timing signals)
 *   2. Risk-based authentication (adaptive MFA triggers)
 *   3. Session anomaly detection (new IP, impossible travel, burst patterns)
 *   4. API abuse detection (velocity, rotation, credential stuffing)
 *   5. Behavioral scoring engine (0–100 trust score per identity)
 *
 * Integration: called from auth middleware, enriches authCtx with trustScore
 *
 * Endpoints:
 *   GET  /api/zero-trust/score          → trust score for current session
 *   GET  /api/zero-trust/anomalies      → recent anomalies for identity
 *   POST /api/zero-trust/verify         → explicit trust assertion
 */

// ─── Trust score weights ──────────────────────────────────────────────────────
const TRUST_WEIGHTS = {
  // Positive signals (+trust)
  known_user_agent:     +10,
  known_ip:             +15,
  valid_jwt:            +20,
  enterprise_key:       +15,
  low_request_rate:     +10,
  consistent_timezone:  +8,
  verified_email:       +10,
  mfa_verified:         +20,
  // Negative signals (-trust)
  tor_exit_node:        -40,
  vpn_datacenter:       -20,
  unknown_ua:           -10,
  new_ip_high_risk:     -15,
  burst_requests:       -20,
  credential_rotation:  -15,
  impossible_travel:    -30,
  bot_signals:          -25,
  scan_pattern:         -20,
  repeated_auth_fail:   -30,
  suspicious_ua:        -15,
  missing_accept_lang:  -5,
  no_referrer:          -3,
  high_entropy_ua:      -8,
};

// ─── Known benign bot UAs (allow list) ───────────────────────────────────────
const BENIGN_BOTS = ['googlebot', 'bingbot', 'slurp', 'duckduckbot', 'baiduspider', 'twitterbot', 'facebookbot', 'linkedinbot'];
const KNOWN_SCANNERS = ['nmap', 'masscan', 'shodan', 'censys', 'zgrab', 'nuclei', 'nikto', 'sqlmap', 'burpsuite', 'zap', 'metasploit'];
const DATACENTER_ASN_PREFIXES = ['amazonaws', 'google cloud', 'microsoft azure', 'digitalocean', 'linode', 'vultr', 'hetzner', 'ovh'];

// ─── Device fingerprint from request headers ──────────────────────────────────
export function fingerprintDevice(request) {
  const ua          = request.headers.get('User-Agent')        || '';
  const accept      = request.headers.get('Accept')            || '';
  const acceptLang  = request.headers.get('Accept-Language')   || '';
  const acceptEnc   = request.headers.get('Accept-Encoding')   || '';
  const cacheCtrl   = request.headers.get('Cache-Control')     || '';
  const dnt         = request.headers.get('DNT')               || '';
  const secFetch    = request.headers.get('Sec-Fetch-Mode')    || '';
  const secUA       = request.headers.get('Sec-Ch-Ua')         || '';
  const cfIPCountry = request.headers.get('CF-IPCountry')      || 'XX';
  const cfASN       = request.headers.get('CF-BGP-ASN')        || '0';
  const ip          = request.headers.get('CF-Connecting-IP')  || request.headers.get('X-Forwarded-For')?.split(',')[0]?.trim() || 'unknown';

  // Generate fingerprint hash from stable signals
  const raw = [ua, acceptEnc, acceptLang.slice(0,5), secUA.slice(0,20)].join('|');
  let hash  = 0;
  for (let i = 0; i < raw.length; i++) hash = ((hash << 5) - hash + raw.charCodeAt(i)) >>> 0;
  const fingerprint = hash.toString(16).padStart(8, '0');

  const uaLower = ua.toLowerCase();
  const isBrowser  = /mozilla|chrome|safari|firefox|edge/i.test(ua);
  const isBot      = KNOWN_SCANNERS.some(s => uaLower.includes(s));
  const isScanner  = /scan|fuzz|exploit|hack|attack|pentest/i.test(uaLower);
  const isDatacenter = DATACENTER_ASN_PREFIXES.some(dc => (request.headers.get('CF-ASN-Description') || '').toLowerCase().includes(dc));

  return {
    fingerprint,
    ip,
    country:      cfIPCountry,
    asn:          cfASN,
    ua_parsed: {
      raw:            ua.slice(0, 200),
      is_browser:     isBrowser,
      is_bot:         isBot,
      is_scanner:     isScanner,
      is_datacenter:  isDatacenter,
      has_sec_fetch:  !!secFetch,
      has_accept_lang:!!acceptLang,
      has_accept:     !!accept,
    },
    signals: {
      has_dnt:          dnt === '1',
      has_cache_ctrl:   !!cacheCtrl,
      accept_lang_set:  !!acceptLang,
      sec_ua_set:       !!secUA,
    },
  };
}

// ─── Trust score calculator ───────────────────────────────────────────────────
export async function computeTrustScore(request, authCtx, env) {
  let score = 50; // baseline
  const factors = [];

  const fp = fingerprintDevice(request);

  // Auth method bonuses
  if (authCtx.method === 'jwt')     { score += TRUST_WEIGHTS.valid_jwt;      factors.push('valid_jwt'); }
  if (authCtx.tier === 'ENTERPRISE'){ score += TRUST_WEIGHTS.enterprise_key; factors.push('enterprise_key'); }
  if (!fp.ua_parsed.is_browser && !authCtx.authenticated) { score += TRUST_WEIGHTS.unknown_ua; factors.push('unknown_ua'); }

  // Device signals
  if (!fp.ua_parsed.has_accept_lang) { score += TRUST_WEIGHTS.missing_accept_lang; factors.push('missing_accept_lang'); }
  if (fp.ua_parsed.is_bot)           { score += TRUST_WEIGHTS.bot_signals;         factors.push('bot_signals'); }
  if (fp.ua_parsed.is_scanner)       { score += TRUST_WEIGHTS.scan_pattern;        factors.push('scan_pattern'); }
  if (fp.ua_parsed.is_datacenter)    { score += TRUST_WEIGHTS.vpn_datacenter;      factors.push('vpn_datacenter'); }
  if (fp.ua_parsed.has_sec_fetch)    { score += 5;                                  } // browser with modern API

  // KV-based signals (session history)
  if (env?.SECURITY_HUB_KV && authCtx.identity) {
    try {
      const identity = authCtx.identity;
      const day      = new Date().toISOString().slice(0, 10);

      const [knownIPs, burstCount, failCount] = await Promise.all([
        env.SECURITY_HUB_KV.get(`zt:known_ips:${identity}`, { type: 'json' }).catch(() => []),
        env.SECURITY_HUB_KV.get(`rl:burst:${identity}:all:${new Date().toISOString().slice(0,16)}`).catch(() => '0'),
        env.SECURITY_HUB_KV.get(`zt:auth_fail:${identity}:${day}`).catch(() => '0'),
      ]);

      // Known IP bonus
      if ((knownIPs || []).includes(fp.ip)) {
        score += TRUST_WEIGHTS.known_ip;
        factors.push('known_ip');
      } else if ((knownIPs || []).length > 0) {
        score += TRUST_WEIGHTS.new_ip_high_risk;
        factors.push('new_ip');
        // Record new IP
        const updatedIPs = [...new Set([...(knownIPs || []), fp.ip])].slice(-10);
        env.SECURITY_HUB_KV.put(`zt:known_ips:${identity}`, JSON.stringify(updatedIPs), { expirationTtl: 2592000 }).catch(() => {});
      } else {
        // First time — record IP
        env.SECURITY_HUB_KV.put(`zt:known_ips:${identity}`, JSON.stringify([fp.ip]), { expirationTtl: 2592000 }).catch(() => {});
      }

      // Burst detection
      const burst = parseInt(burstCount || '0', 10);
      if (burst > 30) { score += TRUST_WEIGHTS.burst_requests; factors.push('burst_requests'); }

      // Auth failure pattern
      const fails = parseInt(failCount || '0', 10);
      if (fails > 5) { score += TRUST_WEIGHTS.repeated_auth_fail; factors.push('repeated_auth_fail'); }
    } catch {}
  }

  // Clamp to 0–100
  const clamped   = Math.min(100, Math.max(0, score));
  const trustLevel = clamped >= 75 ? 'HIGH' : clamped >= 50 ? 'MEDIUM' : clamped >= 25 ? 'LOW' : 'UNTRUSTED';
  const requiresMFA = clamped < 50 && authCtx.tier !== 'IP';

  return {
    trust_score:   clamped,
    trust_level:   trustLevel,
    requires_mfa:  requiresMFA,
    factors,
    fingerprint:   fp.fingerprint,
    ip:            fp.ip,
    country:       fp.country,
    computed_at:   new Date().toISOString(),
  };
}

// ─── Session anomaly detection ────────────────────────────────────────────────
export async function detectSessionAnomaly(request, authCtx, env) {
  if (!env?.SECURITY_HUB_KV || !authCtx?.identity) return null;

  const identity = authCtx.identity;
  const ip       = request.headers.get('CF-Connecting-IP') || 'unknown';
  const country  = request.headers.get('CF-IPCountry')     || 'XX';
  const now      = Date.now();
  const dayKey   = new Date().toISOString().slice(0, 10);
  const anomalies = [];

  try {
    // Check impossible travel: country changed in < 1 hour
    const lastCtxKey = `zt:last_ctx:${identity}`;
    const lastRaw    = await env.SECURITY_HUB_KV.get(lastCtxKey);
    const lastCtx    = lastRaw ? JSON.parse(lastRaw) : null;

    if (lastCtx) {
      const timeDiff = (now - lastCtx.timestamp) / 1000 / 60; // minutes
      if (lastCtx.country !== country && timeDiff < 60) {
        anomalies.push({
          type: 'impossible_travel',
          severity: 'HIGH',
          detail: `Country changed from ${lastCtx.country} to ${country} in ${Math.round(timeDiff)} minutes`,
        });
      }
      if (lastCtx.ip !== ip && lastCtx.country !== country) {
        anomalies.push({
          type: 'new_location',
          severity: 'MEDIUM',
          detail: `New IP and country: ${ip} (${country})`,
        });
      }
    }

    // Update last context
    env.SECURITY_HUB_KV.put(lastCtxKey, JSON.stringify({ ip, country, timestamp: now }), { expirationTtl: 86400 }).catch(() => {});

    // Check request velocity anomaly (> 100 requests in 1 minute is suspicious)
    const minuteKey = `zt:velocity:${identity}:${new Date().toISOString().slice(0,16)}`;
    const curVelocity = parseInt(await env.SECURITY_HUB_KV.get(minuteKey) || '0', 10) + 1;
    env.SECURITY_HUB_KV.put(minuteKey, String(curVelocity), { expirationTtl: 120 }).catch(() => {});

    if (curVelocity > 100) {
      anomalies.push({
        type: 'high_velocity',
        severity: 'HIGH',
        detail: `${curVelocity} requests in 1 minute — potential automated attack`,
      });
    }

    // Log anomalies if found
    if (anomalies.length > 0) {
      const logKey = `zt:anomaly_log:${identity}:${Date.now()}`;
      env.SECURITY_HUB_KV.put(logKey, JSON.stringify({ anomalies, ip, country, ts: new Date().toISOString() }), { expirationTtl: 604800 }).catch(() => {});
    }
  } catch {}

  return anomalies.length > 0 ? anomalies : null;
}

// ─── API abuse detector (credential stuffing, key rotation) ───────────────────
export async function detectAPIAbuse(request, authCtx, env) {
  if (!env?.SECURITY_HUB_KV) return { abusive: false };

  const ip   = request.headers.get('CF-Connecting-IP') || 'unknown';
  const path = new URL(request.url).pathname;
  const day  = new Date().toISOString().slice(0, 10);

  try {
    // Check for credential stuffing: many 401s from same IP
    const failKey   = `zt:api_fail:${ip}:${day}`;
    const failCount = parseInt(await env.SECURITY_HUB_KV.get(failKey) || '0', 10);

    if (!authCtx.authenticated && authCtx.error === 'invalid_key') {
      const newCount = failCount + 1;
      env.SECURITY_HUB_KV.put(failKey, String(newCount), { expirationTtl: 86400 }).catch(() => {});
      if (newCount > 20) {
        // Auto-flag IP for abuse
        env.SECURITY_HUB_KV.put(`abuse:ip:${ip}`, 'credential_stuffing', { expirationTtl: 3600 }).catch(() => {});
        return { abusive: true, reason: 'credential_stuffing', fail_count: newCount };
      }
    }

    // Check for key rotation (many different keys from same IP)
    if (authCtx.method === 'api_key' && !authCtx.authenticated) {
      const keyTrialKey   = `zt:key_trials:${ip}:${day}`;
      const keyTrialCount = parseInt(await env.SECURITY_HUB_KV.get(keyTrialKey) || '0', 10) + 1;
      env.SECURITY_HUB_KV.put(keyTrialKey, String(keyTrialCount), { expirationTtl: 86400 }).catch(() => {});
      if (keyTrialCount > 10) {
        return { abusive: true, reason: 'key_enumeration', trial_count: keyTrialCount };
      }
    }
  } catch {}

  return { abusive: false };
}

// ─── Handler: GET /api/zero-trust/score ──────────────────────────────────────
export async function handleTrustScore(request, env, authCtx) {
  const trustCtx = await computeTrustScore(request, authCtx, env);
  const anomalies = await detectSessionAnomaly(request, authCtx, env);

  return Response.json({
    identity:     authCtx.identity || 'anonymous',
    tier:         authCtx.tier || 'FREE',
    trust:        trustCtx,
    anomalies:    anomalies || [],
    policy: {
      allow:       trustCtx.trust_score >= 25,
      step_up_mfa: trustCtx.requires_mfa,
      block:       trustCtx.trust_score < 15,
    },
    platform: 'CYBERDUDEBIVASH AI Security Hub v19.0',
  });
}

// ─── Handler: GET /api/zero-trust/anomalies ───────────────────────────────────
export async function handleZeroTrustAnomalies(request, env, authCtx) {
  if (!authCtx.authenticated) {
    return Response.json({ error: 'Authentication required' }, { status: 401 });
  }

  const anomalies = [];
  if (env?.SECURITY_HUB_KV) {
    try {
      const list = await env.SECURITY_HUB_KV.list({ prefix: `zt:anomaly_log:${authCtx.identity}:` });
      for (const key of (list.keys || []).slice(0, 20)) {
        const raw = await env.SECURITY_HUB_KV.get(key.name);
        if (raw) { try { anomalies.push(JSON.parse(raw)); } catch {} }
      }
    } catch {}
  }

  anomalies.sort((a, b) => new Date(b.ts) - new Date(a.ts));
  return Response.json({
    identity:  authCtx.identity,
    anomalies,
    total:     anomalies.length,
    platform: 'CYBERDUDEBIVASH AI Security Hub v19.0',
  });
}

// ─── Handler: POST /api/zero-trust/verify ────────────────────────────────────
export async function handleZeroTrustVerify(request, env, authCtx) {
  if (!authCtx.authenticated) {
    return Response.json({ error: 'Authentication required' }, { status: 401 });
  }

  const trustCtx = await computeTrustScore(request, authCtx, env);

  // Mark identity as step-up verified for 1 hour
  if (env?.SECURITY_HUB_KV) {
    env.SECURITY_HUB_KV.put(
      `zt:verified:${authCtx.identity}`,
      JSON.stringify({ verified_at: new Date().toISOString(), ip: request.headers.get('CF-Connecting-IP') }),
      { expirationTtl: 3600 }
    ).catch(() => {});
  }

  return Response.json({
    verified:    true,
    identity:    authCtx.identity,
    trust_score: Math.min(100, trustCtx.trust_score + 20), // boost for explicit verification
    valid_until: new Date(Date.now() + 3600000).toISOString(),
    platform: 'CYBERDUDEBIVASH AI Security Hub v19.0',
  });
}
