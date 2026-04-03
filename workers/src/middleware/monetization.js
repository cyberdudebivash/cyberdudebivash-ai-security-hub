/**
 * Monetization + Rate Limiting middleware
 * KV-backed rate limiting: 10 req/hour, 50 req/day free tier
 * Premium lock with Razorpay/UPI payment URLs
 */

const FREE_LIMIT_HOURLY = 10;
const FREE_LIMIT_DAILY  = 50;

// Razorpay payment link builder — swap in your actual Razorpay key
function buildPaymentUrl(module) {
  const LINKS = {
    domain:     'https://rzp.io/l/cyberdudebivash-domain',
    ai:         'https://rzp.io/l/cyberdudebivash-ai',
    redteam:    'https://rzp.io/l/cyberdudebivash-redteam',
    identity:   'https://rzp.io/l/cyberdudebivash-identity',
    compliance: 'https://rzp.io/l/cyberdudebivash-compliance',
  };
  return LINKS[module] || 'https://cyberdudebivash.in/#pricing';
}

const MODULE_PRICES = {
  domain:     '₹199',
  ai:         '₹499',
  redteam:    '₹999',
  identity:   '₹799',
  compliance: '₹499–₹1,999',
};

export async function checkRateLimit(env, ip, module) {
  if (!env?.SECURITY_HUB_KV) return true; // No KV → allow (dev mode)
  const hourKey = `rl:${ip}:${module}:${Math.floor(Date.now()/3600000)}`;
  const dayKey  = `rl:${ip}:day:${Math.floor(Date.now()/86400000)}`;
  try {
    const [hourly, daily] = await Promise.all([
      env.SECURITY_HUB_KV.get(hourKey),
      env.SECURITY_HUB_KV.get(dayKey),
    ]);
    if (parseInt(hourly||0) >= FREE_LIMIT_HOURLY) return false;
    if (parseInt(daily||0)  >= FREE_LIMIT_DAILY)  return false;
    return true;
  } catch {
    return true; // On KV error, allow request
  }
}

export async function trackUsage(env, ip, module) {
  if (!env?.SECURITY_HUB_KV) return;
  const hourKey  = `rl:${ip}:${module}:${Math.floor(Date.now()/3600000)}`;
  const dayKey   = `rl:${ip}:day:${Math.floor(Date.now()/86400000)}`;
  const totalKey = `stats:total:${module}`;
  try {
    await Promise.all([
      env.SECURITY_HUB_KV.put(hourKey,  String((parseInt(await env.SECURITY_HUB_KV.get(hourKey)||0))+1),  { expirationTtl: 3600  }),
      env.SECURITY_HUB_KV.put(dayKey,   String((parseInt(await env.SECURITY_HUB_KV.get(dayKey)||0))+1),   { expirationTtl: 86400 }),
      env.SECURITY_HUB_KV.put(totalKey, String((parseInt(await env.SECURITY_HUB_KV.get(totalKey)||0))+1)),
    ]);
  } catch { /* fire-and-forget — never block response */ }
}

export function addMonetizationFlags(result, module) {
  // Mark premium findings and trim them from free response
  const allFindings = result.findings || [];
  const freeFindings    = allFindings.filter(f => !f.is_premium).slice(0, 3);
  const premiumFindings = allFindings.filter(f => f.is_premium);

  return {
    ...result,
    findings: freeFindings,
    premium_findings_count: premiumFindings.length,
    is_premium_locked: true,
    unlock_required: true,
    unlock_price: MODULE_PRICES[module] || '₹499',
    payment_url: buildPaymentUrl(module),
    upgrade_cta: `Unlock ${premiumFindings.length} additional findings + full report for ${MODULE_PRICES[module]||'₹499'}`,
    contact: {
      email: 'cyberdudebivash@gmail.com',
      website: 'https://cyberdudebivash.in',
      enterprise: 'bivashnayak.ai007@gmail.com',
    },
  };
}
