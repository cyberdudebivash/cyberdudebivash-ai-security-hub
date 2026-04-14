/**
 * Input validation helpers for all scan endpoints
 */

const DOMAIN_RE = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;

export function validateDomain(raw) {
  if (!raw || typeof raw !== 'string') {
    return { valid: false, message: 'domain is required and must be a string' };
  }
  const val = raw.trim().toLowerCase().replace(/^https?:\/\//,'').replace(/\/.*$/,'');
  if (val.length < 4 || val.length > 253) {
    return { valid: false, message: 'domain must be 4–253 characters' };
  }
  if (!DOMAIN_RE.test(val)) {
    return { valid: false, message: `"${val}" is not a valid domain name` };
  }
  return { valid: true, value: val };
}

export function validateString(raw, fieldName, minLen = 1, maxLen = 255) {
  if (!raw || typeof raw !== 'string') {
    return { valid: false, message: `${fieldName} is required` };
  }
  const val = raw.trim();
  if (val.length < minLen) {
    return { valid: false, message: `${fieldName} must be at least ${minLen} characters` };
  }
  if (val.length > maxLen) {
    return { valid: false, message: `${fieldName} must be at most ${maxLen} characters` };
  }
  return { valid: true, value: val };
}

export function validateEnum(raw, fieldName, allowed, defaultVal) {
  if (!raw || !allowed.includes(raw.toLowerCase())) {
    return { valid: true, value: defaultVal };
  }
  return { valid: true, value: raw.toLowerCase() };
}

export async function parseBody(request) {
  const ct = request.headers.get('Content-Type') || '';
  try {
    if (ct.includes('application/json')) {
      return await request.json();
    }
    if (ct.includes('application/x-www-form-urlencoded')) {
      const text   = await request.text();
      const params = new URLSearchParams(text);
      const obj    = {};
      for (const [k, v] of params.entries()) obj[k] = v;
      return obj;
    }
    // Fallback: try JSON
    const text = await request.text();
    return text ? JSON.parse(text) : {};
  } catch {
    return {};
  }
}
