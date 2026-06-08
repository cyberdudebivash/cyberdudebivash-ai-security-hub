/**
 * CYBERDUDEBIVASH — Vibe Code Scanner :: Rule Catalog
 * ---------------------------------------------------
 * Every rule maps to CWE + (where applicable) OWASP Web Top 10 and OWASP LLM
 * Top 10, carries a plain-English "why an AI assistant tends to write this",
 * and emits findings with HIGH/MEDIUM/LOW confidence.
 *
 * Detection runs on two views of the source (see engine.js / util.js):
 *   ctx.raw  — original source (use to read string CONTENTS, e.g. secrets, SQL)
 *   ctx.mask — string/comment text blanked, but ${...} interpolations KEPT
 *              (use for structural rules; immune to false hits in comments)
 */
'use strict';

import { matches, shannonEntropy, nearbyMatch } from './util.js';

// --- small helpers ---------------------------------------------------------
const maskLine = (ctx, line) => ctx.maskLines[line - 1] || '';
const isCode   = (ctx, line) => maskLine(ctx, line).trim() !== '';   // false => comment/blank
const rawLine  = (ctx, line) => ctx.rawLines[line - 1] || '';

const USERINPUT = /\b(?:req|request)\.(?:params|query|body|args|form|values|cookies|headers|json|GET|POST)\b|\b(?:userInput|user_input|userMessage|user_message|untrusted|payload|searchParams)\b/i;
const AUTHCHECK = /\b(?:req\.user|request\.user|currentUser|authorize|authenticate|isAuthenticated|requireAuth|ensureAuth|verifyToken|checkPermission|hasPermission|can\(|isOwner|ownerId|userId\s*[=!]==|@login_required|@requires_auth|verify_jwt)\b/i;
const LLM_CALL  = /\b(?:openai|anthropic|cohere|mistral|groq|together|replicate|vertexai|bedrock|generativeai)\b|\.(?:chat\.completions\.create|messages\.create|completions\.create|generateContent|generate_content|invoke|predict)\s*\(|choices\s*\[\s*0\s*\]\s*\.\s*message|\bChatOpenAI\b|\bChatAnthropic\b|\bHumanMessage\b|\bSystemMessage\b|\bllm\.\w/i;
const LLM_OUT   = /\b(?:response|completion|message|content|answer|result|output|reply|generated|ai[_-]?\w*|llm[_-]?\w*|gpt\w*|claude\w*|model[_-]?\w*|chat[_-]?\w*)\b/i;
const PLACEHOLDER = /^(?:x{3,}|\.{3,}|\*{3,}|0{6,}|<[^>]*>|\{\{.*\}\}|\$\{.*\}|your[_-]?\w*|my[_-]?\w*|change[_-]?me|example\w*|placeholder|redacted|sample|testing?|dummy|none|null|undefined|todo|fixme|secret|password|api[_-]?key|token|abc123|123456|foo|bar|baz)$/i;

/**
 * Rule factory: wraps a detector so emitted findings inherit all metadata.
 * detector(ctx, emit) where emit(line, {confidence, evidence}).
 */
function rule(meta, detector) {
  return {
    id: meta.id,
    langs: meta.langs,
    title: meta.title,
    category: meta.category,
    severity: meta.severity,
    cwe: meta.cwe,
    owasp: meta.owasp || null,
    owasp_llm: meta.owasp_llm || null,
    why_ai: meta.why_ai,
    remediation: meta.remediation,
    detect(ctx) {
      const out = [];
      const emit = (line, { confidence = 'MEDIUM', evidence = '' } = {}) => {
        if (!line || !isCode(ctx, line)) return; // never flag commented-out code
        out.push({
          rule_id: meta.id, title: meta.title, category: meta.category,
          severity: meta.severity, confidence, cwe: meta.cwe,
          owasp: meta.owasp || null, owasp_llm: meta.owasp_llm || null,
          line, snippet: ctx.snippet(line), evidence,
          why_ai: meta.why_ai, remediation: meta.remediation,
        });
      };
      detector(ctx, emit);
      return out;
    },
  };
}

// Provider secret signatures (high confidence — these formats are unambiguous).
const PROVIDER_SECRETS = [
  { name: 'AWS Access Key ID',     re: /\bAKIA[0-9A-Z]{16}\b/g },
  { name: 'AWS Secret Access Key', re: /\baws_secret_access_key\s*[:=]\s*['"][A-Za-z0-9/+=]{40}['"]/gi },
  { name: 'OpenAI API Key',        re: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/g },
  { name: 'Anthropic API Key',     re: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g },
  { name: 'Google API Key',        re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { name: 'GitHub Token',          re: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{22,}\b/g },
  { name: 'Stripe Secret Key',     re: /\b(?:sk|rk)_live_[0-9a-zA-Z]{16,}\b/g },
  { name: 'Slack Token',           re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g },
  { name: 'Twilio API Key',        re: /\bSK[0-9a-fA-F]{32}\b/g },
  { name: 'SendGrid API Key',      re: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g },
  { name: 'JSON Web Token',        re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g },
];

export const RULES = [

  // ========================= SECRETS =========================
  rule({
    id: 'CDB-VC-SECRET-PROVIDER', category: 'Hardcoded Secret', severity: 'CRITICAL',
    cwe: 'CWE-798', owasp: 'A07:2021-Identification and Authentication Failures', langs: ['*'],
    title: 'Hardcoded cloud / API provider credential',
    why_ai: 'When you ask an assistant for "working" code it inlines the literal key you pasted into the chat instead of reading it from an environment variable, because that is the shortest path to a runnable snippet.',
    remediation: 'Move the secret to an environment variable or secret manager (e.g. Workers Secrets, AWS Secrets Manager, Doppler). Rotate the exposed key immediately — assume it is compromised the moment it lands in source control.',
  }, (ctx, emit) => {
    for (const sig of PROVIDER_SECRETS) {
      for (const { line } of matches(ctx, sig.re, 'raw')) {
        emit(line, { confidence: 'HIGH', evidence: sig.name });
      }
    }
  }),

  rule({
    id: 'CDB-VC-SECRET-PRIVATEKEY', category: 'Hardcoded Secret', severity: 'CRITICAL',
    cwe: 'CWE-798', owasp: 'A02:2021-Cryptographic Failures', langs: ['*'],
    title: 'Private key embedded in source',
    why_ai: 'Assistants paste full PEM blocks inline to make a demo "just run", rather than loading the key from a mounted secret.',
    remediation: 'Never commit private keys. Load from a secret store at runtime and rotate the exposed key.',
  }, (ctx, emit) => {
    const re = /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g;
    for (const { line } of matches(ctx, re, 'raw')) emit(line, { confidence: 'HIGH', evidence: 'PEM private key block' });
  }),

  rule({
    id: 'CDB-VC-SECRET-GENERIC', category: 'Hardcoded Secret', severity: 'HIGH',
    cwe: 'CWE-798', owasp: 'A07:2021-Identification and Authentication Failures', langs: ['*'],
    title: 'High-entropy secret assigned to a credential-named variable',
    why_ai: 'AI completions fill credential fields with a plausible literal value to keep the example self-contained, instead of stubbing an env lookup.',
    remediation: 'Read credentials from environment variables or a secret manager. Treat any value that reached a commit as burned and rotate it.',
  }, (ctx, emit) => {
    const re = /\b([A-Za-z0-9_]*?(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?key|auth[_-]?token|client[_-]?secret|private[_-]?key|credential|token)s?)\s*[:=]\s*(['"])([^'"\n]{8,80})\2/gi;
    for (const { match, line } of matches(ctx, re, 'raw')) {
      const value = match[3];
      if (PLACEHOLDER.test(value.trim())) continue;
      if (/\$\{|process\.env|os\.environ|import\.meta\.env|getenv|os\.getenv/i.test(value)) continue;
      if (/^[a-z0-9_-]+\.(?:com|io|net|org|local)$/i.test(value)) continue; // hostnames
      const ent = shannonEntropy(value);
      if (ent < 2.6) continue;
      emit(line, { confidence: ent >= 3.4 && value.length >= 16 ? 'HIGH' : 'MEDIUM', evidence: `entropy ${ent.toFixed(2)}, len ${value.length}` });
    }
  }),

  // ========================= INJECTION =========================
  rule({
    id: 'CDB-VC-SQLI-JS', category: 'SQL Injection', severity: 'CRITICAL',
    cwe: 'CWE-89', owasp: 'A03:2021-Injection', langs: ['javascript', 'typescript'],
    title: 'SQL query built by string concatenation / interpolation',
    why_ai: 'The fastest "working" query an assistant can emit interpolates the variable straight into the SQL text; parameterized placeholders need an extra arg the model often omits.',
    remediation: 'Use parameterized queries / prepared statements (e.g. db.query("... WHERE id = ?", [id]), or an ORM query builder). Never concatenate user input into SQL.',
  }, (ctx, emit) => {
    const tmpl = /\b(?:query|execute|exec|raw|prepare)\s*\(\s*`[^`]*\b(?:select|insert|update|delete|where|from|drop|union|order\s+by)\b[^`]*\$\{/gi;
    const concat = /\b(?:query|execute|exec|raw|prepare)\s*\(\s*['"][^'"]*\b(?:select|insert|update|delete|where|from|drop|union)\b[^'"]*['"]\s*\+/gi;
    for (const { line } of matches(ctx, tmpl, 'raw')) emit(line, { confidence: 'HIGH', evidence: 'template-literal interpolation into SQL' });
    for (const { line } of matches(ctx, concat, 'raw')) emit(line, { confidence: 'HIGH', evidence: 'string concatenation into SQL' });
  }),

  rule({
    id: 'CDB-VC-SQLI-PY', category: 'SQL Injection', severity: 'CRITICAL',
    cwe: 'CWE-89', owasp: 'A03:2021-Injection', langs: ['python'],
    title: 'SQL query built with f-string / % / .format / concatenation',
    why_ai: 'f-strings read as the "natural" way to compose a query, so assistants reach for execute(f"... {id}") instead of passing params as the second argument.',
    remediation: 'Pass parameters as the second argument: cursor.execute("... WHERE id = %s", (id,)). Do not format user data into the SQL string.',
  }, (ctx, emit) => {
    const fstr = /\b(?:execute|executemany)\s*\(\s*f['"][^'"]*\b(?:select|insert|update|delete|where|from|drop)\b/gi;
    const fmt  = /\b(?:execute|executemany)\s*\(\s*['"][^'"]*\b(?:select|insert|update|delete|where|from)\b[^'"]*['"]\s*(?:%|\.format\b|\+)/gi;
    for (const { line } of matches(ctx, fstr, 'raw')) emit(line, { confidence: 'HIGH', evidence: 'f-string into SQL' });
    for (const { line } of matches(ctx, fmt, 'raw')) emit(line, { confidence: 'HIGH', evidence: '%/format/concat into SQL' });
  }),

  rule({
    id: 'CDB-VC-CMDI-JS', category: 'Command Injection', severity: 'CRITICAL',
    cwe: 'CWE-78', owasp: 'A03:2021-Injection', langs: ['javascript', 'typescript'],
    title: 'OS command built from interpolated / concatenated input',
    why_ai: 'Shelling out with a single interpolated string is the most compact way to "run" a command, so the assistant skips argument arrays and input sanitisation.',
    remediation: 'Use execFile/spawn with an argument array and never pass user input through a shell. Validate against an allowlist where a shell is unavoidable.',
  }, (ctx, emit) => {
    const re = /\b(?:exec|execSync|spawn|spawnSync|execFile)\s*\(\s*`[^`]*\$\{/g;
    const re2 = /\b(?:exec|execSync)\s*\(\s*['"][^'"]*['"]\s*\+/g;
    for (const { line } of matches(ctx, re, 'raw')) emit(line, { confidence: 'HIGH', evidence: 'template interpolation into shell command' });
    for (const { line } of matches(ctx, re2, 'raw')) emit(line, { confidence: 'HIGH', evidence: 'concatenation into shell command' });
  }),

  rule({
    id: 'CDB-VC-CMDI-PY', category: 'Command Injection', severity: 'CRITICAL',
    cwe: 'CWE-78', owasp: 'A03:2021-Injection', langs: ['python'],
    title: 'OS command via os.system / shell=True with dynamic input',
    why_ai: 'os.system(f"...") and subprocess(..., shell=True) are the snippets the model has seen most often; they "just work" but invoke a shell on attacker-controlled text.',
    remediation: 'Use subprocess.run([...], shell=False) with a list of arguments. Avoid os.system entirely for dynamic input.',
  }, (ctx, emit) => {
    const sys = /\bos\.(?:system|popen)\s*\(\s*f?['"][^'"]*(?:\{|['"]\s*\+|\+)/g;
    const shell = /\bsubprocess\.(?:call|run|Popen|check_output|check_call)\s*\([^)]*shell\s*=\s*True/g;
    for (const { line } of matches(ctx, sys, 'raw')) emit(line, { confidence: 'HIGH', evidence: 'dynamic input into os.system/popen' });
    for (const { line } of matches(ctx, shell, 'raw')) emit(line, { confidence: 'HIGH', evidence: 'subprocess shell=True' });
  }),

  rule({
    id: 'CDB-VC-CODEEXEC-JS', category: 'Code Injection', severity: 'CRITICAL',
    cwe: 'CWE-95', owasp: 'A03:2021-Injection', langs: ['javascript', 'typescript'],
    title: 'Dynamic code execution via eval / new Function',
    why_ai: 'eval is the smallest possible "make this string runnable" primitive, so assistants reach for it when a prompt asks to "run" or "calculate" user-provided text.',
    remediation: 'Remove eval/new Function. Parse data with JSON.parse, dispatch via a lookup table, or use a sandboxed expression evaluator with an allowlist.',
  }, (ctx, emit) => {
    const evalVar = /\beval\s*\(\s*[A-Za-z_$]/g;          // eval(variable …)
    const fn = /\bnew\s+Function\s*\(/g;
    const strTimer = /\bset(?:Timeout|Interval)\s*\(\s*['"]/g;
    for (const { line } of matches(ctx, evalVar, 'mask')) emit(line, { confidence: 'HIGH', evidence: 'eval() on a non-literal' });
    for (const { line } of matches(ctx, fn, 'mask')) emit(line, { confidence: 'MEDIUM', evidence: 'new Function()' });
    for (const { line } of matches(ctx, strTimer, 'raw')) emit(line, { confidence: 'MEDIUM', evidence: 'string-arg setTimeout/setInterval (implicit eval)' });
  }),

  rule({
    id: 'CDB-VC-CODEEXEC-PY', category: 'Code Injection', severity: 'CRITICAL',
    cwe: 'CWE-95', owasp: 'A03:2021-Injection', langs: ['python'],
    title: 'Dynamic code execution via eval / exec',
    why_ai: 'eval(input) and exec(...) are the canonical "evaluate this" answers in training data, but they execute arbitrary Python on untrusted input.',
    remediation: 'Use ast.literal_eval for data, or an explicit parser / dispatch dict. Never eval/exec untrusted strings.',
  }, (ctx, emit) => {
    const re = /\b(?:eval|exec)\s*\(\s*[A-Za-z_]/g;
    for (const { match, line } of matches(ctx, re, 'mask')) {
      if (/literal_eval/.test(rawLine(ctx, line))) continue;
      emit(line, { confidence: 'HIGH', evidence: 'eval/exec on a non-literal' });
    }
  }),

  // ========================= SSRF =========================
  rule({
    id: 'CDB-VC-SSRF-JS', category: 'SSRF', severity: 'HIGH',
    cwe: 'CWE-918', owasp: 'A10:2021-Server-Side Request Forgery', langs: ['javascript', 'typescript'],
    title: 'Outbound request to a URL derived from user input',
    why_ai: 'A "fetch the URL the user gave me" feature is exactly what prompts ask for; the assistant wires the input straight into fetch() without an allowlist.',
    remediation: 'Validate the destination against an allowlist of hosts/schemes, block link-local and private ranges (169.254/RFC1918), and disable redirects to untrusted hosts.',
  }, (ctx, emit) => {
    const re = /\b(?:fetch|axios(?:\.get|\.post|\.put|\.request)?|got|request|https?\.get)\s*\(\s*`[^`]*\$\{([^}]+)\}/g;
    for (const { match, line } of matches(ctx, re, 'raw')) {
      const interp = match[1] || '';
      const conf = USERINPUT.test(interp) || USERINPUT.test(rawLine(ctx, line)) ? 'HIGH' : 'MEDIUM';
      emit(line, { confidence: conf, evidence: 'interpolated request URL' });
    }
  }),

  rule({
    id: 'CDB-VC-SSRF-PY', category: 'SSRF', severity: 'HIGH',
    cwe: 'CWE-918', owasp: 'A10:2021-Server-Side Request Forgery', langs: ['python'],
    title: 'Outbound request to a URL derived from user input',
    why_ai: 'requests.get(user_url) is the obvious one-liner for a "fetch this link" task and ships without host validation.',
    remediation: 'Allowlist destination hosts/schemes, block private/link-local ranges, and resolve+pin the IP before connecting to defeat DNS rebinding.',
  }, (ctx, emit) => {
    const re = /\b(?:requests|httpx|urllib\.request|aiohttp)\.[\w]*\s*\(\s*f?['"]?[^)]*(?:\{|\+)/g;
    for (const { line } of matches(ctx, re, 'raw')) {
      if (!USERINPUT.test(rawLine(ctx, line))) continue;
      emit(line, { confidence: 'HIGH', evidence: 'user input in request URL' });
    }
  }),

  // ========================= XSS =========================
  rule({
    id: 'CDB-VC-XSS-DOM', category: 'Cross-Site Scripting', severity: 'HIGH',
    cwe: 'CWE-79', owasp: 'A03:2021-Injection', langs: ['javascript', 'typescript'],
    title: 'Untrusted value written to innerHTML / outerHTML / document.write',
    why_ai: 'Setting innerHTML is the shortest way to "show this content", so assistants assign user/served data to it instead of using textContent or a sanitizer.',
    remediation: 'Use textContent / setAttribute for data, or sanitize with DOMPurify before assigning to innerHTML. Avoid document.write entirely.',
  }, (ctx, emit) => {
    const dom = /\.(?:innerHTML|outerHTML)\s*\+?=\s*[^'"\s;]/g;       // RHS not a string literal
    const adj = /\.insertAdjacentHTML\s*\(/g;
    const dw  = /\bdocument\.write(?:ln)?\s*\(/g;
    for (const { line } of matches(ctx, dom, 'mask')) emit(line, { confidence: 'HIGH', evidence: 'innerHTML/outerHTML = non-literal' });
    for (const { line } of matches(ctx, adj, 'mask')) emit(line, { confidence: 'MEDIUM', evidence: 'insertAdjacentHTML' });
    for (const { line } of matches(ctx, dw, 'mask')) emit(line, { confidence: 'MEDIUM', evidence: 'document.write' });
  }),

  rule({
    id: 'CDB-VC-XSS-REACT', category: 'Cross-Site Scripting', severity: 'HIGH',
    cwe: 'CWE-79', owasp: 'A03:2021-Injection', langs: ['javascript', 'typescript'],
    title: 'dangerouslySetInnerHTML with unsanitized value',
    why_ai: 'When a prompt says "render this HTML", the assistant uses the only React API that allows it — dangerouslySetInnerHTML — and skips the sanitiser.',
    remediation: 'Sanitize the HTML with DOMPurify first, or render as text. Treat any non-constant __html as attacker-controlled.',
  }, (ctx, emit) => {
    const re = /dangerouslySetInnerHTML\s*=\s*\{\{\s*__html\s*:/g;
    for (const { line } of matches(ctx, re, 'mask')) {
      const conf = nearbyMatch(ctx, line, /DOMPurify|sanitize|sanitise/i, 4) ? 'MEDIUM' : 'HIGH';
      emit(line, { confidence: conf, evidence: 'dangerouslySetInnerHTML' });
    }
  }),

  rule({
    id: 'CDB-VC-XSS-PY', category: 'Cross-Site Scripting', severity: 'HIGH',
    cwe: 'CWE-79', owasp: 'A03:2021-Injection', langs: ['python'],
    title: 'Server-side template injection / unescaped HTML rendering',
    why_ai: 'render_template_string and mark_safe look like simple "render this" helpers; with interpolated input they disable autoescaping and enable XSS/SSTI.',
    remediation: 'Render static templates with variables passed as context (autoescaped). Never build a template string from user input; avoid mark_safe on dynamic data.',
  }, (ctx, emit) => {
    const rts = /\brender_template_string\s*\(\s*[^'")\s]/g;          // non-literal template
    const ms  = /\bmark_safe\s*\(/g;
    for (const { line } of matches(ctx, rts, 'mask')) emit(line, { confidence: 'HIGH', evidence: 'render_template_string on dynamic input' });
    for (const { line } of matches(ctx, ms, 'mask')) emit(line, { confidence: 'MEDIUM', evidence: 'mark_safe()' });
  }),

  // ========================= ACCESS CONTROL =========================
  rule({
    id: 'CDB-VC-IDOR', category: 'Broken Access Control', severity: 'HIGH',
    cwe: 'CWE-639', owasp: 'A01:2021-Broken Access Control', langs: ['javascript', 'typescript'],
    title: 'Object looked up by user-supplied ID with no ownership check',
    why_ai: 'The model implements "get the record for this id" literally — it fetches by the id from the request and never adds the authorization clause the prompt did not mention.',
    remediation: 'Scope every lookup to the authenticated principal (e.g. findOne({ _id: id, ownerId: req.user.id })) and enforce an access-control check before returning the object.',
  }, (ctx, emit) => {
    const re = /\b(?:findById|findByPk|findOne|getById|deleteOne|deleteById|updateOne|update|destroy)\s*\(\s*[^)]*\breq\.(?:params|query|body)\.\w+/g;
    for (const { line } of matches(ctx, re, 'raw')) {
      if (nearbyMatch(ctx, line, AUTHCHECK, 8)) continue;
      emit(line, { confidence: 'MEDIUM', evidence: 'lookup keyed on request id, no nearby authorization check' });
    }
  }),

  // ========================= CRYPTO / TLS =========================
  rule({
    id: 'CDB-VC-TLS-DISABLED', category: 'Insecure Transport', severity: 'HIGH',
    cwe: 'CWE-295', owasp: 'A02:2021-Cryptographic Failures', langs: ['*'],
    title: 'TLS certificate verification disabled',
    why_ai: 'When a request fails on a self-signed cert, the assistant "fixes" it by turning verification off — the change that makes the error disappear, and the one that enables MITM.',
    remediation: 'Keep certificate verification on. Add the correct CA to the trust store instead of disabling validation.',
  }, (ctx, emit) => {
    const re = /rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0|verify\s*=\s*False|ssl\._create_unverified_context|InsecureRequestWarning/g;
    for (const { line } of matches(ctx, re, 'mask')) emit(line, { confidence: 'HIGH', evidence: 'certificate validation turned off' });
  }),

  rule({
    id: 'CDB-VC-WEAKHASH', category: 'Weak Cryptography', severity: 'MEDIUM',
    cwe: 'CWE-327', owasp: 'A02:2021-Cryptographic Failures', langs: ['*'],
    title: 'Weak hash (MD5 / SHA-1) used',
    why_ai: 'MD5/SHA-1 appear constantly in older training examples for "hash this", so assistants reproduce them despite being broken for security use.',
    remediation: 'Use SHA-256+ for integrity, and a password KDF (bcrypt / scrypt / Argon2) for passwords. Never use MD5/SHA-1 for security decisions.',
  }, (ctx, emit) => {
    const re = /createHash\s*\(\s*['"](?:md5|sha1)['"]|hashlib\.(?:md5|sha1)\s*\(/gi;
    for (const { line } of matches(ctx, re, 'raw')) {
      const conf = nearbyMatch(ctx, line, /password|passwd|pwd|secret|token/i, 3) ? 'HIGH' : 'MEDIUM';
      emit(line, { confidence: conf, evidence: 'MD5/SHA-1' });
    }
  }),

  rule({
    id: 'CDB-VC-WEAKRAND', category: 'Weak Cryptography', severity: 'MEDIUM',
    cwe: 'CWE-338', owasp: 'A02:2021-Cryptographic Failures', langs: ['*'],
    title: 'Non-cryptographic RNG used for a security value',
    why_ai: 'Math.random()/random.randint are the first randomness primitives a model recalls, and it applies them to tokens and OTPs that need a CSPRNG.',
    remediation: 'Use crypto.randomBytes / crypto.getRandomValues (JS) or the secrets module (Python) for tokens, OTPs, session IDs, and keys.',
  }, (ctx, emit) => {
    const re = /Math\.random\s*\(\s*\)|\brandom\.(?:random|randint|choice|randrange)\s*\(/g;
    for (const { line } of matches(ctx, re, 'mask')) {
      if (!nearbyMatch(ctx, line, /token|secret|password|otp|nonce|session|api[_-]?key|reset|verify|csrf|salt/i, 3)) continue;
      emit(line, { confidence: 'MEDIUM', evidence: 'weak RNG in a security context' });
    }
  }),

  // ========================= MISC WEB =========================
  rule({
    id: 'CDB-VC-CORS-WILDCARD', category: 'Security Misconfiguration', severity: 'MEDIUM',
    cwe: 'CWE-942', owasp: 'A05:2021-Security Misconfiguration', langs: ['*'],
    title: 'CORS configured to allow any origin',
    why_ai: 'origin "*" is the setting that makes a cross-origin error go away during development, so the assistant leaves it wide open.',
    remediation: 'Reflect only an explicit allowlist of trusted origins. Never combine a wildcard origin with credentials: true.',
  }, (ctx, emit) => {
    const re = /Access-Control-Allow-Origin['"]?\s*[:,]\s*['"]\*['"]|origin\s*:\s*['"]\*['"]|cors\.allow_origins\s*=\s*\[\s*['"]\*['"]/gi;
    for (const { line } of matches(ctx, re, 'raw')) {
      const conf = nearbyMatch(ctx, line, /credentials\s*:\s*true|allow_credentials\s*=\s*True/i, 4) ? 'HIGH' : 'MEDIUM';
      emit(line, { confidence: conf, evidence: 'wildcard CORS origin' });
    }
  }),

  rule({
    id: 'CDB-VC-PATH-TRAVERSAL', category: 'Path Traversal', severity: 'HIGH',
    cwe: 'CWE-22', owasp: 'A01:2021-Broken Access Control', langs: ['*'],
    title: 'Filesystem path built from user input',
    why_ai: 'Reading the file the user names is the literal task; the assistant joins the request value to a path without normalising or confining it to a base directory.',
    remediation: 'Resolve the path and verify it stays inside an allowed base directory; reject "..". Prefer an indirect handle (map an ID to a known path) over passing names through.',
  }, (ctx, emit) => {
    const js = /\bfs\.(?:readFile|readFileSync|createReadStream|writeFile|writeFileSync|unlink|sendFile)\s*\(\s*[^)]*\breq\.(?:params|query|body)/g;
    const py = /\bopen\s*\(\s*[^)]*\brequest\.(?:args|form|values|json)/g;
    for (const { line } of matches(ctx, js, 'raw')) emit(line, { confidence: 'HIGH', evidence: 'fs path from request' });
    for (const { line } of matches(ctx, py, 'raw')) emit(line, { confidence: 'HIGH', evidence: 'open() path from request' });
  }),

  rule({
    id: 'CDB-VC-DESERIALIZE-PY', category: 'Insecure Deserialization', severity: 'CRITICAL',
    cwe: 'CWE-502', owasp: 'A08:2021-Software and Data Integrity Failures', langs: ['python'],
    title: 'Unsafe deserialization (pickle / yaml.load / marshal)',
    why_ai: 'pickle.loads and yaml.load are the shortest "load this object" calls and are reproduced without the safe-loader variant.',
    remediation: 'Use yaml.safe_load and JSON for untrusted data. Never unpickle data you did not produce and sign.',
  }, (ctx, emit) => {
    const pk = /\b(?:pickle|cPickle|_pickle|marshal)\.loads?\s*\(/g;
    const yl = /\byaml\.load\s*\((?![^)]*Loader\s*=\s*(?:yaml\.)?SafeLoader)/g;
    for (const { line } of matches(ctx, pk, 'mask')) emit(line, { confidence: 'HIGH', evidence: 'pickle/marshal load' });
    for (const { line } of matches(ctx, yl, 'mask')) emit(line, { confidence: 'HIGH', evidence: 'yaml.load without SafeLoader' });
  }),

  rule({
    id: 'CDB-VC-OPEN-REDIRECT', category: 'Open Redirect', severity: 'MEDIUM',
    cwe: 'CWE-601', owasp: 'A01:2021-Broken Access Control', langs: ['*'],
    title: 'Redirect target taken from user input',
    why_ai: 'A "redirect back to where they came from" feature is implemented by echoing the request parameter straight into redirect(), with no host check.',
    remediation: 'Redirect only to a relative path or a validated entry from an allowlist of destinations.',
  }, (ctx, emit) => {
    const re = /\b(?:res\.redirect|redirect)\s*\(\s*[^)]*(?:req\.(?:query|params|body)|request\.(?:args|form|values))/g;
    for (const { line } of matches(ctx, re, 'raw')) emit(line, { confidence: 'MEDIUM', evidence: 'redirect target from request' });
  }),

  rule({
    id: 'CDB-VC-JWT-WEAK', category: 'Broken Authentication', severity: 'HIGH',
    cwe: 'CWE-347', owasp: 'A07:2021-Identification and Authentication Failures', langs: ['*'],
    title: 'JWT used without signature verification / with "none" algorithm',
    why_ai: 'jwt.decode (which does not verify) and algorithms:["none"] make a token "parse" in a demo, silently removing the integrity check.',
    remediation: 'Always verify the signature with a fixed algorithm allowlist (e.g. ["HS256"] or ["RS256"]). Never accept the "none" algorithm.',
  }, (ctx, emit) => {
    const none = /algorithms?\s*[:=]\s*\[?\s*['"]none['"]/gi;
    const noverify = /verify\s*=\s*False|"verify_signature"\s*:\s*False|verify_signature\s*=\s*False/g;
    for (const { line } of matches(ctx, none, 'raw')) emit(line, { confidence: 'HIGH', evidence: 'alg "none"' });
    for (const { line } of matches(ctx, noverify, 'raw')) emit(line, { confidence: 'HIGH', evidence: 'signature verification disabled' });
  }),

  rule({
    id: 'CDB-VC-DEBUG-PROD', category: 'Security Misconfiguration', severity: 'MEDIUM',
    cwe: 'CWE-489', owasp: 'A05:2021-Security Misconfiguration', langs: ['python'],
    title: 'Debug mode enabled',
    why_ai: 'debug=True is added so errors are visible while iterating, and it tends to survive into code that ships — exposing an interactive console and stack traces.',
    remediation: 'Drive debug from an environment variable and default it off. Never run with the debugger enabled in production.',
  }, (ctx, emit) => {
    const re = /\.run\s*\([^)]*debug\s*=\s*True|DEBUG\s*=\s*True/g;
    for (const { line } of matches(ctx, re, 'mask')) emit(line, { confidence: 'MEDIUM', evidence: 'debug mode on' });
  }),

  // ========================= AI / LLM-SPECIFIC (DIFFERENTIATOR) =========================
  rule({
    id: 'CDB-VC-LLM-OUTPUT-EXEC', category: 'Insecure LLM Output Handling', severity: 'CRITICAL',
    cwe: 'CWE-94', owasp: 'A03:2021-Injection', owasp_llm: 'LLM02:2025 Insecure Output Handling',
    langs: ['javascript', 'typescript', 'python'],
    title: 'Model output flows into a dangerous sink (eval / shell / SQL / DOM)',
    why_ai: 'Agent demos pipe the model\'s reply straight into a sink to "make it act" — eval, a shell, a query, or innerHTML — turning prompt injection into RCE/SQLi/XSS.',
    remediation: 'Treat every LLM response as untrusted. Constrain tool calls to a strict allowlist with typed arguments; never eval/exec/query/render raw model output. Validate and schema-check before any privileged action.',
  }, (ctx, emit) => {
    if (!LLM_CALL.test(ctx.raw)) return;     // gate: only meaningful when an LLM is in play
    const sinks = ctx.lang === 'python'
      ? [/\b(?:eval|exec)\s*\(/g, /\bos\.system\s*\(/g, /\bsubprocess\.\w+\s*\(/g, /\.execute\s*\(/g]
      : [/\beval\s*\(/g, /\bnew\s+Function\s*\(/g, /\b(?:exec|execSync|spawn)\s*\(/g, /\.(?:query|execute)\s*\(/g, /\.innerHTML\s*=/g, /dangerouslySetInnerHTML/g];
    for (const re of sinks) {
      for (const { line } of matches(ctx, re, 'mask')) {
        if (!LLM_OUT.test(rawLine(ctx, line))) continue;
        const dangerous = /eval|exec|system|spawn|Function/i.test(rawLine(ctx, line));
        emit(line, { confidence: dangerous ? 'HIGH' : 'MEDIUM', evidence: 'LLM-derived value reaches a sink' });
      }
    }
  }),

  rule({
    id: 'CDB-VC-LLM-PROMPT-INJECTION', category: 'Prompt Injection Exposure', severity: 'HIGH',
    cwe: 'CWE-77', owasp_llm: 'LLM01:2025 Prompt Injection',
    langs: ['javascript', 'typescript', 'python'],
    title: 'Untrusted input concatenated into a system / instruction prompt',
    why_ai: 'Building the prompt by interpolating the user string into the system instruction is the obvious template; it lets the user overwrite the model\'s instructions.',
    remediation: 'Keep system instructions separate from user content (use the user role / message boundaries). Never interpolate raw user input into the system prompt; add input/output guards and least-privilege tool scopes.',
  }, (ctx, emit) => {
    if (!LLM_CALL.test(ctx.raw)) return;
    const re = /\b(?:system|prompt|instruction|persona|context)\w*\s*[:=]\s*(?:`[^`]*\$\{|f?['"][^'"]*(?:['"]\s*\+|\+\s*['"]))/gi;
    for (const { line } of matches(ctx, re, 'raw')) {
      const conf = USERINPUT.test(rawLine(ctx, line)) || nearbyMatch(ctx, line, USERINPUT, 3) ? 'HIGH' : 'MEDIUM';
      emit(line, { confidence: conf, evidence: 'dynamic content built into a system/instruction prompt' });
    }
  }),

  rule({
    id: 'CDB-VC-LLM-PROXY-OPEN', category: 'Unbounded LLM Consumption', severity: 'MEDIUM',
    cwe: 'CWE-770', owasp_llm: 'LLM10:2025 Unbounded Consumption',
    langs: ['javascript', 'typescript', 'python'],
    title: 'Model API called from a request handler with no auth / rate limit nearby',
    why_ai: 'A "chat endpoint" prompt yields a route that forwards the body to the provider with your key — the assistant rarely adds the auth and rate-limiting the spec did not request.',
    remediation: 'Require authentication, enforce per-user rate and token limits, and cap max_tokens. An open model proxy is a direct path to financial-DoS on your provider bill.',
  }, (ctx, emit) => {
    if (!LLM_CALL.test(ctx.raw)) return;
    const routeRe = /\b(?:app|router)\.(?:post|get|put)\s*\(|@app\.(?:route|post|get)\s*\(|async\s+def\s+\w+\s*\(\s*request/g;
    for (const { line } of matches(ctx, routeRe, 'mask')) {
      // does an LLM call appear within ~25 lines after the route opens?
      if (!nearbyMatch(ctx, line + 12, LLM_CALL, 14)) continue;
      if (nearbyMatch(ctx, line, /rate[_-]?limit|ratelimit|@limiter|throttle|requireAuth|authenticate|req\.user|@login_required/i, 14)) continue;
      emit(line, { confidence: 'LOW', evidence: 'model call in handler without visible auth/rate-limit' });
    }
  }),

];
