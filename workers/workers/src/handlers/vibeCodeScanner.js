/**
 * VIBE CODE SECURITY SCANNER — v29.0.0
 * Detects security vulnerabilities in AI-generated code (Cursor, Copilot, Claude)
 * 2026's #1 emerging threat: insecure vibe-coded AI-generated applications
 *
 * ENDPOINTS:
 *   POST /api/vibe-code/scan     — Scan AI-generated code for vulnerabilities
 *   GET  /api/vibe-code/patterns — Get vulnerability pattern catalog
 *   POST /api/vibe-code/report   — Generate full PDF-ready security report
 *
 * Free: 50 lines / 3 findings | Paid ₹499 = Full codebase analysis + fixes
 */

// ── Vibe Code Vulnerability Pattern Catalog ──────────────────────────────────
const VIBE_PATTERNS = [
  {
    id: 'VC-001', severity: 'CRITICAL',
    title: 'Hardcoded API Keys or Secrets',
    pattern: /(api[_-]?key|secret|password|token|auth|credential)\s*[=:]\s*["'][a-zA-Z0-9_\-\.]{12,}/gi,
    pattern_desc: 'String assignment with "key", "secret", "password", "token" keywords',
    description: 'AI-generated code frequently hardcodes API keys directly in source files instead of using environment variables.',
    ai_cause: 'LLMs trained on example code often generate working examples with placeholder keys that developers forget to replace.',
    remediation: 'Move all secrets to environment variables (process.env.API_KEY). Use .env files with dotenv and add .env to .gitignore.',
    fix_example: '// BEFORE (AI generated):\nconst apiKey = "sk-abc123def456";\n// AFTER (secure):\nconst apiKey = process.env.OPENAI_API_KEY;',
    cvss_base: 9.8,
    references: ['CWE-798', 'OWASP A02:2021'],
  },
  {
    id: 'VC-002', severity: 'CRITICAL',
    title: 'SQL Injection via String Concatenation',
    pattern: /(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\s+.*?\+\s*(req\.|request\.|body\.|params\.|query\.)/gi,
    pattern_desc: 'SQL keyword followed by string concatenation with request data',
    description: 'AI-generated database queries often concatenate user input directly into SQL strings.',
    ai_cause: 'LLMs generate the simplest working code; parameterized queries require additional complexity the model may omit.',
    remediation: 'Use parameterized queries or ORMs. Never concatenate user input into SQL strings.',
    fix_example: '// BEFORE: "SELECT * FROM users WHERE id = " + req.params.id\n// AFTER: db.query("SELECT * FROM users WHERE id = ?", [req.params.id])',
    cvss_base: 9.1,
    references: ['CWE-89', 'OWASP A03:2021'],
  },
  {
    id: 'VC-003', severity: 'HIGH',
    title: 'Server-Side Request Forgery (SSRF) via fetch()',
    pattern: /fetch\s*\(\s*(req\.|request\.|body\.|params\.|query\.|url\s*=|target\s*=)/gi,
    pattern_desc: 'fetch() called with user-controlled URL parameter',
    description: 'AI code using fetch() with user-supplied URLs enables SSRF attacks to internal services.',
    ai_cause: 'AI models generate fetch() calls for URL parameters without URL allowlist validation.',
    remediation: 'Validate URLs against an allowlist before fetching. Reject private IP ranges (10.x, 172.16.x, 192.168.x, 127.x).',
    fix_example: '// Add before fetch():\nconst ALLOWED = ["api.example.com", "cdn.example.com"];\nconst host = new URL(url).hostname;\nif (!ALLOWED.includes(host)) throw new Error("Blocked");',
    cvss_base: 8.6,
    references: ['CWE-918', 'OWASP A10:2021'],
  },
  {
    id: 'VC-004', severity: 'HIGH',
    title: 'Reflected XSS via innerHTML',
    pattern: /\.innerHTML\s*[+=]+\s*(req\.|request\.|body\.|params\.|query\.|data\.|user\.|input)/gi,
    pattern_desc: 'innerHTML assignment with request/user data',
    description: 'AI-generated frontend code assigns user input to innerHTML, enabling XSS attacks.',
    ai_cause: 'innerHTML is the simplest way to inject HTML dynamically; AI frequently uses it without sanitization.',
    remediation: 'Use textContent instead of innerHTML for user data. If HTML is required, sanitize with DOMPurify.',
    fix_example: '// BEFORE: element.innerHTML = userInput;\n// AFTER: element.textContent = userInput; // or\n// element.innerHTML = DOMPurify.sanitize(userInput);',
    cvss_base: 7.5,
    references: ['CWE-79', 'OWASP A03:2021'],
  },
  {
    id: 'VC-005', severity: 'HIGH',
    title: 'Missing Authentication Middleware',
    pattern: /app\.(get|post|put|delete|patch)\s*\(\s*["']\/api\//gi,
    pattern_desc: 'API route without auth middleware',
    description: 'AI-generated API routes often lack authentication middleware, exposing sensitive endpoints publicly.',
    ai_cause: 'When asked to "create a route", AI generates the minimal code without adding auth unless explicitly requested.',
    remediation: 'Add authentication middleware to all /api/ routes. Use express-jwt or passport.js middleware.',
    fix_example: '// BEFORE: app.get("/api/users", (req, res) => {...})\n// AFTER: app.get("/api/users", requireAuth, (req, res) => {...})',
    cvss_base: 8.1,
    references: ['CWE-306', 'OWASP A01:2021'],
  },
  {
    id: 'VC-006', severity: 'HIGH',
    title: 'Insecure Direct Object Reference (IDOR)',
    pattern: /\.(find|findOne|findById|get)\s*\(\s*(req\.|request\.)(params|body|query)\.(id|userId|user_id|objectId)/gi,
    pattern_desc: 'Database lookup using user-supplied ID without ownership check',
    description: 'AI code fetches resources by user-supplied ID without verifying the requesting user owns that resource.',
    ai_cause: 'AI generates CRUD operations without authorization checks unless explicitly prompted for them.',
    remediation: 'Always add ownership check: include current user ID in the query (AND user_id = req.user.id).',
    fix_example: '// BEFORE: User.findById(req.params.id)\n// AFTER: User.findOne({ _id: req.params.id, owner: req.user.id })',
    cvss_base: 7.5,
    references: ['CWE-639', 'OWASP A01:2021'],
  },
  {
    id: 'VC-007', severity: 'MEDIUM',
    title: 'eval() or Function() with User Input',
    pattern: /eval\s*\([^)]*?(req\.|request\.|body\.|params\.|query\.|user|input)/gi,
    pattern_desc: 'eval() called with request or user data',
    description: 'AI-generated code uses eval() for dynamic functionality, enabling remote code execution.',
    ai_cause: 'AI uses eval() for quick JSON parsing or dynamic expression evaluation without considering security.',
    remediation: 'Never use eval() with external data. Use JSON.parse() for JSON, express parsers for form data.',
    fix_example: '// BEFORE: const result = eval(req.body.expression);\n// AFTER: // Redesign to not evaluate arbitrary expressions',
    cvss_base: 9.0,
    references: ['CWE-95', 'OWASP A03:2021'],
  },
  {
    id: 'VC-008', severity: 'MEDIUM',
    title: 'Missing CORS Configuration (Wildcard)',
    pattern: /cors\s*\(\s*\{[^}]*origin\s*:\s*["']\*["']/gi,
    pattern_desc: 'CORS configured with wildcard origin',
    description: 'AI-generated express apps often use cors({ origin: "*" }) for convenience, allowing any domain to make credentialed requests.',
    ai_cause: 'AI uses the simplest CORS config to make code "work" without restricting origin.',
    remediation: 'Restrict CORS origin to your specific frontend domains. Never use "*" with credentials.',
    fix_example: '// BEFORE: app.use(cors({ origin: "*" }))\n// AFTER: app.use(cors({ origin: ["https://yourdomain.com"] }))',
    cvss_base: 6.5,
    references: ['CWE-942', 'OWASP A05:2021'],
  },
  {
    id: 'VC-009', severity: 'MEDIUM',
    title: 'Missing Input Validation',
    pattern: /(req\.body|req\.params|req\.query)\.[a-zA-Z_]+\s*(?!\.trim|\.validate|\.sanitize|!==|===|typeof|instanceof)/gi,
    pattern_desc: 'Request data used directly without validation or sanitization',
    description: 'AI code uses request data directly without validating type, length, or format.',
    ai_cause: 'Validation adds boilerplate; AI generates minimal working code without it unless specified.',
    remediation: 'Use Zod, Joi, or express-validator to validate all inputs before processing.',
    fix_example: '// Add validation:\nconst schema = z.object({ email: z.string().email(), age: z.number().min(0).max(150) });\nconst data = schema.parse(req.body);',
    cvss_base: 6.1,
    references: ['CWE-20', 'OWASP A03:2021'],
  },
  {
    id: 'VC-010', severity: 'MEDIUM',
    title: 'Insecure File Upload Path',
    pattern: /upload|multer|formData.*file|req\.file.*path/gi,
    pattern_desc: 'File upload handling without path sanitization',
    description: 'AI-generated file upload code stores files with user-controlled filenames, enabling path traversal.',
    ai_cause: 'File upload examples focus on functionality; AI omits filename sanitization.',
    remediation: 'Sanitize filenames: remove path traversal chars (../, /). Generate UUID-based filenames. Validate MIME types.',
    fix_example: '// BEFORE: path.join(uploadDir, req.file.originalname)\n// AFTER: path.join(uploadDir, uuidv4() + path.extname(req.file.originalname))',
    cvss_base: 7.0,
    references: ['CWE-22', 'CWE-434', 'OWASP A04:2021'],
  },
];

// ── Scan Engine ───────────────────────────────────────────────────────────────
function scanCode(code, language = 'javascript') {
  if (!code || typeof code !== 'string') return { error: 'No code provided' };

  const lines = code.split('\n');
  const lineCount = lines.length;
  const findings = [];

  for (const patternDef of VIBE_PATTERNS) {
    // Reset regex state
    const re = new RegExp(patternDef.pattern.source, patternDef.pattern.flags);
    let match;
    const lineMatches = [];

    // Check each line
    lines.forEach((line, idx) => {
      const lineRe = new RegExp(patternDef.pattern.source, patternDef.pattern.flags);
      if (lineRe.test(line)) {
        lineMatches.push({
          line_number: idx + 1,
          code: line.trim().substring(0, 120),
        });
      }
    });

    if (lineMatches.length > 0) {
      findings.push({
        ...patternDef,
        pattern: undefined, // don't return compiled regex
        occurrences: lineMatches.length,
        line_matches: lineMatches.slice(0, 3), // show first 3 matches
      });
    }
  }

  // Sort by CVSS
  findings.sort((a, b) => (b.cvss_base || 0) - (a.cvss_base || 0));

  const risk_score = Math.min(100,
    findings.reduce((sum, f) => sum + ({ CRITICAL: 25, HIGH: 15, MEDIUM: 8, LOW: 3 }[f.severity] || 0), 0)
  );
  const risk_level = risk_score >= 75 ? 'CRITICAL' : risk_score >= 50 ? 'HIGH' : risk_score >= 25 ? 'MEDIUM' : 'LOW';

  const FREE_LIMIT = 3;
  const free_findings = findings.slice(0, FREE_LIMIT).map(f => ({
    id: f.id, severity: f.severity, title: f.title,
    description: f.description, remediation: f.remediation,
    fix_example: f.fix_example, cvss_base: f.cvss_base,
    occurrences: f.occurrences, line_matches: f.line_matches,
    references: f.references, ai_cause: f.ai_cause,
  }));

  const locked_findings = findings.slice(FREE_LIMIT).map(f => ({
    id: f.id, severity: f.severity, title: f.title,
    preview: f.description.substring(0, 80) + '...',
    cvss_base: f.cvss_base,
  }));

  const ai_generation_score = Math.min(10, Math.round(
    (findings.some(f => f.id === 'VC-001') ? 3 : 0) +
    (findings.some(f => f.id === 'VC-005') ? 2 : 0) +
    (findings.some(f => f.id === 'VC-002') ? 2 : 0) +
    (findings.length > 5 ? 3 : findings.length)
  ));

  return {
    scan_id: crypto.randomUUID(),
    language,
    line_count: lineCount,
    risk_score,
    risk_level,
    grade: findings.some(f=>f.severity==='CRITICAL') ? 'F' : findings.some(f=>f.severity==='HIGH') ? 'D' : findings.some(f=>f.severity==='MEDIUM') ? 'C' : findings.length > 0 ? 'B' : 'A',
    total_vulnerabilities: findings.length,
    ai_generation_likelihood: `${ai_generation_score}/10`,
    ai_generation_indicators: findings.filter(f => ['VC-001','VC-005','VC-008'].includes(f.id)).map(f => f.title),
    findings: free_findings,
    locked_findings,
    summary: `${lineCount} lines analyzed. ${findings.length} vulnerabilities found (${findings.filter(f=>f.severity==='CRITICAL').length} CRITICAL, ${findings.filter(f=>f.severity==='HIGH').length} HIGH).`,
    top_priority_fix: findings.length > 0 ? findings[0].remediation : 'No critical issues found.',
    vibe_coding_risk: risk_score > 50 ? 'HIGH — This code shows patterns common in insecure AI-generated code.' : 'LOW — Standard security patterns detected.',
    monetization: locked_findings.length > 0 ? {
      unlock_price: '₹499',
      amount: 49900,
      upgrade_cta: `Unlock ${locked_findings.length} more vulnerabilities + complete fix code for every issue`,
    } : null,
    scanned_at: new Date().toISOString(),
    scanner_version: 'VIBECODE-SCANNER-v29.0',
  };
}

// ── Handler: Full Vibe Code Scan ──────────────────────────────────────────────
export async function handleVibeCodeScan(request, env, authCtx) {
  try {
    const body = await request.json().catch(() => ({}));
    const { code, language = 'javascript', source = 'user' } = body;

    if (!code) {
      return Response.json({ error: 'code field is required' }, { status: 400, headers: { 'Access-Control-Allow-Origin': '*' } });
    }

    // Free tier: max 200 lines
    const lines = code.split('\n');
    const isPaid = authCtx?.plan && authCtx.plan !== 'FREE';
    const MAX_FREE_LINES = 200;
    const codeToScan = isPaid ? code : lines.slice(0, MAX_FREE_LINES).join('\n');
    const truncated = !isPaid && lines.length > MAX_FREE_LINES;

    const result = scanCode(codeToScan, language);
    result.source = source;
    result.truncated = truncated;
    if (truncated) {
      result.truncation_notice = `Free tier: scanned first ${MAX_FREE_LINES} of ${lines.length} lines. Upgrade for full codebase analysis.`;
    }

    // Persist to D1
    if (env.DB) {
      try {
        await env.DB.prepare(`
          INSERT OR IGNORE INTO vibe_code_scans (scan_id, language, line_count, risk_score, risk_level, vuln_count, user_email, scanned_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `).bind(
          result.scan_id, language, result.line_count,
          result.risk_score, result.risk_level, result.total_vulnerabilities,
          authCtx?.email || null, result.scanned_at
        ).run();
      } catch (_) {}
    }

    return Response.json(result, { headers: { 'Access-Control-Allow-Origin': '*', 'Cache-Control': 'no-store' } });
  } catch (e) {
    return Response.json({ error: 'Vibe code scan failed', detail: e.message }, { status: 500, headers: { 'Access-Control-Allow-Origin': '*' } });
  }
}

// ── Handler: Vulnerability Patterns Catalog ──────────────────────────────────
export async function handleVibeCodePatterns(request, env) {
  return Response.json({
    version: 'v29.0',
    pattern_count: VIBE_PATTERNS.length,
    patterns: VIBE_PATTERNS.map(p => ({
      id: p.id, severity: p.severity, title: p.title,
      description: p.description, pattern_desc: p.pattern_desc,
      ai_cause: p.ai_cause, cvss_base: p.cvss_base,
      references: p.references,
    })),
    supported_languages: ['javascript', 'typescript', 'python', 'php', 'java', 'go'],
    last_updated: '2026-06-01',
    powered_by: 'CYBERDUDEBIVASH Vibe Code Security Lab',
  }, { headers: { 'Access-Control-Allow-Origin': '*', 'Cache-Control': 'public, max-age=3600' } });
}
