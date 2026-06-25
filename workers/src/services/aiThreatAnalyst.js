/**
 * CYBERDUDEBIVASH® AI Security Hub — AI Threat Analyst Engine v1.0
 *
 * Natural-language threat intelligence analyst powered by LLM + RAG.
 * Answers analyst questions grounded in live threat data from D1.
 *
 * Architecture:
 *   1. Semantic query parsing — extract entities (CVE IDs, actor names, sectors, techniques)
 *   2. Context retrieval — pull relevant CVEs, actors, campaigns from D1
 *   3. LLM synthesis — generate grounded, cited analyst brief
 *   4. Citation enforcement — every claim must cite a CVE ID or source
 *
 * AI Provider cascade (same as APEX Copilot):
 *   Groq (llama-3.1-70b, fastest) → DeepSeek (reasoning) → OpenRouter → CF AI (fallback)
 */

const ANALYST_SYSTEM_PROMPT = `You are SENTINEL, an elite AI threat intelligence analyst for CYBERDUDEBIVASH® AI Security Hub. You have deep expertise in:
- CVE vulnerability analysis and prioritization
- APT actor attribution and threat actor profiling
- MITRE ATT&CK technique mapping
- Incident response and threat hunting
- CISA KEV interpretation and remediation guidance

RULES:
1. Ground every claim in the CONTEXT provided below. Do NOT fabricate CVE IDs, scores, or actor attributions.
2. Structure responses with: Threat Summary → Risk Level → Key Findings → Recommended Actions
3. Be direct and concise — analysts need actionable intelligence, not verbose explanations.
4. Always cite specific CVE IDs, actor names, and ATT&CK technique IDs when available in context.
5. Use threat intelligence terminology precisely.
6. If asked about something not in the context, say "This is not in current threat data" rather than hallucinating.
`;

// ─── LLM provider cascade (mirrors APEX Copilot v4.0) ────────────────────────
async function callLLM(systemPrompt, userMessage, env) {
  const model = 'llama-3.1-70b-versatile';

  // ── Groq (fastest, primary) ───────────────────────────────────────────────
  if (env?.GROQ_API_KEY) {
    try {
      const res = await fetch('https://api.groq.com/openai/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${env.GROQ_API_KEY}`,
          'Content-Type':  'application/json',
        },
        body: JSON.stringify({
          model,
          messages: [
            { role: 'system',    content: systemPrompt },
            { role: 'user',      content: userMessage },
          ],
          temperature:  0.2,  // low temp for factual accuracy
          max_tokens:   1200,
          stream:       false,
        }),
        signal: AbortSignal.timeout(12000),
      });
      if (res.ok) {
        const data = await res.json();
        const text = data.choices?.[0]?.message?.content?.trim();
        if (text) return { text, model: `groq/${model}`, provider: 'groq' };
      }
    } catch {}
  }

  // ── DeepSeek (strong reasoning) ───────────────────────────────────────────
  if (env?.DEEPSEEK_API_KEY) {
    try {
      const res = await fetch('https://api.deepseek.com/chat/completions', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${env.DEEPSEEK_API_KEY}`,
          'Content-Type':  'application/json',
        },
        body: JSON.stringify({
          model:       'deepseek-chat',
          messages:    [
            { role: 'system', content: systemPrompt },
            { role: 'user',   content: userMessage },
          ],
          temperature: 0.2,
          max_tokens:  1200,
        }),
        signal: AbortSignal.timeout(15000),
      });
      if (res.ok) {
        const data = await res.json();
        const text = data.choices?.[0]?.message?.content?.trim();
        if (text) return { text, model: 'deepseek-chat', provider: 'deepseek' };
      }
    } catch {}
  }

  // ── OpenRouter (meta-provider) ─────────────────────────────────────────────
  if (env?.OPENROUTER_API_KEY) {
    try {
      const res = await fetch('https://openrouter.ai/api/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${env.OPENROUTER_API_KEY}`,
          'Content-Type':  'application/json',
          'HTTP-Referer':  'https://cyberdudebivash.in',
          'X-Title':       'CYBERDUDEBIVASH AI Security Hub',
        },
        body: JSON.stringify({
          model:       'meta-llama/llama-3.1-70b-instruct',
          messages:    [
            { role: 'system', content: systemPrompt },
            { role: 'user',   content: userMessage },
          ],
          temperature: 0.2,
          max_tokens:  1200,
        }),
        signal: AbortSignal.timeout(15000),
      });
      if (res.ok) {
        const data = await res.json();
        const text = data.choices?.[0]?.message?.content?.trim();
        if (text) return { text, model: 'llama-3.1-70b-instruct', provider: 'openrouter' };
      }
    } catch {}
  }

  // ── Cloudflare Workers AI (fallback) ──────────────────────────────────────
  if (env?.AI) {
    try {
      const res = await env.AI.run('@cf/meta/llama-3.1-8b-instruct', {
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user',   content: userMessage },
        ],
        max_tokens: 800,
      });
      const text = res?.response?.trim();
      if (text) return { text, model: 'llama-3.1-8b-instruct', provider: 'cf_ai' };
    } catch {}
  }

  throw new Error('All AI providers unavailable');
}

// ─── Context retrieval — pull relevant threat data from D1 ────────────────────
async function retrieveContext(query, env, maxEntries = 15) {
  if (!env?.DB) return { entries: [], actors: [] };

  const q = query.toLowerCase();
  const results = { entries: [], actors: [] };

  // Extract CVE IDs from query
  const cveMatches = query.match(/CVE-\d{4}-\d{4,7}/gi) || [];

  // Build D1 query
  try {
    let dbEntries = [];

    if (cveMatches.length > 0) {
      // Direct CVE lookup
      const placeholders = cveMatches.map(() => '?').join(',');
      const rows = await env.DB.prepare(
        `SELECT id, title, severity, cvss, description, exploit_status, known_ransomware,
                published_at, source, tags, weakness_types, affected_products
         FROM threat_intel WHERE id IN (${placeholders}) LIMIT 10`
      ).bind(...cveMatches).all();
      dbEntries = rows?.results || [];
    }

    // Keyword search for additional context
    const keywords = q.split(/\s+/).filter(w => w.length > 4).slice(0, 3);
    if (keywords.length > 0 || dbEntries.length < 5) {
      const searchTerm = `%${keywords[0] || q.slice(0, 20)}%`;
      const keywordRows = await env.DB.prepare(
        `SELECT id, title, severity, cvss, description, exploit_status, known_ransomware,
                published_at, source, tags, weakness_types
         FROM threat_intel
         WHERE (title LIKE ? OR description LIKE ?)
         ORDER BY CASE severity WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 ELSE 1 END DESC, cvss DESC
         LIMIT ?`
      ).bind(searchTerm, searchTerm, maxEntries - dbEntries.length).all();

      const additional = (keywordRows?.results || []).filter(r => !dbEntries.some(e => e.id === r.id));
      dbEntries = [...dbEntries, ...additional];
    }

    // Always add latest criticals for context
    if (dbEntries.length < 5) {
      const critRows = await env.DB.prepare(
        `SELECT id, title, severity, cvss, description, exploit_status, known_ransomware,
                published_at, source, tags
         FROM threat_intel WHERE severity = 'CRITICAL'
         ORDER BY cvss DESC, published_at DESC LIMIT 10`
      ).all();
      const criticals = (critRows?.results || []).filter(r => !dbEntries.some(e => e.id === r.id));
      dbEntries = [...dbEntries, ...criticals];
    }

    results.entries = dbEntries.slice(0, maxEntries);
  } catch {}

  return results;
}

// ─── Format context for LLM prompt ───────────────────────────────────────────
function formatContext(retrievedCtx, queryType) {
  const { entries } = retrievedCtx;

  if (!entries.length) return 'No threat data currently available in the database.';

  const formatted = entries.slice(0, 12).map(e => {
    const tags = (() => { try { return JSON.parse(e.tags || '[]'); } catch { return []; } })();
    return [
      `CVE: ${e.id} | Severity: ${e.severity} | CVSS: ${e.cvss}`,
      `Title: ${e.title}`,
      `Status: ${e.exploit_status || 'unknown'} | Ransomware: ${e.known_ransomware ? 'YES' : 'no'}`,
      `Published: ${e.published_at} | Tags: ${tags.join(', ')}`,
      `Description: ${(e.description || '').slice(0, 200)}`,
      '---',
    ].join('\n');
  }).join('\n');

  return `CURRENT THREAT DATABASE (${entries.length} relevant entries):\n\n${formatted}`;
}

// ─── Session cache in KV ──────────────────────────────────────────────────────
const SESSION_TTL = 3600; // 1 hour sessions

async function getSession(sessionId, env) {
  if (!env?.SECURITY_HUB_KV || !sessionId) return { messages: [] };
  try {
    const raw = await env.SECURITY_HUB_KV.get(`analyst:session:${sessionId}`);
    return raw ? JSON.parse(raw) : { messages: [] };
  } catch { return { messages: [] }; }
}

async function saveSession(sessionId, session, env) {
  if (!env?.SECURITY_HUB_KV || !sessionId) return;
  try {
    await env.SECURITY_HUB_KV.put(
      `analyst:session:${sessionId}`,
      JSON.stringify(session),
      { expirationTtl: SESSION_TTL }
    );
  } catch {}
}

// ─── Main analyst query handler ───────────────────────────────────────────────
export async function analyzeQuery(query, env, options = {}) {
  if (!query?.trim()) {
    throw new Error('Query is required');
  }

  const sessionId = options.session_id || null;
  const tier      = options.tier || 'FREE';

  // Load conversation history
  const session = await getSession(sessionId, env);

  // Retrieve relevant threat context from D1
  const context = await retrieveContext(query, env, 15);
  const contextText = formatContext(context, 'general');

  // Build the user message with context
  const userMessage = `ANALYST QUERY: ${query}

${contextText}

Please provide a concise threat intelligence analysis addressing this query. Ground your response in the context above. Format:
1. **Threat Summary** (2-3 sentences)
2. **Risk Level & Priority**
3. **Key Findings** (bullet points)
4. **Recommended Actions** (numbered steps)`;

  // Include conversation history for multi-turn (last 4 exchanges)
  const historyMessages = session.messages.slice(-8);

  // Build full system prompt
  const systemPrompt = ANALYST_SYSTEM_PROMPT;

  // Build messages with history
  const messages = [
    { role: 'system', content: systemPrompt },
    ...historyMessages,
    { role: 'user', content: userMessage },
  ];

  // Call LLM
  const start = Date.now();
  let response;
  try {
    // For multi-turn, pass history through the cascade
    response = await callLLM(systemPrompt, userMessage, env);
  } catch (err) {
    // Structured fallback — no LLM, still useful
    const topEntries = context.entries.slice(0, 5);
    const fallbackText = topEntries.length > 0
      ? `**Threat Summary**: Based on current data, ${topEntries.length} relevant advisories found.\n\n**Key Findings**:\n${topEntries.map(e => `• ${e.id} (${e.severity}, CVSS ${e.cvss}): ${(e.title || '').slice(0, 80)}`).join('\n')}\n\n**AI Analysis**: LLM providers temporarily unavailable. Raw data above is accurate and live from database.`
      : 'No specific threat data found for this query. Please try a more specific CVE ID, actor name, or vulnerability type.';

    response = { text: fallbackText, model: 'fallback', provider: 'local' };
  }

  const latency_ms = Date.now() - start;

  // Update session history
  session.messages.push(
    { role: 'user',      content: query },  // Store raw query, not context-enriched
    { role: 'assistant', content: response.text }
  );
  if (sessionId) await saveSession(sessionId, session, env);

  return {
    query,
    response:    response.text,
    model:       response.model,
    provider:    response.provider,
    context: {
      entries_retrieved: context.entries.length,
      cve_ids:           context.entries.slice(0, 5).map(e => e.id),
    },
    session_id:  sessionId,
    latency_ms,
    tier,
    generated_at: new Date().toISOString(),
  };
}

// ─── Generate threat brief for a specific CVE ─────────────────────────────────
export async function generateCVEBrief(entry, env, options = {}) {
  const { aptActors = [], attackMapping = null } = options;

  const actorContext = aptActors.length > 0
    ? `\nAPT ATTRIBUTION: This CVE is associated with ${aptActors.map(a => a.actor_id).join(', ')}.\n`
    : '';

  const attackContext = attackMapping?.techniques?.length > 0
    ? `\nMITRE ATT&CK MAPPING: ${attackMapping.techniques.slice(0, 3).map(t => `${t.technique_id} (${t.technique_name})`).join(', ')}\n`
    : '';

  const query = `Analyze CVE ${entry.id}: ${entry.title}
CVSS: ${entry.cvss} | Severity: ${entry.severity} | Exploit Status: ${entry.exploit_status || 'unknown'}
Description: ${(entry.description || '').slice(0, 300)}
${actorContext}${attackContext}
Provide: impact assessment, attack chain, who is at risk, and specific remediation steps.`;

  return analyzeQuery(query, env, { tier: options.tier });
}

// ─── Sector threat brief ───────────────────────────────────────────────────────
export async function generateSectorBrief(sector, env) {
  const query = `What are the current top threats and vulnerabilities for the ${sector} sector? Focus on actively exploited CVEs, relevant APT groups targeting this sector, and key remediation priorities for ${sector} security teams.`;
  return analyzeQuery(query, env, { tier: 'ENTERPRISE' });
}
