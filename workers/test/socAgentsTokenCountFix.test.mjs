/* P3 (Tier-3, cosmetic/minor class) — soc-agents.html's per-agent "meta" row
 * (model · provider · latency · tokens) never showed a token count, for any
 * agent, on any successful run, ever.
 *
 * ROOT CAUSE: updateAgentCard() read `result.tokens?.total_tokens`. The
 * actual, only, field shape ever produced by the backend is
 * `tokens: { input, output }` (runAgent() in
 * workers/src/handlers/multiAgentSOC.js passes through routeAICall()'s
 * return value unchanged — see src/core/aiProviderRouter.js's
 * dispatchToProvider(), `tokens: { input: raw.input_tokens, output:
 * raw.output_tokens }`). There is no total_tokens field anywhere in the real
 * response, on any of the three routes that feed updateAgentCard()
 * (/api/agents/run, /api/agents/stream, /api/agents/dispatch/:id — all three
 * call the same runAgent()) — so the field-path read was always undefined,
 * silently dropping the pill instead of ever showing real usage.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';

const html = readFileSync(new URL('../../frontend/soc-agents.html', import.meta.url), 'utf8');

function fnBody(name) {
  const marker = `function ${name}(`;
  const start = html.indexOf(marker);
  expect(start, `${name} should be defined`).toBeGreaterThan(-1);
  const bodyStart = html.indexOf('{', start);
  let depth = 0, i = bodyStart;
  for (; i < html.length; i++) {
    if (html[i] === '{') depth++;
    else if (html[i] === '}') { depth--; if (depth === 0) break; }
  }
  return html.slice(start, i + 1);
}

describe('soc-agents.html — token-count pill read a field that never existed (static parse)', () => {
  it('updateAgentCard() no longer reads the nonexistent tokens.total_tokens field', () => {
    const body = fnBody('updateAgentCard');
    expect(body).not.toMatch(/tokens\??\.total_tokens/);
  });

  it('updateAgentCard() derives the total from the real tokens.input / tokens.output fields', () => {
    const body = fnBody('updateAgentCard');
    expect(body).toContain('result.tokens?.input');
    expect(body).toContain('result.tokens?.output');
  });

  it('the tokens pill still degrades cleanly (no pill) when there is no real usage data, matching the original intent', () => {
    const body = fnBody('updateAgentCard');
    expect(body).toMatch(/if\s*\(totalTokens\)/);
  });
});
