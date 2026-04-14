/**
 * CYBERDUDEBIVASH AI Security Hub — Content & Distribution Engine v8.0
 *
 * Auto-generates professional content from scan results and publishes
 * to Telegram channels and (optionally) LinkedIn.
 *
 * Routes:
 *   POST /api/content/generate        — generate blog/post from scan
 *   GET  /api/content                 — list user's content
 *   GET  /api/content/:id             — get single post
 *   POST /api/content/:id/publish     — publish to Telegram / LinkedIn
 *   DELETE /api/content/:id           — delete post
 *   GET  /api/content/feed            — public blog feed (top posts)
 *
 * Also handles:
 *   POST /api/content/auto-publish    — auto-publish from scan (internal)
 */

import { generateBlogPost, buildExecutiveBrief } from '../lib/aiBrain.js';

const MAX_CONTENT_FREE       = 5;
const MAX_CONTENT_PRO        = 50;
const MAX_CONTENT_ENTERPRISE = 500;

// ─── Generate content from scan result ───────────────────────────────────────
export async function handleGenerateContent(request, env, authCtx) {
  if (!authCtx.authenticated) {
    return Response.json({ error: 'Authentication required to generate content' }, { status: 401 });
  }

  let body;
  try { body = await request.json(); } catch {
    return Response.json({ error: 'Invalid JSON body' }, { status: 400 });
  }

  const { scan_result, module, target, type = 'blog', job_id, org_id } = body;

  if (!scan_result || !module) {
    return Response.json({ error: 'scan_result and module are required' }, { status: 400 });
  }

  const validTypes = ['blog', 'linkedin', 'telegram', 'executive_brief', 'threat_advisory'];
  if (!validTypes.includes(type)) {
    return Response.json({ error: `type must be one of: ${validTypes.join(', ')}` }, { status: 400 });
  }

  // Check content limit
  const maxContent = authCtx.tier === 'ENTERPRISE' ? MAX_CONTENT_ENTERPRISE
    : authCtx.tier === 'PRO' ? MAX_CONTENT_PRO : MAX_CONTENT_FREE;

  const existing = await env.DB.prepare(
    `SELECT COUNT(*) as n FROM content_posts WHERE user_id = ?`
  ).bind(authCtx.userId).first();

  if ((existing?.n || 0) >= maxContent) {
    return Response.json({
      error: `Content limit reached (${maxContent} for ${authCtx.tier} tier). Upgrade or delete old posts.`,
      upgrade_url: 'https://cyberdudebivash.in/#pricing',
    }, { status: 429 });
  }

  const findings = [...(scan_result.findings || []), ...(scan_result.locked_findings || [])];
  const generated = generateBlogPost(scan_result, module, target || 'the assessed system', findings);

  // Select content based on type
  let title, bodyMd, excerpt;
  switch (type) {
    case 'linkedin':
      title   = generated.title;
      bodyMd  = generated.linkedin_post;
      excerpt = generated.excerpt;
      break;
    case 'telegram':
      title   = `Telegram: ${generated.title}`;
      bodyMd  = generated.telegram_post;
      excerpt = `Telegram post for ${module.toUpperCase()} scan`;
      break;
    case 'executive_brief': {
      const brief = buildExecutiveBrief(scan_result, module, target, findings, scan_result.risk_score, scan_result.risk_level);
      title   = `Executive Brief: ${brief.headline}`;
      bodyMd  = `# ${brief.headline}\n\n**Date:** ${brief.date}\n**Module:** ${brief.module}\n**Risk Level:** ${brief.level}\n\n${brief.paragraph}\n\n## Board Summary\n${brief.board_summary}`;
      excerpt = brief.board_summary;
      break;
    }
    case 'threat_advisory': {
      title  = `Threat Advisory: ${module.toUpperCase()} Assessment — ${target || 'Your System'}`;
      bodyMd = buildThreatAdvisory(scan_result, module, target, findings, generated);
      excerpt = `Threat advisory covering ${findings.filter(f=>f.severity==='CRITICAL').length} critical and ${findings.filter(f=>f.severity==='HIGH').length} high findings.`;
      break;
    }
    default: // blog
      title   = generated.title;
      bodyMd  = generated.body_md;
      excerpt = generated.excerpt;
  }

  const postId = crypto.randomUUID();
  await env.DB.prepare(`
    INSERT INTO content_posts
      (id, user_id, org_id, type, title, body_md, excerpt, tags,
       scan_job_id, module, target_summary)
    VALUES (?,?,?,?,?,?,?,?,?,?,?)
  `).bind(
    postId, authCtx.userId, org_id || null, type, title, bodyMd, excerpt,
    generated.tags || null, job_id || null, module, target || null,
  ).run();

  return Response.json({
    success:   true,
    post_id:   postId,
    type,
    title,
    body_md:   bodyMd,
    excerpt,
    word_count: bodyMd.split(' ').length,
    message:   `${type} content generated successfully`,
  }, { status: 201 });
}

// ─── List content ─────────────────────────────────────────────────────────────
export async function handleListContent(request, env, authCtx) {
  if (!authCtx.authenticated) {
    return Response.json({ error: 'Authentication required' }, { status: 401 });
  }

  const url    = new URL(request.url);
  const type   = url.searchParams.get('type');
  const limit  = Math.min(parseInt(url.searchParams.get('limit') || '20'), 50);
  const offset = parseInt(url.searchParams.get('offset') || '0');

  let query  = `SELECT id, type, title, excerpt, module, target_summary,
    published_to_telegram, published_to_linkedin, published_at, created_at,
    view_count
    FROM content_posts WHERE user_id = ?`;
  const params = [authCtx.userId];

  if (type) { query += ' AND type = ?'; params.push(type); }
  query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
  params.push(limit, offset);

  const { results } = await env.DB.prepare(query).bind(...params).all();

  const countRow = await env.DB.prepare(
    `SELECT COUNT(*) as n FROM content_posts WHERE user_id = ?`
  ).bind(authCtx.userId).first();

  return Response.json({
    posts:  results || [],
    total:  countRow?.n || 0,
    limit,
    offset,
  });
}

// ─── Get single post ──────────────────────────────────────────────────────────
export async function handleGetContent(request, env, authCtx, postId) {
  if (!authCtx.authenticated) {
    return Response.json({ error: 'Authentication required' }, { status: 401 });
  }

  const post = await env.DB.prepare(
    `SELECT * FROM content_posts WHERE id = ? AND user_id = ?`
  ).bind(postId, authCtx.userId).first();

  if (!post) return Response.json({ error: 'Post not found' }, { status: 404 });

  // Increment view count
  env.DB.prepare(`UPDATE content_posts SET view_count = view_count + 1 WHERE id = ?`).bind(postId).run().catch(() => {});

  return Response.json(post);
}

// ─── Publish to Telegram / LinkedIn ──────────────────────────────────────────
export async function handlePublishContent(request, env, authCtx, postId) {
  if (!authCtx.authenticated) {
    return Response.json({ error: 'Authentication required' }, { status: 401 });
  }

  let body;
  try { body = await request.json(); } catch {
    return Response.json({ error: 'Invalid JSON body' }, { status: 400 });
  }

  const { channels = ['telegram'] } = body;
  const post = await env.DB.prepare(
    `SELECT * FROM content_posts WHERE id = ? AND user_id = ?`
  ).bind(postId, authCtx.userId).first();

  if (!post) return Response.json({ error: 'Post not found' }, { status: 404 });

  const results = { telegram: null, linkedin: null };

  // Publish to Telegram
  if (channels.includes('telegram') && !post.published_to_telegram) {
    const telegramResult = await publishToTelegram(env, post, authCtx.userId);
    results.telegram = telegramResult;

    if (telegramResult.success) {
      await env.DB.prepare(
        `UPDATE content_posts SET published_to_telegram = 1, telegram_msg_id = ?,
         published_at = COALESCE(published_at, datetime('now')) WHERE id = ?`
      ).bind(telegramResult.message_id || null, postId).run();
    }
  } else if (post.published_to_telegram) {
    results.telegram = { success: true, already_published: true };
  }

  // LinkedIn placeholder (requires OAuth2 — returns instructions)
  if (channels.includes('linkedin') && !post.published_to_linkedin) {
    results.linkedin = publishToLinkedIn(post);
    if (results.linkedin.manual_copy) {
      await env.DB.prepare(
        `UPDATE content_posts SET published_to_linkedin = 1,
         published_at = COALESCE(published_at, datetime('now')) WHERE id = ?`
      ).bind(postId).run();
    }
  }

  return Response.json({
    success:  true,
    post_id:  postId,
    published: {
      telegram: results.telegram?.success || false,
      linkedin: results.linkedin?.manual_copy || false,
    },
    results,
  });
}

// ─── Delete content ───────────────────────────────────────────────────────────
export async function handleDeleteContent(request, env, authCtx, postId) {
  if (!authCtx.authenticated) {
    return Response.json({ error: 'Authentication required' }, { status: 401 });
  }

  const result = await env.DB.prepare(
    `DELETE FROM content_posts WHERE id = ? AND user_id = ?`
  ).bind(postId, authCtx.userId).run();

  if (!result.meta?.changes) {
    return Response.json({ error: 'Post not found' }, { status: 404 });
  }

  return Response.json({ success: true, message: 'Post deleted' });
}

// ─── Public blog feed ─────────────────────────────────────────────────────────
export async function handleContentFeed(request, env) {
  const url   = new URL(request.url);
  const limit = Math.min(parseInt(url.searchParams.get('limit') || '10'), 20);
  const type  = url.searchParams.get('type') || 'blog';

  const { results } = await env.DB.prepare(`
    SELECT id, type, title, excerpt, module, target_summary, published_at, created_at
    FROM content_posts
    WHERE published_to_telegram = 1 OR published_at IS NOT NULL
    ORDER BY created_at DESC LIMIT ?
  `).bind(limit).all();

  return Response.json({
    feed:  results || [],
    total: results?.length || 0,
  });
}

// ─── Auto-publish after paid scan (internal) ──────────────────────────────────
export async function autoPublishScanContent(env, scanResult, module, target, userId) {
  if (!env?.SENTINEL_CHANNEL_ID || !env?.TELEGRAM_BOT_TOKEN) return;

  try {
    const findings = [...(scanResult.findings || []), ...(scanResult.locked_findings || [])];
    const generated = generateBlogPost(scanResult, module, target, findings);
    const score     = scanResult.risk_score || 0;

    // Only auto-publish if HIGH or CRITICAL risk
    if (score < 60) return;

    const postId = crypto.randomUUID();
    await env.DB.prepare(`
      INSERT INTO content_posts
        (id, user_id, type, title, body_md, excerpt, tags, module, target_summary)
      VALUES (?,?,?,?,?,?,?,?,?)
    `).bind(
      postId, userId, 'telegram',
      generated.title, generated.telegram_post, generated.excerpt,
      generated.tags, module, target,
    ).run();

    // Publish to Sentinel APEX Telegram channel
    await fetch(`https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chat_id:    env.SENTINEL_CHANNEL_ID,
        text:       generated.telegram_post,
        parse_mode: 'HTML',
        disable_web_page_preview: false,
      }),
    });

    await env.DB.prepare(
      `UPDATE content_posts SET published_to_telegram = 1, published_at = datetime('now') WHERE id = ?`
    ).bind(postId).run();

  } catch (err) {
    console.error('[ContentEngine] auto-publish error:', err?.message);
  }
}

// ─── Telegram publisher ───────────────────────────────────────────────────────
async function publishToTelegram(env, post, userId) {
  if (!env.TELEGRAM_BOT_TOKEN) {
    return { success: false, error: 'TELEGRAM_BOT_TOKEN not configured' };
  }

  // Get user's telegram_chat_id or use Sentinel channel
  let chatId = null;
  try {
    const user = await env.DB.prepare(
      `SELECT telegram_chat_id FROM users WHERE id = ?`
    ).bind(userId).first();
    chatId = user?.telegram_chat_id || env.SENTINEL_CHANNEL_ID;
  } catch {
    chatId = env.SENTINEL_CHANNEL_ID;
  }

  if (!chatId) return { success: false, error: 'No Telegram chat ID configured' };

  // Truncate to Telegram limit (4096 chars)
  const text = (post.body_md || post.title || '').slice(0, 4000);

  try {
    const resp = await fetch(`https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chat_id:    chatId,
        text,
        parse_mode: 'HTML',
        disable_web_page_preview: false,
      }),
    });
    const data = await resp.json();

    if (data.ok) {
      return { success: true, message_id: data.result?.message_id, chat_id: chatId };
    } else {
      return { success: false, error: data.description || 'Telegram API error' };
    }
  } catch (err) {
    return { success: false, error: err?.message };
  }
}

// ─── LinkedIn publisher (manual copy approach) ────────────────────────────────
function publishToLinkedIn(post) {
  return {
    success:     true,
    manual_copy: true,
    message:     'LinkedIn API requires OAuth2. Copy the text below and paste into LinkedIn.',
    text:        post.body_md,
    character_count: post.body_md?.length || 0,
    linkedin_url:    'https://www.linkedin.com/sharing/share-offsite/?url=https://cyberdudebivash.in',
    tip:         'For automated LinkedIn posting, contact bivash@cyberdudebivash.com for Enterprise API access.',
  };
}

// ─── Threat Advisory builder ──────────────────────────────────────────────────
function buildThreatAdvisory(scanResult, module, target, findings, generated) {
  const score  = scanResult.risk_score || 0;
  const level  = scanResult.risk_level || 'MEDIUM';
  const crits  = findings.filter(f => f.severity === 'CRITICAL').length;
  const highs  = findings.filter(f => f.severity === 'HIGH').length;
  const date   = new Date().toLocaleDateString('en-IN', { year: 'numeric', month: 'long', day: 'numeric' });

  let doc = `# THREAT ADVISORY\n**Classification:** TLP:WHITE | **Date:** ${date}\n\n`;
  doc += `## Affected System\n- **Target:** ${target || 'Assessed System'}\n- **Module:** ${module.toUpperCase()}\n- **Risk Score:** ${score}/100 (${level})\n\n`;
  doc += `## Executive Summary\n${generated.excerpt || 'Security assessment identified significant vulnerabilities requiring attention.'}\n\n`;

  doc += `## Critical Findings\n`;
  if (crits > 0) {
    findings.filter(f => f.severity === 'CRITICAL').forEach((f, i) => {
      doc += `### ${i+1}. ${f.title}\n**Severity:** CRITICAL | **CVSS:** ${f.cvss_base || 'N/A'}\n${f.description || ''}\n**Remediation:** ${f.recommendation || 'Immediate action required'}\n\n`;
    });
  } else {
    doc += `No critical findings identified.\n\n`;
  }

  doc += `## High-Severity Findings\n`;
  if (highs > 0) {
    findings.filter(f => f.severity === 'HIGH').slice(0, 5).forEach((f, i) => {
      doc += `${i+1}. **${f.title}** — ${f.description?.slice(0, 100) || 'See full report'}\n`;
    });
  } else {
    doc += `No high-severity findings identified.\n`;
  }

  doc += `\n## Recommended Actions\n`;
  doc += `1. Immediately remediate all CRITICAL findings\n`;
  doc += `2. Schedule HIGH findings for resolution within 7 days\n`;
  doc += `3. Re-scan after remediation to confirm resolution\n`;
  doc += `4. Contact bivash@cyberdudebivash.com for enterprise support\n\n`;
  doc += `---\n*CYBERDUDEBIVASH AI Security Hub | ${date} | https://cyberdudebivash.in*`;

  return doc;
}
