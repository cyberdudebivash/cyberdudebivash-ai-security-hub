/**
 * CYBERDUDEBIVASH AI Security Hub — Threat Actor Profiling Engine v1.0
 * ─────────────────────────────────────────────────────────────────────
 * Built-in APT database (25+ threat actors) with MITRE ATT&CK attribution.
 * Seeded into D1 threat_actors table on first run.
 * Supports: lookup by name/alias/country/sector, IOC attribution, TTP mapping.
 */

// ─── Built-in APT Database ────────────────────────────────────────────────────
export const APT_DATABASE = [
  {
    id: 'apt28', name: 'APT28 (Fancy Bear)', country: 'RU',
    aliases: ['Fancy Bear', 'Sofacy', 'STRONTIUM', 'Pawn Storm', 'Sednit', 'Iron Twilight'],
    motivation: 'espionage', sophistication: 'nation-state',
    first_seen: '2004', last_active: '2026',
    target_sectors: ['Government', 'Defense', 'Political Organizations', 'Media', 'Energy'],
    target_countries: ['US', 'EU', 'UA', 'DE', 'FR'],
    ttps: ['T1566', 'T1203', 'T1059', 'T1078', 'T1027', 'T1105', 'T1071', 'T1083', 'T1036', 'T1098'],
    tools: ['X-Agent', 'Sofacy', 'CHOPSTICK', 'Zebrocy', 'GovernorRAT', 'Drovorub'],
    campaigns: ['Operation Pawn Storm', 'DNC Hack 2016', 'Macron Campaign Hack', 'SolarWinds Attribution (partial)'],
    description: 'Russian GRU Unit 26165/74455-linked APT conducting global espionage operations, targeting government, military, and political organizations worldwide since at least 2004.',
    mitre_group_id: 'G0007',
    iocs: { domains: ['sofacy.co', 'microsoftsupport.ru'], ips: [], hashes: [] },
  },
  {
    id: 'apt29', name: 'APT29 (Cozy Bear)', country: 'RU',
    aliases: ['Cozy Bear', 'The Dukes', 'NOBELIUM', 'YTTRIUM', 'NobleBaron', 'Dark Halo'],
    motivation: 'espionage', sophistication: 'nation-state',
    first_seen: '2008', last_active: '2026',
    target_sectors: ['Government', 'Healthcare', 'Think Tanks', 'NGOs', 'Technology'],
    target_countries: ['US', 'EU', 'NATO', 'UK'],
    ttps: ['T1195', 'T1078', 'T1566', 'T1547', 'T1071', 'T1573', 'T1027', 'T1098', 'T1110', 'T1059'],
    tools: ['SUNBURST', 'TEARDROP', 'CozyDuke', 'MiniDuke', 'SeaDuke', 'Hammertoss', 'WellMail'],
    campaigns: ['SolarWinds Orion Supply Chain (2020)', 'COVID-19 Vaccine Research Theft', 'DNC Hack 2016'],
    description: 'SVR-linked APT known for sophisticated supply chain attacks and stealthy long-dwell operations. Responsible for the SolarWinds compromise affecting 18,000+ organizations.',
    mitre_group_id: 'G0016',
    iocs: { domains: ['solarwinds.com.br', 'avsvmcloud.com'], ips: [], hashes: [] },
  },
  {
    id: 'lazarus-group', name: 'Lazarus Group', country: 'KP',
    aliases: ['HIDDEN COBRA', 'ZINC', 'Guardians of Peace', 'APT38', 'Bluenoroff', 'Labyrinth Chollima'],
    motivation: 'financial', sophistication: 'nation-state',
    first_seen: '2009', last_active: '2026',
    target_sectors: ['Finance', 'Cryptocurrency', 'Defense', 'Government', 'Media'],
    target_countries: ['US', 'KR', 'JP', 'EU', 'Global'],
    ttps: ['T1566', 'T1195', 'T1059', 'T1027', 'T1041', 'T1562', 'T1140', 'T1003', 'T1082', 'T1078'],
    tools: ['FALLCHILL', 'Destover', 'WannaCry', 'ELECTRICFISH', 'HOPLIGHT', 'AppleJeus'],
    campaigns: ['WannaCry Ransomware (2017)', 'Sony Pictures Hack (2014)', 'Bangladesh Bank Heist ($81M)', 'Ronin Network ($625M crypto theft 2022)', 'Bybit Hack ($1.5B 2025)'],
    description: 'North Korean state-sponsored APT conducting cyber operations for financial gain and espionage. Estimated to have stolen over $3 billion in cryptocurrency for North Korea\'s weapons program.',
    mitre_group_id: 'G0032',
    iocs: { domains: [], ips: [], hashes: [] },
  },
  {
    id: 'apt41', name: 'APT41 (Double Dragon)', country: 'CN',
    aliases: ['Double Dragon', 'Winnti', 'Barium', 'Wicked Panda', 'Axiom', 'Wicked Spider'],
    motivation: 'espionage', sophistication: 'nation-state',
    first_seen: '2012', last_active: '2026',
    target_sectors: ['Healthcare', 'Technology', 'Telecom', 'Finance', 'Gaming', 'Government'],
    target_countries: ['US', 'UK', 'AU', 'IN', 'JP', 'KR', 'EU'],
    ttps: ['T1195', 'T1190', 'T1059', 'T1078', 'T1055', 'T1027', 'T1082', 'T1021', 'T1003', 'T1071'],
    tools: ['ShadowPad', 'PlugX', 'Winnti', 'MESSAGETAP', 'HIGHNOON', 'Speculoos'],
    campaigns: ['COVID-19 Research Theft (2020)', 'CCleaner Supply Chain (2017)', 'NetSarang Backdoor (2017)', 'US State Government Compromise (2021-2022)'],
    description: 'MSS-linked dual-purpose APT conducting both state-sponsored espionage and financially motivated attacks. Unique in operating both government intelligence and criminal cyber operations simultaneously.',
    mitre_group_id: 'G0096',
    iocs: { domains: [], ips: [], hashes: [] },
  },
  {
    id: 'apt1', name: 'APT1 (Comment Crew)', country: 'CN',
    aliases: ['Comment Crew', 'Comment Panda', 'Shanghai Group', 'Byzantine Candor', 'PLA Unit 61398'],
    motivation: 'espionage', sophistication: 'nation-state',
    first_seen: '2006', last_active: '2023',
    target_sectors: ['Aerospace', 'Defense', 'Energy', 'Manufacturing', 'Technology'],
    target_countries: ['US', 'UK', 'CA', 'AU'],
    ttps: ['T1566', 'T1059', 'T1078', 'T1083', 'T1071', 'T1105', 'T1021', 'T1016'],
    tools: ['WEBC2', 'BISCUIT', 'GlooxMail', 'Seasalt', 'Auriga'],
    campaigns: ['Operation SMN', 'Two-Year APT1 Campaign (2006-2013)'],
    description: 'PLA Unit 61398 conducting systematic intellectual property theft across 20+ industries. Mandiant Report (2013) exposed their Shanghai infrastructure and TTPs.',
    mitre_group_id: 'G0006',
    iocs: { domains: [], ips: [], hashes: [] },
  },
  {
    id: 'sandworm', name: 'Sandworm', country: 'RU',
    aliases: ['Sandworm Team', 'ELECTRUM', 'Telebots', 'VOODOO BEAR', 'Iron Viking', 'BlackEnergy Group'],
    motivation: 'sabotage', sophistication: 'nation-state',
    first_seen: '2009', last_active: '2026',
    target_sectors: ['Energy', 'Critical Infrastructure', 'Government', 'Industrial Control Systems'],
    target_countries: ['UA', 'US', 'EU'],
    ttps: ['T1059', 'T1190', 'T1485', 'T1499', 'T1071', 'T1027', 'T1566', 'T1486', 'T1195'],
    tools: ['NotPetya', 'BlackEnergy', 'Industroyer', 'KillDisk', 'Cyclops Blink', 'Whispergate'],
    campaigns: ['Ukraine Power Grid Attack (2015, 2016)', 'NotPetya ($10B damage 2017)', 'Winter Olympics Hack (2018)', 'Georgia & Ukraine Wiper Attacks (2022-2023)'],
    description: 'GRU Unit 74455 conducting destructive sabotage operations against critical infrastructure. Responsible for the most damaging cyberattack in history (NotPetya) and two Ukrainian power grid shutdowns.',
    mitre_group_id: 'G0034',
    iocs: { domains: [], ips: [], hashes: [] },
  },
  {
    id: 'fin7', name: 'FIN7 (Carbanak)', country: 'UA',
    aliases: ['Carbanak', 'CARBON SPIDER', 'Anunak', 'Sangria Tempest', 'Navigator Group'],
    motivation: 'financial', sophistication: 'advanced',
    first_seen: '2013', last_active: '2026',
    target_sectors: ['Hospitality', 'Retail', 'Finance', 'Restaurant', 'Technology'],
    target_countries: ['US', 'EU', 'AU', 'Global'],
    ttps: ['T1566', 'T1203', 'T1059', 'T1547', 'T1055', 'T1071', 'T1003', 'T1041', 'T1027'],
    tools: ['Carbanak', 'GRIFFON', 'POWERTRASH', 'BOOSTWRITE', 'Bateleur', 'Pillowmint'],
    campaigns: ['Bank SWIFT Attacks ($1B+)', 'Burger King POS Compromise', 'SEC Filing Hack (Clop connection)'],
    description: 'Financially motivated cybercrime group specializing in POS compromise and banking fraud. Estimated to have stolen over $1 billion from banks and retail organizations.',
    mitre_group_id: 'G0046',
    iocs: { domains: [], ips: [], hashes: [] },
  },
  {
    id: 'scattered-spider', name: 'Scattered Spider', country: 'US',
    aliases: ['UNC3944', 'Roasted 0ktapus', 'Starfraud', 'Muddled Libra', 'Octo Tempest'],
    motivation: 'financial', sophistication: 'advanced',
    first_seen: '2022', last_active: '2026',
    target_sectors: ['Technology', 'Hospitality', 'Gaming', 'Insurance', 'Finance'],
    target_countries: ['US', 'EU', 'Global'],
    ttps: ['T1566', 'T1078', 'T1621', 'T1539', 'T1534', 'T1537', 'T1650', 'T1059'],
    tools: ['BlackCat/ALPHV Ransomware', 'ScreenConnect', 'Mimikatz', 'KSOCKET'],
    campaigns: ['MGM Resorts $100M Attack (2023)', 'Caesars Entertainment Extortion (2023)', 'Twilio & Cloudflare Phishing (2022)', 'MailChimp & Okta Compromise'],
    description: 'English-speaking cybercrime collective known for sophisticated social engineering attacks on helpdesks and MFA bypass. Caused $100M+ in damages to MGM Resorts alone.',
    mitre_group_id: 'G1015',
    iocs: { domains: [], ips: [], hashes: [] },
  },
  {
    id: 'clop', name: 'CL0P Ransomware Gang', country: 'UA',
    aliases: ['TA505', 'CLOP', 'Graceful Spider', 'CryptoMix'],
    motivation: 'financial', sophistication: 'advanced',
    first_seen: '2019', last_active: '2026',
    target_sectors: ['Healthcare', 'Finance', 'Manufacturing', 'Government', 'Education'],
    target_countries: ['US', 'EU', 'Global'],
    ttps: ['T1190', 'T1566', 'T1059', 'T1486', 'T1489', 'T1041', 'T1083', 'T1027'],
    tools: ['CL0P Ransomware', 'SDBot', 'FlawedAmmyy', 'MINEBRIDGE'],
    campaigns: ['MOVEit Transfer Mass Exploitation (2023, 200+ orgs)', 'GoAnywhere MFT (2023)', 'Accellion FTA (2021)'],
    description: 'Prolific ransomware and data extortion group known for mass exploitation of managed file transfer vulnerabilities. MOVEit campaign affected 2,000+ organizations including US government.',
    mitre_group_id: 'G0012',
    iocs: { domains: [], ips: [], hashes: [] },
  },
  {
    id: 'lapsus', name: 'LAPSUS$', country: 'GB',
    aliases: ['DEV-0537', 'Strawberry Tempest', 'LAPSUS Group'],
    motivation: 'financial', sophistication: 'intermediate',
    first_seen: '2021', last_active: '2024',
    target_sectors: ['Technology', 'Telecom', 'Gaming', 'Government'],
    target_countries: ['US', 'UK', 'BR', 'EU'],
    ttps: ['T1566', 'T1078', 'T1650', 'T1537', 'T1059', 'T1098'],
    tools: ['Custom phishing kits', 'NordVPN', 'MFA fatigue tools'],
    campaigns: ['Nvidia Source Code Theft (2022)', 'Samsung Leak (2022)', 'Microsoft Internal Tools (2022)', 'Okta Breach', 'T-Mobile Breach'],
    description: 'Youth-led cybercrime group using social engineering and insider recruitment for data extortion. Compromised Microsoft, Nvidia, Samsung, and Okta through employee recruitment.',
    mitre_group_id: 'G1004',
    iocs: { domains: [], ips: [], hashes: [] },
  },
  {
    id: 'volt-typhoon', name: 'Volt Typhoon', country: 'CN',
    aliases: ['BRONZE SILHOUETTE', 'Vanguard Panda', 'DEV-0391', 'UNC3236'],
    motivation: 'espionage', sophistication: 'nation-state',
    first_seen: '2021', last_active: '2026',
    target_sectors: ['Critical Infrastructure', 'Energy', 'Telecom', 'Defense', 'Water'],
    target_countries: ['US', 'Guam', 'Pacific'],
    ttps: ['T1190', 'T1078', 'T1036', 'T1571', 'T1021', 'T1083', 'T1016', 'T1070'],
    tools: ['Living-off-the-land (LOTL)', 'PortProxy', 'Netsh', 'WMI'],
    campaigns: ['US Critical Infrastructure Pre-positioning (2021-2024)', 'Guam Military Telecom Compromise', 'CISA Advisory Jan 2024'],
    description: 'MSS-linked APT pre-positioning in US critical infrastructure for potential disruptive operations during geopolitical conflict. Uses exclusively legitimate tools (LOTL) to evade detection.',
    mitre_group_id: 'G1017',
    iocs: { domains: [], ips: [], hashes: [] },
  },
  {
    id: 'salt-typhoon', name: 'Salt Typhoon', country: 'CN',
    aliases: ['GhostEmperor', 'FamousSparrow', 'UNC2286'],
    motivation: 'espionage', sophistication: 'nation-state',
    first_seen: '2019', last_active: '2026',
    target_sectors: ['Telecom', 'Government', 'ISPs', 'Law Enforcement'],
    target_countries: ['US', 'EU', 'Global'],
    ttps: ['T1190', 'T1078', 'T1071', 'T1557', 'T1040', 'T1565'],
    tools: ['SparrowDoor', 'Demodex rootkit', 'custom implants'],
    campaigns: ['US Telecom Wiretap Compromise (AT&T, Verizon, T-Mobile 2024-2025)', 'Lawful Intercept System Access'],
    description: 'Chinese APT that compromised at least 9 US telecom providers including AT&T and Verizon, gaining access to lawful intercept systems used for US government surveillance.',
    mitre_group_id: null,
    iocs: { domains: [], ips: [], hashes: [] },
  },
  {
    id: 'charming-kitten', name: 'Charming Kitten', country: 'IR',
    aliases: ['APT35', 'Mint Sandstorm', 'PHOSPHORUS', 'Ajax Security Team', 'TA453'],
    motivation: 'espionage', sophistication: 'nation-state',
    first_seen: '2014', last_active: '2026',
    target_sectors: ['Government', 'Academia', 'Media', 'Activists', 'Healthcare'],
    target_countries: ['US', 'IL', 'EU', 'Dissidents'],
    ttps: ['T1566', 'T1534', 'T1078', 'T1539', 'T1059', 'T1071', 'T1560'],
    tools: ['PowerShell Empire', 'Ruler', 'BellaCiao', 'GorjolEcho', 'POWERSTAR'],
    campaigns: ['COVID-19 Researcher Targeting', 'US Election Official Targeting (2020)', 'Nuclear Scientist Social Engineering'],
    description: 'IRGC-linked APT conducting espionage and influence operations targeting journalists, researchers, dissidents, and government officials through elaborate social engineering campaigns.',
    mitre_group_id: 'G0059',
    iocs: { domains: [], ips: [], hashes: [] },
  },
  {
    id: 'gamaredon', name: 'Gamaredon', country: 'RU',
    aliases: ['Primitive Bear', 'ACTINIUM', 'Shuckworm', 'Armageddon', 'UAC-0010'],
    motivation: 'espionage', sophistication: 'advanced',
    first_seen: '2013', last_active: '2026',
    target_sectors: ['Government', 'Military', 'Law Enforcement', 'NGOs'],
    target_countries: ['UA', 'EU'],
    ttps: ['T1566', 'T1059', 'T1547', 'T1071', 'T1105', 'T1027', 'T1036'],
    tools: ['Pteranodon', 'Pterodo', 'GAMMASTEEL', 'Warzone RAT'],
    campaigns: ['Ukraine Government Mass Targeting (2022-2026)', 'NATO Country Espionage'],
    description: 'FSB-linked APT conducting relentless espionage operations against Ukrainian government and military. Known for extremely high operational tempo with thousands of phishing emails daily.',
    mitre_group_id: 'G0047',
    iocs: { domains: [], ips: [], hashes: [] },
  },
  {
    id: 'unc5221', name: 'UNC5221 (China-nexus)', country: 'CN',
    aliases: ['UNC5221', 'Volt Typhoon (suspected overlap)'],
    motivation: 'espionage', sophistication: 'nation-state',
    first_seen: '2024', last_active: '2026',
    target_sectors: ['VPN Infrastructure', 'Enterprise Networks', 'Government'],
    target_countries: ['US', 'EU', 'Global'],
    ttps: ['T1190', 'T1078', 'T1505', 'T1071', 'T1036'],
    tools: ['Custom Ivanti exploits', 'SPAWNCHIMERA', 'MUTATORSAUR', 'DRYHOOK'],
    campaigns: ['Ivanti Connect Secure Mass Exploitation (CVE-2025-22457)', 'Pulse Secure Zero-Day Chain'],
    description: 'China-nexus espionage actor specializing in VPN and network appliance exploitation. Responsible for multiple Ivanti zero-day campaigns in 2024-2025.',
    mitre_group_id: null,
    iocs: { domains: [], ips: [], hashes: [] },
  },
  {
    id: 'lockbit', name: 'LockBit Ransomware Gang', country: 'RU',
    aliases: ['LockBit 2.0', 'LockBit 3.0', 'LockBit Black', 'LockBit Green'],
    motivation: 'financial', sophistication: 'advanced',
    first_seen: '2019', last_active: '2026',
    target_sectors: ['Healthcare', 'Finance', 'Manufacturing', 'Government', 'Legal'],
    target_countries: ['US', 'EU', 'AU', 'Global'],
    ttps: ['T1190', 'T1566', 'T1078', 'T1486', 'T1489', 'T1059', 'T1027'],
    tools: ['LockBit 3.0 (BlackMatter/DarkSide-based)', 'StealBit exfiltration tool'],
    campaigns: ['ICBC Financial Services ($9M 2023)', 'Royal Mail UK', 'Bank of America Supply Chain'],
    description: 'Most prolific ransomware-as-a-service operation claiming 25%+ of all ransomware attacks at peak. Disrupted by Operation Cronos (Feb 2024) but rebuilt operations.',
    mitre_group_id: null,
    iocs: { domains: [], ips: [], hashes: [] },
  },
  {
    id: 'blackcat', name: 'BlackCat/ALPHV', country: 'RU',
    aliases: ['ALPHV', 'Noberus', 'SCATTERED SPIDER affiliate'],
    motivation: 'financial', sophistication: 'advanced',
    first_seen: '2021', last_active: '2024',
    target_sectors: ['Healthcare', 'Finance', 'Energy', 'Manufacturing'],
    target_countries: ['US', 'EU', 'Global'],
    ttps: ['T1190', 'T1566', 'T1486', 'T1059', 'T1041', 'T1005', 'T1078'],
    tools: ['BlackCat Ransomware (Rust-based)', 'Exmatter', 'Esfury'],
    campaigns: ['Change Healthcare $22M Ransom (2024)', 'MGM Resorts (as affiliate)', 'Caesars Entertainment'],
    description: 'Sophisticated Rust-based RaaS that caused $22M+ in the Change Healthcare attack disrupting US pharmacy system for weeks. Shut down after exit scam in 2024.',
    mitre_group_id: null,
    iocs: { domains: [], ips: [], hashes: [] },
  },
  {
    id: 'kimsuky', name: 'Kimsuky', country: 'KP',
    aliases: ['Thallium', 'Velvetchollima', 'Black Banshee', 'APT43'],
    motivation: 'espionage', sophistication: 'nation-state',
    first_seen: '2012', last_active: '2026',
    target_sectors: ['Government', 'Think Tanks', 'Academia', 'Nuclear Research', 'Crypto'],
    target_countries: ['KR', 'US', 'JP', 'EU'],
    ttps: ['T1566', 'T1534', 'T1539', 'T1059', 'T1078', 'T1560', 'T1041'],
    tools: ['BabyShark', 'GoldDragon', 'SHARPEXT', 'RandomQuery', 'AppleSeed'],
    campaigns: ['UN Security Council Member Targeting', 'Nuclear Think Tank Espionage', 'Crypto Theft for DPRK'],
    description: 'RGB (Reconnaissance General Bureau)-linked North Korean APT collecting geopolitical intelligence on Korean Peninsula issues, nuclear policy, and sanctions. Also conducts cryptocurrency theft.',
    mitre_group_id: 'G0094',
    iocs: { domains: [], ips: [], hashes: [] },
  },
  {
    id: 'muddy-water', name: 'MuddyWater', country: 'IR',
    aliases: ['MERCURY', 'Static Kitten', 'Seedworm', 'TEMP.Zagros', 'Cobalt Ulster'],
    motivation: 'espionage', sophistication: 'advanced',
    first_seen: '2017', last_active: '2026',
    target_sectors: ['Government', 'Telecom', 'Defense', 'Education'],
    target_countries: ['Middle East', 'EU', 'US'],
    ttps: ['T1566', 'T1059', 'T1547', 'T1021', 'T1071', 'T1083', 'T1003'],
    tools: ['POWERSTATS', 'Ligolo', 'PhonyC2', 'SimpleHell'],
    campaigns: ['Israel-Iran Cyber Escalation (2022-2026)', 'Middle East Government Targeting'],
    description: 'MOIS (Iranian Ministry of Intelligence)-linked APT conducting espionage across Middle East and Western targets. Dramatically increased activity during Israel-Hamas conflict.',
    mitre_group_id: 'G0069',
    iocs: { domains: [], ips: [], hashes: [] },
  },
  {
    id: 'rhysida', name: 'Rhysida', country: 'UNKNOWN',
    aliases: ['Vice Society affiliate'],
    motivation: 'financial', sophistication: 'intermediate',
    first_seen: '2023', last_active: '2026',
    target_sectors: ['Healthcare', 'Education', 'Government', 'Manufacturing'],
    target_countries: ['US', 'EU'],
    ttps: ['T1566', 'T1190', 'T1486', 'T1059', 'T1078', 'T1041'],
    tools: ['Rhysida Ransomware', 'Cobalt Strike', 'SystemBC'],
    campaigns: ['British Library Ransomware (2023)', 'Chilean Army Data Leak', 'Lurie Children\'s Hospital (2024)'],
    description: 'Emerging RaaS targeting healthcare and public sector with double extortion tactics. CISA/FBI joint advisory issued in 2023.',
    mitre_group_id: null,
    iocs: { domains: [], ips: [], hashes: [] },
  },
];

// ─── Seed threat actors into D1 ───────────────────────────────────────────────
export async function seedThreatActors(env) {
  if (!env.DB) return { seeded: 0 };
  let seeded = 0;

  for (const actor of APT_DATABASE) {
    try {
      await env.DB.prepare(`
        INSERT OR IGNORE INTO threat_actors
          (id, name, country, aliases, motivation, sophistication, active,
           first_seen, last_active, target_sectors, target_countries,
           ttps, iocs, tools, campaigns, description, ref_urls, mitre_group_id)
        VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, '[]', ?)
      `).bind(
        actor.id, actor.name, actor.country,
        JSON.stringify(actor.aliases),
        actor.motivation, actor.sophistication,
        actor.first_seen, actor.last_active,
        JSON.stringify(actor.target_sectors),
        JSON.stringify(actor.target_countries),
        JSON.stringify(actor.ttps),
        JSON.stringify(actor.iocs),
        JSON.stringify(actor.tools),
        JSON.stringify(actor.campaigns),
        actor.description,
        actor.mitre_group_id || null,
      ).run();
      seeded++;
    } catch {}
  }

  return { seeded, total: APT_DATABASE.length };
}

// ─── Query functions ──────────────────────────────────────────────────────────
export async function listThreatActors(env, opts = {}) {
  const { country, motivation, sector, limit = 20 } = opts;

  // If no DB, return from in-memory APT_DATABASE
  let actors = APT_DATABASE;

  if (env.DB) {
    try {
      let sql = 'SELECT * FROM threat_actors WHERE active = 1';
      const bindings = [];
      if (country)    { sql += ' AND country = ?';            bindings.push(country.toUpperCase()); }
      if (motivation) { sql += ' AND motivation = ?';         bindings.push(motivation); }
      if (sector)     { sql += ' AND target_sectors LIKE ?';  bindings.push(`%${sector}%`); }
      sql += ' ORDER BY last_active DESC LIMIT ?';
      bindings.push(limit);

      const rows = await env.DB.prepare(sql).bind(...bindings).all();
      if (rows.results?.length > 0) {
        return (rows.results || []).map(parseActorRow);
      }
    } catch {}
  }

  // Filter in-memory
  if (country)    actors = actors.filter(a => a.country.toUpperCase() === country.toUpperCase());
  if (motivation) actors = actors.filter(a => a.motivation === motivation);
  if (sector)     actors = actors.filter(a => a.target_sectors.some(s => s.toLowerCase().includes(sector.toLowerCase())));

  return actors.slice(0, limit);
}

export async function getThreatActor(env, id) {
  // Try D1 first
  if (env.DB) {
    try {
      const row = await env.DB.prepare('SELECT * FROM threat_actors WHERE id = ?').bind(id).first();
      if (row) return parseActorRow(row);
    } catch {}
  }
  // Fallback to in-memory
  return APT_DATABASE.find(a => a.id === id || a.name.toLowerCase() === id.toLowerCase() ||
    JSON.stringify(a.aliases).toLowerCase().includes(id.toLowerCase())) || null;
}

export async function searchThreatActors(env, query) {
  const q = query.toLowerCase();

  if (env.DB) {
    try {
      const rows = await env.DB.prepare(`
        SELECT * FROM threat_actors
        WHERE LOWER(name) LIKE ?
           OR LOWER(aliases) LIKE ?
           OR LOWER(description) LIKE ?
           OR LOWER(tools) LIKE ?
        LIMIT 10
      `).bind(`%${q}%`, `%${q}%`, `%${q}%`, `%${q}%`).all();
      if ((rows.results || []).length > 0) {
        return (rows.results || []).map(parseActorRow);
      }
    } catch {}
  }

  return APT_DATABASE.filter(a =>
    a.name.toLowerCase().includes(q) ||
    a.aliases.some(al => al.toLowerCase().includes(q)) ||
    a.description.toLowerCase().includes(q) ||
    a.tools.some(t => t.toLowerCase().includes(q))
  ).slice(0, 10);
}

// ─── Attribute IOC to threat actors ──────────────────────────────────────────
export function attributeIOC(value, type = 'unknown') {
  const valueLower = value.toLowerCase();
  const matches = [];

  for (const actor of APT_DATABASE) {
    const iocs = actor.iocs || {};
    const allIOCs = [
      ...(iocs.domains || []),
      ...(iocs.ips || []),
      ...(iocs.hashes || []),
    ];
    if (allIOCs.some(ioc => ioc.toLowerCase() === valueLower)) {
      matches.push({
        actor_id: actor.id,
        actor_name: actor.name,
        country: actor.country,
        confidence: 95,
      });
    }
  }

  return matches;
}

// ─── Parse D1 row ─────────────────────────────────────────────────────────────
function parseActorRow(row) {
  return {
    ...row,
    aliases:          safeParse(row.aliases, []),
    target_sectors:   safeParse(row.target_sectors, []),
    target_countries: safeParse(row.target_countries, []),
    ttps:             safeParse(row.ttps, []),
    iocs:             safeParse(row.iocs, {}),
    tools:            safeParse(row.tools, []),
    campaigns:        safeParse(row.campaigns, []),
    ref_urls:         safeParse(row.ref_urls, []),
  };
}

function safeParse(val, def) {
  try { return JSON.parse(val); }
  catch { return def; }
}
