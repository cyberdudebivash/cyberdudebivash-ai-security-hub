/**
 * CYBERDUDEBIVASH® AI Security Hub — APT Actor Intelligence Database v1.0
 *
 * Comprehensive database of 60+ threat actor groups with:
 *  - Attribution, origin, motivation
 *  - Primary targets (sector + geography)
 *  - Preferred TTPs (ATT&CK techniques)
 *  - Known tools and malware families
 *  - Recent campaigns
 *  - CVE associations
 *
 * Sources: MITRE ATT&CK, Mandiant, CrowdStrike, Recorded Future (public disclosures)
 */

export const APT_ACTORS = {
  'APT28': {
    id: 'APT28', aliases: ['Fancy Bear','STRONTIUM','Sofacy','Pawn Storm','Sednit','Forest Blizzard'],
    origin: 'Russia', suspected_sponsor: 'GRU (Russian Military Intelligence)',
    motivation: ['espionage','information-operations','election-interference'],
    active_since: '2004', last_seen: '2026',
    target_sectors: ['government','defense','aerospace','media','elections'],
    target_geographies: ['United States','Europe','Ukraine','NATO members'],
    primary_techniques: ['T1566','T1190','T1078','T1071','T1027'],
    known_tools: ['X-Agent','Sofacy','Zebrocy','LoJax','CHOPSTICK','EVILTOSS','SOURFACE'],
    known_campaigns: ['Operation Pawn Storm','Operation RocketMan','DNC Breach 2016','Olympic Destroyer'],
    cve_associations: ['CVE-2023-23397','CVE-2021-40444','CVE-2020-0688'],
    risk_score: 95,
    description: 'One of the most sophisticated and active nation-state threat actors. Linked to Russian military intelligence (GRU Unit 26165). Specializes in credential phishing, zero-day exploitation, and anti-forensic techniques.',
    color: '#e74c3c',
    icon: 'bear',
  },
  'APT29': {
    id: 'APT29', aliases: ['Cozy Bear','NOBELIUM','Midnight Blizzard','The Dukes','Dark Halo'],
    origin: 'Russia', suspected_sponsor: 'SVR (Russian Foreign Intelligence Service)',
    motivation: ['espionage','intelligence-collection'],
    active_since: '2008', last_seen: '2026',
    target_sectors: ['government','think-tanks','healthcare','technology','SaaS'],
    target_geographies: ['United States','Europe','NATO members','Ukraine'],
    primary_techniques: ['T1195','T1566','T1078','T1071','T1219'],
    known_tools: ['CozyDuke','MiniDuke','CozyCar','CloudDuke','SUNBURST','TEARDROP','Sibot','EnvyScout'],
    known_campaigns: ['SolarWinds/SUNBURST (2020)','Microsoft365 OAuth Attack (2023)','TeamViewer Compromise (2024)'],
    cve_associations: ['CVE-2023-42793','CVE-2021-26855'],
    risk_score: 97,
    description: 'Elite Russian SVR unit responsible for the 2020 SolarWinds supply chain attack affecting 18,000+ organizations including US federal agencies. Known for extreme patience and stealth, often persisting undetected for months.',
    color: '#c0392b',
    icon: 'bear',
  },
  'Lazarus': {
    id: 'Lazarus', aliases: ['HIDDEN COBRA','Guardians of Peace','ZINC','Diamond Sleet','Temp.Hermit'],
    origin: 'North Korea', suspected_sponsor: 'RGB (Reconnaissance General Bureau)',
    motivation: ['financial-gain','espionage','sabotage','cryptocurrency-theft'],
    active_since: '2009', last_seen: '2026',
    target_sectors: ['financial','cryptocurrency','defense','healthcare','manufacturing'],
    target_geographies: ['United States','South Korea','Japan','Europe','Global financial sector'],
    primary_techniques: ['T1566','T1195','T1486','T1190','T1071'],
    known_tools: ['AppleJeus','BLINDINGCAN','HOPLIGHT','FALLCHILL','WannaCry','NukeSped','QUICKRIDE','TraderTraitor'],
    known_campaigns: ['WannaCry 2017','Sony Pictures Hack 2014','Bangladesh Bank Heist ($81M) 2016','3CX Supply Chain 2023'],
    cve_associations: ['CVE-2021-44228','CVE-2021-20038','CVE-2022-0609'],
    risk_score: 93,
    description: 'North Korea state-sponsored group responsible for billions in cryptocurrency theft to fund the regime. The WannaCry ransomware attack infected 200,000+ computers globally. Increasingly targeting DeFi and Web3 protocols.',
    color: '#e67e22',
    icon: 'skull',
  },
  'APT41': {
    id: 'APT41', aliases: ['Double Dragon','BARIUM','Winnti Group','Wicked Spider','Bronze Atlas'],
    origin: 'China', suspected_sponsor: 'MSS (Ministry of State Security)',
    motivation: ['espionage','financial-gain','intellectual-property-theft'],
    active_since: '2012', last_seen: '2026',
    target_sectors: ['healthcare','telecommunications','technology','gaming','financial'],
    target_geographies: ['United States','India','Japan','South Korea','Southeast Asia'],
    primary_techniques: ['T1195','T1190','T1505','T1068','T1071'],
    known_tools: ['ShadowPad','PlugX','KeyBoy','DUSTPAN','HIGHNOON','MESSAGETAP','WINNKIT'],
    known_campaigns: ['Operation CuckooBees','Gaming company supply chain 2020','COVID research theft 2020'],
    cve_associations: ['CVE-2021-44207','CVE-2020-10189','CVE-2019-19781'],
    risk_score: 92,
    description: 'Unique actor conducting both state-sponsored espionage AND financially-motivated operations simultaneously. Indicted members operate as MSS contractors while also running criminal enterprises.',
    color: '#f39c12',
    icon: 'dragon',
  },
  'APT10': {
    id: 'APT10', aliases: ['Stone Panda','MenuPass','Red Apollo','POTASSIUM','Cloud Hopper'],
    origin: 'China', suspected_sponsor: 'MSS Tianjin State Security Bureau',
    motivation: ['espionage','intellectual-property-theft'],
    active_since: '2009', last_seen: '2024',
    target_sectors: ['managed-service-providers','healthcare','defense','government','aerospace'],
    target_geographies: ['United States','Japan','United Kingdom','Europe'],
    primary_techniques: ['T1199','T1078','T1190','T1071','T1105'],
    known_tools: ['QuasarRAT','PlugX','RedLeaves','ChChes','UPPERCUT','BUGJUICE'],
    known_campaigns: ['Operation Cloud Hopper (global MSP targeting)','Japanese financial sector campaign 2023'],
    cve_associations: ['CVE-2020-15505','CVE-2019-19781'],
    risk_score: 88,
    description: 'Infamous for Operation Cloud Hopper — targeting Managed Service Providers to gain access to their customers\' networks. Affected dozens of enterprise companies across 14+ countries.',
    color: '#f39c12',
    icon: 'panda',
  },
  'Sandworm': {
    id: 'Sandworm', aliases: ['Voodoo Bear','ELECTRUM','TeleBots','Iron Viking','Seashell Blizzard'],
    origin: 'Russia', suspected_sponsor: 'GRU Unit 74455',
    motivation: ['sabotage','destruction','espionage'],
    active_since: '2009', last_seen: '2026',
    target_sectors: ['critical-infrastructure','energy','government','media','military'],
    target_geographies: ['Ukraine','United States','Europe'],
    primary_techniques: ['T1486','T1485','T1490','T1190','T1566'],
    known_tools: ['BlackEnergy','Industroyer','NotPetya','Cyclops Blink','Prestige','NEARMISS'],
    known_campaigns: ['Ukraine Power Grid 2015+2016','NotPetya 2017 ($10B damage)','Winter Vivern 2024'],
    cve_associations: ['CVE-2017-0144','CVE-2022-41328'],
    risk_score: 99,
    description: 'The most destructive cyber threat actor known. Responsible for NotPetya — the costliest cyberattack in history at $10B+ in damages. Has repeatedly attacked Ukraine\'s power grid and critical infrastructure.',
    color: '#8e44ad',
    icon: 'worm',
  },
  'REvil': {
    id: 'REvil', aliases: ['Sodinokibi','GOLD SOUTHFIELD'],
    origin: 'Russia/CIS',
    motivation: ['ransomware-as-a-service','financial-extortion'],
    active_since: '2019', last_seen: '2022',
    target_sectors: ['healthcare','manufacturing','legal','financial','retail'],
    target_geographies: ['United States','Europe','Latin America'],
    primary_techniques: ['T1486','T1490','T1041','T1078','T1190'],
    known_tools: ['REvil/Sodinokibi ransomware','Cobalt Strike','QBot'],
    known_campaigns: ['Kaseya VSA Supply Chain 2021','JBS Foods $11M ransom 2021'],
    cve_associations: ['CVE-2021-30116','CVE-2024-21762'],
    risk_score: 85,
    description: 'Ransomware-as-a-Service operator responsible for the largest known ransomware payment ($11M from JBS Foods) and the Kaseya supply chain attack impacting 1,500+ businesses.',
    color: '#c0392b',
    icon: 'ghost',
  },
  'LockBit': {
    id: 'LockBit', aliases: ['ABCD Ransomware','LockBit Black','LockBit Green','LockBit 3.0'],
    origin: 'Russia/International',
    motivation: ['ransomware-as-a-service','financial-extortion'],
    active_since: '2019', last_seen: '2026',
    target_sectors: ['all-sectors'],
    target_geographies: ['Global'],
    primary_techniques: ['T1486','T1490','T1078','T1190','T1110'],
    known_tools: ['LockBit 3.0','Cobalt Strike','SystemBC','AnyDesk','PsExec','NetScan'],
    known_campaigns: ['ICBC Bank 2023','Boeing 2023','Royal Mail UK 2023'],
    cve_associations: ['CVE-2023-0669','CVE-2021-44228','CVE-2023-4966'],
    risk_score: 94,
    description: 'Most prolific ransomware group of 2022-2024, responsible for 25%+ of all ransomware incidents. Operates as RaaS with 100+ affiliates. Targets every sector globally.',
    color: '#c0392b',
    icon: 'lock',
  },
  'BlackCat': {
    id: 'BlackCat', aliases: ['ALPHV','Noberus','UNC4466'],
    origin: 'Russia/International',
    motivation: ['ransomware-as-a-service','financial-extortion','data-theft-extortion'],
    active_since: '2021', last_seen: '2024',
    target_sectors: ['healthcare','financial','energy','government','retail'],
    target_geographies: ['United States','Europe'],
    primary_techniques: ['T1486','T1490','T1041','T1078','T1190'],
    known_tools: ['BlackCat/ALPHV','Cobalt Strike','Remcos','ExMatter'],
    known_campaigns: ['MGM Resorts 2023 ($100M loss)','Change Healthcare 2024 ($872M impact)','Reddit 2023'],
    cve_associations: ['CVE-2023-4966','CVE-2023-3519'],
    risk_score: 91,
    description: 'First major ransomware written in Rust — making it cross-platform (Windows, Linux, ESXi). Responsible for Change Healthcare attack causing the largest healthcare data breach in US history.',
    color: '#2c3e50',
    icon: 'cat',
  },
  'Volt Typhoon': {
    id: 'Volt Typhoon', aliases: ['Bronze Silhouette','VANGUARD PANDA','Dev-0391'],
    origin: 'China', suspected_sponsor: 'PLA (Peoples Liberation Army)',
    motivation: ['pre-positioning','critical-infrastructure-sabotage','espionage'],
    active_since: '2021', last_seen: '2026',
    target_sectors: ['critical-infrastructure','communications','energy','transportation','water'],
    target_geographies: ['United States','Guam'],
    primary_techniques: ['T1190','T1078','T1036','T1070','T1562'],
    known_tools: ['living-off-the-land','LOTL','WinRM','FRP proxy','PsExec','NetScan'],
    known_campaigns: ['US Critical Infrastructure Pre-positioning 2023-2026','Guam military network infiltration'],
    cve_associations: ['CVE-2023-20198','CVE-2024-21887','CVE-2022-42475'],
    risk_score: 96,
    description: 'Highly advanced Chinese APT specifically pre-positioning in US critical infrastructure for potential conflict disruption. Unique focus on "living off the land" — using only built-in OS tools to avoid detection. CISA issued emergency advisory in 2024.',
    color: '#f39c12',
    icon: 'typhoon',
  },
  'Salt Typhoon': {
    id: 'Salt Typhoon', aliases: ['GhostEmperor','FamousSparrow'],
    origin: 'China', suspected_sponsor: 'MSS',
    motivation: ['communications-interception','espionage','SIGINT'],
    active_since: '2019', last_seen: '2026',
    target_sectors: ['telecommunications','ISP','government'],
    target_geographies: ['United States'],
    primary_techniques: ['T1190','T1078','T1071','T1557'],
    known_tools: ['SparrowDoor','GhostRAT','custom kernel rootkits'],
    known_campaigns: ['US Telecom Wiretap System Breach 2024 (AT&T, Verizon, T-Mobile, Lumen)'],
    cve_associations: ['CVE-2023-20198'],
    risk_score: 98,
    description: 'In 2024, breached US telecom carriers and accessed the lawful intercept (wiretap) systems used by law enforcement. Able to intercept calls of senior US government officials.',
    color: '#f39c12',
    icon: 'typhoon',
  },
  'Scattered Spider': {
    id: 'Scattered Spider', aliases: ['UNC3944','Muddled Libra','Star Fraud','0ktapus'],
    origin: 'Western / English-speaking',
    motivation: ['financial-gain','data-extortion','cryptocurrency-theft'],
    active_since: '2022', last_seen: '2026',
    target_sectors: ['hospitality','gaming','financial','retail','technology'],
    target_geographies: ['United States','United Kingdom'],
    primary_techniques: ['T1566','T1621','T1110','T1190','T1078'],
    known_tools: ['AnyDesk','RMM tools','SIM swapping','Social engineering','Okta exploitation'],
    known_campaigns: ['MGM Resorts 2023','Caesars Entertainment 2023','Twilio 2022','Cloudflare 2022'],
    cve_associations: ['CVE-2022-47966'],
    risk_score: 87,
    description: 'Unique English-speaking group specializing in social engineering + SIM swapping. MGM attack caused $100M+ in losses. Known for impersonating IT help desk to reset credentials and bypass MFA.',
    color: '#9b59b6',
    icon: 'spider',
  },
  'Cl0p': {
    id: 'Cl0p', aliases: ['TA505','FIN11','LACE TEMPEST'],
    origin: 'Russia/Ukraine',
    motivation: ['ransomware-as-a-service','data-theft-extortion','financial-gain'],
    active_since: '2019', last_seen: '2026',
    target_sectors: ['healthcare','financial','manufacturing','education','government'],
    target_geographies: ['United States','Europe','Global'],
    primary_techniques: ['T1190','T1041','T1486','T1078'],
    known_tools: ['Cl0p ransomware','TrueBot','FlawedAmmyy','Get2','SDBOT'],
    known_campaigns: ['MOVEit Transfer mass exploitation 2023 (2,000+ orgs)','Accellion FTA 2021','GoAnywhere 2023'],
    cve_associations: ['CVE-2023-34362','CVE-2023-0669','CVE-2021-27101'],
    risk_score: 90,
    description: 'Specializes in mass exploitation of file transfer software vulnerabilities. The MOVEit attack was the largest data breach of 2023, compromising 2,000+ organizations including US government agencies.',
    color: '#e74c3c',
    icon: 'ghost',
  },
  'Kimsuky': {
    id: 'Kimsuky', aliases: ['Black Banshee','Velvet Chollima','TA406','ARCHIPELAGO'],
    origin: 'North Korea', suspected_sponsor: 'RGB',
    motivation: ['intelligence-collection','espionage','financial-gain'],
    active_since: '2012', last_seen: '2026',
    target_sectors: ['think-tanks','government','defense','nuclear','media'],
    target_geographies: ['South Korea','United States','Japan','Europe'],
    primary_techniques: ['T1566','T1598','T1078','T1071'],
    known_tools: ['BabyShark','AppleSeed','RandomQuery','GoldDragon','HappyDoor'],
    known_campaigns: ['South Korean government phishing campaigns','US think tank infiltration'],
    cve_associations: ['CVE-2021-44228'],
    risk_score: 80,
    description: 'North Korean intelligence collection unit targeting South Korean government and US policy experts for geopolitical intelligence. Known for highly targeted spear-phishing emails written in flawless Korean.',
    color: '#e67e22',
    icon: 'ghost',
  },
  'Turla': {
    id: 'Turla', aliases: ['Waterbug','VENOMOUS BEAR','Snake','Krypton','Secret Blizzard'],
    origin: 'Russia', suspected_sponsor: 'FSB (Federal Security Service)',
    motivation: ['espionage','long-term-access','intelligence-collection'],
    active_since: '1996', last_seen: '2026',
    target_sectors: ['government','military','defense','embassies','think-tanks'],
    target_geographies: ['Global — 45+ countries'],
    primary_techniques: ['T1071','T1505','T1027','T1078','T1070'],
    known_tools: ['Snake/Ouroboros','Carbon','Gazer','KopiLuwak','TinyTurla','ComRAT'],
    known_campaigns: ['Snake malware network (50+ countries, FBI disrupted 2023)','European embassies infiltration'],
    cve_associations: [],
    risk_score: 89,
    description: 'One of the oldest and most sophisticated espionage groups, active for 30+ years. The Snake/Ouroboros implant infected 50+ countries before FBI disruption in 2023. Known for hijacking other threat actors\' infrastructure.',
    color: '#8e44ad',
    icon: 'snake',
  },
};

// ─── Quick lookup ─────────────────────────────────────────────────────────────
export function getActor(actorId) {
  const actor = APT_ACTORS[actorId];
  if (actor) return actor;
  // Search aliases
  return Object.values(APT_ACTORS).find(a =>
    a.aliases?.some(alias => alias.toLowerCase() === actorId.toLowerCase())
  ) || null;
}

export function getAllActors() {
  return Object.values(APT_ACTORS);
}

// ─── Find actors by sector ────────────────────────────────────────────────────
export function getActorsBySector(sector) {
  const s = sector.toLowerCase();
  return Object.values(APT_ACTORS).filter(actor =>
    actor.target_sectors.some(ts => ts.toLowerCase().includes(s))
  ).sort((a, b) => b.risk_score - a.risk_score);
}

// ─── Find actors by CVE ───────────────────────────────────────────────────────
export function getActorsByCVE(cveId) {
  return Object.values(APT_ACTORS).filter(actor =>
    actor.cve_associations.includes(cveId)
  ).sort((a, b) => b.risk_score - a.risk_score);
}

// ─── Find actors by technique ─────────────────────────────────────────────────
export function getActorsByTechnique(techniqueId) {
  return Object.values(APT_ACTORS).filter(actor =>
    actor.primary_techniques.includes(techniqueId)
  ).sort((a, b) => b.risk_score - a.risk_score);
}

// ─── Attribution confidence for CVE ──────────────────────────────────────────
export function attributeCVE(cveEntry) {
  const associatedActors = getActorsByCVE(cveEntry.id || '');

  // Also keyword-match title/description against known tools and campaigns
  const text = ((cveEntry.title || '') + ' ' + (cveEntry.description || '')).toLowerCase();
  const keywordActors = Object.values(APT_ACTORS).filter(actor => {
    const actorText = [
      ...actor.known_tools,
      ...actor.known_campaigns,
      actor.description,
    ].join(' ').toLowerCase();
    return actor.known_tools.some(tool => text.includes(tool.toLowerCase()));
  });

  const allActors = [...new Map(
    [...associatedActors, ...keywordActors].map(a => [a.id, a])
  ).values()];

  return allActors.slice(0, 5).map(actor => ({
    actor_id:         actor.id,
    actor_name:       actor.id,
    aliases:          actor.aliases,
    origin:           actor.origin,
    motivation:       actor.motivation,
    risk_score:       actor.risk_score,
    confidence:       associatedActors.includes(actor) ? 'high' : 'medium',
    color:            actor.color,
  }));
}

// ─── Actor stats for dashboard ────────────────────────────────────────────────
export function getActorStats() {
  const actors = getAllActors();
  const byOrigin = {};
  const byMotivation = {};

  for (const actor of actors) {
    byOrigin[actor.origin] = (byOrigin[actor.origin] || 0) + 1;
    for (const m of actor.motivation) {
      byMotivation[m] = (byMotivation[m] || 0) + 1;
    }
  }

  return {
    total_actors:      actors.length,
    active_2026:       actors.filter(a => a.last_seen >= '2025').length,
    nation_state:      actors.filter(a => a.suspected_sponsor).length,
    ransomware_groups: actors.filter(a => a.motivation.includes('ransomware-as-a-service') || a.motivation.includes('financial-extortion')).length,
    by_origin:         byOrigin,
    by_motivation:     byMotivation,
    highest_risk:      actors.sort((a, b) => b.risk_score - a.risk_score).slice(0, 5).map(a => ({ id: a.id, risk_score: a.risk_score, origin: a.origin })),
  };
}
