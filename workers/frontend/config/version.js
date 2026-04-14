/**
 * ═══════════════════════════════════════════════════════════
 * CYBERDUDEBIVASH AI Security Hub — Version Config v21.0
 * SINGLE SOURCE OF TRUTH for all frontend version references
 * Import this file or reference window.CDB_VERSION globally
 * ═══════════════════════════════════════════════════════════
 */
export const PLATFORM_VERSION     = "21.0.0";
export const PLATFORM_VERSION_SHORT = "21.0";
export const PLATFORM_NAME        = "CYBERDUDEBIVASH AI Security Hub";
export const BUILD_DATE           = "2026-04-15";
export const ENGINES = {
  sentinel_apex:      "5.0",
  adaptive_brain:     "21.0",
  mythos:             "3.0",
  revenue_autopilot:  "2.0",
  mcp_control:        "21.0",
  threat_fusion:      "2.0",
  zero_trust:         "2.0",
};

// Expose globally for non-module scripts
if (typeof window !== 'undefined') {
  window.CDB_VERSION = PLATFORM_VERSION;
  window.CDB_VERSION_SHORT = PLATFORM_VERSION_SHORT;

  // Patch all version elements on DOM ready
  function patchVersionElements(v) {
    const IDS = [
      'platform-version-badge',
      'platform-version-footer',
      'soc-version',
      'ai-engine-version',
    ];
    IDS.forEach(id => {
      const el = document.getElementById(id);
      if (el) el.textContent = `v${PLATFORM_VERSION_SHORT}`;
    });
    // Patch any element with data-version-target attribute
    document.querySelectorAll('[data-version-target]').forEach(el => {
      el.textContent = `v${PLATFORM_VERSION_SHORT}`;
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => patchVersionElements(PLATFORM_VERSION_SHORT));
  } else {
    patchVersionElements(PLATFORM_VERSION_SHORT);
  }
}
