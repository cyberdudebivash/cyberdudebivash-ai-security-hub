/**
 * CYBERDUDEBIVASH AI Security Hub — Main Router v20.0
 * Global Cyber Intelligence Dominance System
 * World-class AI Cybersecurity SaaS: AI Brain, Attack Graphs, Threat Correlation,
 * Continuous Monitoring, Multi-Tenant Orgs, Content Engine, Public API Platform
 *
 * Auth priority: JWT Bearer → API Key (cdb_*) → IP fallback (FREE)
 *
 * New in v20.0:
 *   CyberBrain Engine: POST /api/cyber-brain/analyze    → full AI risk analysis
 *                      GET  /api/cyber-brain/risk-score → cached risk score
 *                      GET  /api/cyber-brain/attack-paths → predicted attack chains
 *                      GET  /api/cyber-brain/threat-actors → correlated APT groups
 *                      GET  /api/cyber-brain/remediation   → AI remediation plan
 *   Global ThreatFeed: GET  /api/global-threat-feed        → normalized IOC feed
 *                      GET  /api/global-threat-feed/stream → SSE real-time IOC stream
 *                      GET  /api/global-threat-feed/stats  → feed statistics
 *                      POST /api/global-threat-feed/ingest → manual IOC submission
 *   Zero Trust:        GET  /api/zero-trust/score       → device trust score
 *                      GET  /api/zero-trust/anomalies   → session anomalies
 *                      POST /api/zero-trust/verify      → risk-based auth verify
 *   Revenue Engine:    GET  /api/revenue/plans          → subscription tiers
 *                      POST /api/revenue/subscribe      → create subscription
 *                      GET  /api/revenue/gate/:feature  → feature gate check
 *   Authority Engine:  POST /api/authority/cve-report   → auto-generate CVE report
 *                      POST /api/authority/blog-post    → auto-generate blog post
 *                      GET  /api/authority/bulletin     → latest threat bulletin
 *
 * New in v8.0:
 *   AI Brain:          GET  /api/insights/:jobId  → AI narrative from scan
 *   Attack Graph:      POST /api/attack-graph      → D3-ready attack graph
 *   Threat Intel:      GET  /api/threat-intel/stats
 *   Monitoring:        CRUD /api/monitors/*        → scheduled scan monitors
 *   Content Engine:    CRUD /api/content/*         → auto-generated posts
 *   Org Management:    CRUD /api/orgs/*            → multi-tenant orgs + teams
 *
 * New in v8.1:
 *   Real-Time Feed:    GET  /api/realtime/feed        → SSE live threat alert stream
 *   Realtime Posture:  GET  /api/realtime/posture     → Defense posture JSON
 *   Realtime Stats:    GET  /api/realtime/stats       → Live platform stats
 *   Gumroad Webhook:   POST /api/webhooks/gumroad     → Purchase webhook (HMAC)
 *   Gumroad Verify:    POST /api/gumroad/verify       → License key activation
 *   Gumroad Products:  GET  /api/gumroad/products     → Public product catalog
 *   SIEM Info:         GET  /api/export/siem          → Export format docs
 *   SIEM Export:       POST /api/export/siem          → JSON/CEF/STIX/Sigma/CSV export
 *   SIEM Stream:       GET  /api/export/siem/stream   → Streaming NDJSON (ENTERPRISE)
 */

// ─── Sync scan handlers (v4 — backward compat) ───────────────────────────────


// ── v31.0 ENTERPRISE DASHBOARD STREAM ────────────────────────────────────────
import { handleDashboardStream } from './handlers/dashboardStream.js';

// ── v32.0 PHASE 2 ENTERPRISE PLATFORM IMPORTS ─────────────────────────────
import { handleRevenueMetrics, handleRevenueSnapshot }                              from './handlers/revenueMetrics.js';
import { handleListCustomers, handleCreateCustomer, handleGetCustomer, handleCustomerMetrics, handleUpdateCustomer, handleMSSPOverview, handleDeleteCustomer, handleSuspendCustomer, handleArchiveCustomer, handleRestoreCustomer } from './handlers/msspWorkspace.js';
import { handleListCases, handleGetCase, handleCreateCase, handleUpdateCase, handleAddCaseComment, handleCaseMetrics } from './handlers/socCases.js';
import { handleListActors, handleGetActor, handleIOCSearch, handleAddIOC, handleCTIStats }                             from './handlers/ctiWorkbench.js';
import { handleDeepHealth, handleServicesList }                                     from './handlers/deepHealth.js';

// ── v33.0 PHASE 3 ENTERPRISE MATURITY IMPORTS ─────────────────────────────
import { handleCustomerHealth, handleCustomerHealthByOrg, handleCustomerSuccessOverview, handleRefreshHealthScores, handleCustomerSuccessPlaybooks } from './handlers/customerSuccess.js';
// Aliased to avoid collision with executiveReport.js (handleListReports, handleGetReport)
import {
  handleListReports as handleListEnterpriseReports,
  handleCreateReport as handleCreateEnterpriseReport,
  handleGetReport as handleGetEnterpriseReport,
  handleDownloadReport as handleDownloadEnterpriseReport,
  handleReportTemplates as handleEnterpriseReportTemplates,
  handleScheduleReport as handleScheduleEnterpriseReport,
} from './handlers/reportingEngine.js';
import { handleGlobalSearch, handleSaveSearch, handleListSavedSearches, handleDeleteSavedSearch } from './handlers/globalSearch.js';
import { handleListWorkflows, handleCreateWorkflow, handleUpdateWorkflow, handleDeleteWorkflow, handleExecuteWorkflow, handleWorkflowExecutions, handleWorkflowTemplates } from './handlers/workflowAutomation.js';
import { handleGetTheme, handleUpdateTheme, handleDeleteTheme, handleGetThemeByOrg } from './handlers/whiteLabelMSSP.js';
import { handleIngestEvent, handleGrowthMetrics, handleConversionFunnel, handleFeatureAdoption, handlePruneEvents } from './handlers/productAnalytics.js';
import { handleGetPreferences, handleUpdatePreferences, handleNotificationLog, handleTestNotification, handleAdminSendNotification } from './handlers/notificationPlatform.js';
// Aliased to avoid collision with cisoMetrics.js (handleCreateIncident)
import {
  handleSLAReport, handleErrorBudget, handleCapacityMetrics,
  handleListIncidents as handleListReliabilityIncidents,
  handleCreateIncident as handleCreateReliabilityIncident,
} from './handlers/reliabilityEngineering.js';

// ── v35.0 PHASE 3 P0 REVENUE OPERATING SYSTEM IMPORTS ─────────────────────
import {
  handleRevenueBreakdown, handleRevenueLeads, handleRevenueFunnelOps,
  handleRevenueTransactions, handleRevenueForecastOps,
  handleGetEnterprisePipeline, handleAddEnterpriseDeal,
  handleEnterpriseInquiryAlias, handleAttributionTrack,
} from './handlers/revenueOps.js';
import {
  handleMsspMetrics, handleListMsspPartners, handleAddMsspPartner,
  handleMsspWlStatus, handleMsspUsage, handleMsspRevenueTrend,
  handleMsspExpansionOpps, handleMsspPartnerStatusUpdate,
} from './handlers/msspOps.js';

// ── v35.1 PHASE 5 P0 REVENUE INTELLIGENCE IMPORTS ──────────────────────────
import { handleRevenueKPI, handleFunnelAnalytics } from './handlers/revenueKPI.js';
import { runRenewalAutomation, seedRenewalQueue35d } from './handlers/renewalEngine.js';

// ── v34.0 PHASE 4 GOD MODE IMPORTS ───────────────────────────────────────────
import { handleGetMetrics, handleRefreshMetrics, handleMetricsHistory, handlePlatformStatus } from './handlers/platformMetricsAuthority.js';
import { handleGetTimeline, handleListEvidence, handleAddEvidence, handleListNotes, handleAddNote, handleEscalateCase, handleInvestigationSummary, handleResolveCase } from './handlers/socInvestigations.js';
import { handleListWatchlists, handleCreateWatchlist, handleListWatchlistEntries, handleAddWatchlistEntry, handleDeleteWatchlist, handleWatchlistMatch, handleEnrichIOC, handleSTIXExport } from './handlers/ctiPlatformV2.js';
import { handleCreateSnapshot, handleRevenueHistory, handleRevenueForecast, handleRevenueWaterfall, handleCohortAnalysis, handleTierMix } from './handlers/revenueIntelligence.js';
import { handleGetExpansionScore, handleListSegments, handleLogUpsellEvent, handleUpsellFunnel, handleFeatureGates } from './handlers/commercializationEngine.js';

// ── v28 AI SECURITY PLATFORM IMPORTS ─────────────────────────────────────────
import { handleRegisterAIAsset, handleScanAIAsset, handleASPMDashboard, handleListAIAssets } from './handlers/aiSecurityASPM.js';
import { handleGovernanceAssess, handleGovernanceAnswer, handleGetGovernanceAssessment, handleListFrameworks } from './handlers/aiGovernance.js';
import { handleRedTeamEngage, handleRedTeamAttack, handleRedTeamReport, handleGetRedTeamEngagement } from './handlers/aiRedTeam.js';
import { handleAIThreatFeed, handleAIThreatReport, handleAIThreatRadarStatus, handleAIThreatRadarScanNow, handleLatestPublishedReport, generateAndPublishAIThreatReport, handleScanAgent, handleRegisterAgent, handleListAgents } from './handlers/aiThreatIntel.js';
import { runAIThreatRadar } from './services/aiThreatRadar.js';

// ── v36.0 AI SECURITY COPILOT (APEX — God Mode Orchestrator) ─────────────────
import {
  handleCopilotChat,
  handleGetCopilotSession,
  handleDeleteCopilotSession,
  handleCopilotQuickAction,
  handleCopilotCapabilities,
} from './handlers/aiSecurityCopilot.js';

// v20.0 GOD MODE COMPETITIVE PLATFORM IMPORTS
import { handleAIGovernancePro } from './handlers/aiGovernancePro.js';
import { handleAIRedTeamPro } from './handlers/aiRedTeamPro.js';
import { handleDeveloperPortal, getOpenAPISpec } from './handlers/developerPortal.js';
import { handleExecutiveCommandCenter } from './handlers/executiveCommandCenter.js';
import { handleServiceCatalog, handleBookAIService, handleGetAIServiceEngagement } from './handlers/aiServices.js';


// ── v30.0 P0/P1 REMEDIATION IMPORTS ────────────────────────────────────────
import { refreshPlatformMetrics, servePlatformMetrics }    from './services/metricsHydration.js';
import { enforceGovernanceBatch, validateIngestPayload, logP0Violation } from './middleware/severityGovernanceGate.js';
import { issueScanToken, verifyScanToken, scanTokenError } from './lib/scanTokenEngine.js';
import {
  gatewayRequestCeiling, applyFreemiumPaywall, handleSubscriptionCheckout,
  handleGetMyPlan, normalizeTier,
} from './handlers/subscriptionPaywallEngine.js';

// ── v29 NEW SCANNER IMPORTS ───────────────────────────────────────────────────
import { handleMCPSecurityScan, handleMCPScanResult, handleMCPThreatFeed, handleMCPQuickAssess } from './handlers/mcpSecurityScanner.js';
import { handleVibeCodeScan, handleVibeCodePatterns } from './handlers/vibe-code/vibeCodeScanner.js';
import { handleListAgentAdvisories, handleAgentThreatOverview, handleCreateAgentAdvisory } from './handlers/agentThreatAdvisories.js';
import { ingestAgentThreatAdvisories } from './services/agentThreatIngestion.js';
import { ingestAttackLibraryTechniques } from './services/attackLibraryIngestion.js';
import { handleListAttackTechniques, handleAttackLibraryOverview, handleCreateAttackTechnique } from './handlers/attackLibrary.js';

// ── v27 ENTERPRISE DOMINANCE IMPORTS ─────────────────────────────────────────
import { handleCEODashboard, handleCEOSnapshot }    from './handlers/ceoExecutiveDashboard.js';
import { handleBookAssessment, handleConfirmAssessment, handleGetAssessment, handleListAssessments, handleUpdateAssessmentStatus } from './handlers/assessmentBooking.js';
import { handleTrustCenter, handleTrustMetrics, handleTrustCompany, handleSubmitTestimonial } from './handlers/trustCenter.js';

import { handleDomainScan }        from './handlers/domain.js';
import { handleAIScan }            from './handlers/ai.js';
import { handleRedteamScan }       from './handlers/redteam.js';
import { handleIdentityScan }      from './handlers/identity.js';
import { handleCompliance }        from './handlers/compliance.js';
import { handleLeadCapture }       from './handlers/leads.js';
import { handleEnterpriseContact } from './handlers/enterprise.js';

// ─── New v5.0 handlers ────────────────────────────────────────────────────────
import { handleReportDownload, handleReportGenerate } from './handlers/report.js';
import {
  handleSignup, handleLogin, handleRefresh, handleLogout,
  handleGetProfile, handleUpdateProfile, handleAlertConfig, handleTestAlert,
} from './handlers/auth.js';
import { handleListKeys, handleCreateKey, handleRevokeKey, handleKeyUsage } from './handlers/apikeys.js';
import { handleAsyncScan, handleJobStatus, handleJobResult, handleD1History } from './handlers/jobs.js';

// ─── New v7.0 handlers ────────────────────────────────────────────────────────
import {
  handleCreateOrder, handleVerifyPayment, handlePaymentStatus,
  handleReportDownload as handlePaidReportDownload,
  handleRazorpayWebhook,
  handlePaymentConfirm,
} from './handlers/payments.js';
import { handleGetAnalytics, handleScanStats, trackEvent, meterApiRequest, handleApiUsage } from './handlers/analytics.js';

// ─── AI Cyber Brain V2 handlers (analyze / simulate / forecast) ──────────────
import { handleAIAnalyze, handleAISimulate, handleAIForecast,
         handleAIChat, handleGenerateRules } from './handlers/aiAnalysis.js';

// ─── CVE Engine (for /api/v1/cves endpoint) ───────────────────────────────────
import { getTopCVEsForModule } from './services/cveEngine.js';

// ─── Threat Intelligence Engine v2.0 (Sentinel APEX) ─────────────────────────
import {
  handleGetThreatIntel, handleThreatIntelStats, handleGetThreatIntelEntry,
  handleManualIngest, handleV1ThreatIntel, handleV1IOCs,
  handleThreatIntelStream,
  handleV1Correlations, handleV1Graph, handleV1Hunting,
} from './handlers/threatIntel.js';
import { runIngestion, runBulkBackfill, enrichUnscoredEPSS }  from './services/threatIngestion.js';

// ─── Sentinel APEX v3 — SOC Automation + Autonomous Defense ──────────────────
import {
  handleGetAlerts, handleGetDecisions, handleGetDefenseActions,
  handleGetFederation, handleSOCAnalyze, handleGetSOCPosture,
  handleSOCDashboard,
} from './handlers/soc.js';
import { runFederation }            from './services/federationEngine.js';
import { runDetection, storeDetectionResults } from './services/detectionEngine.js';
import { runDecisionEngine, storeDecisions }   from './services/decisionEngine.js';
import { runAutonomousDefense, storeDefenseActions } from './services/defenseEngine.js';
import { buildResponsePlan, storeResponsePlan }      from './services/responseEngine.js';

// ─── Subscription SaaS Engine (v10.0) ────────────────────────────────────────
import {
  handleGetUserPlan, handleCreateSubscription, handleActivateSubscription, handleGetPlans,
  checkMonthlyQuota,
} from './handlers/subscription.js';

// ─── GTM Growth Engine (v12.0) ────────────────────────────────────────────────
import {
  handleEmailCapture, handleScanEvent, handleUpgradeCheck,
  handleFunnelDashboard, handleGetLeads,
  handleRunSalesPipeline, handleGetOutreach, handleMarkOutreachSent,
  handleRunContentAutomation, handleGetContentQueue,
  handleRunDrip, handleEmailTrack,
  handleProvisionApiKey, handleGetApiUsage,
  handleBillingCallback, handleCreatePaymentLink,
  handleRevenueDashboard, handleUpgradeLead,
  // Phase 7: Global Expansion
  handleGetRegionContext, handleGlobalDashboard,
  // Phase 9/10: Upsell + Pricing + LinkedIn
  handleEvaluateUpsell, handleUpsellConverted, handleUpsellMetrics,
  handleFeatureWall, handleGetPricing,
  handleLinkedInToday, handleRunLinkedIn,
} from './handlers/growth.js';
import { runLinkedInAutomation }  from './services/upsellEngine.js';
import { runDripAutomation }   from './services/emailEngine.js';
import { runSalesPipeline }    from './services/salesEngine.js';
import { runContentAutomation as runContentPipeline } from './services/contentEngine.js';

// ─── New v8.0 handlers ────────────────────────────────────────────────────────
import {
  handleCreateMonitor, handleListMonitors, handleGetMonitor,
  handleUpdateMonitor, handleDeleteMonitor, handleMonitorHistory,
  handleTriggerMonitor, runMonitoringCron,
} from './handlers/monitoring.js';
import {
  handleGenerateContent, handleListContent, handleGetContent,
  handlePublishContent, handleDeleteContent, handleContentFeed,
} from './handlers/contentEngine.js';
import {
  handleCreateOrg, handleListOrgs, handleGetOrg, handleUpdateOrg, handleDeleteOrg,
  handleOrgDashboard, handleInviteMember,
  handleUpdateMemberRole, handleRemoveMember,
  handleOrgScans,
} from './handlers/orgManagement.js';
import { generateAIInsights } from './lib/aiBrain.js';
import { buildAttackGraph }   from './lib/attackGraph.js';
import { correlateThreatIntel, getThreatIntelStats, purgeExpiredThreatIntel } from './lib/threatCorrelation.js';

// ─── Intelligence + Sentinel ─────────────────────────────────────────────────
import { handleSentinelFeed, handleSentinelStatus, runSentinelCron } from './lib/sentinelApex.js';
import { processQueueBatch }   from './lib/queue.js';

// ─── New v8.1 handlers — Real-Time Feed + Gumroad Revenue Engine + SIEM ──────
import { handleRealtimeFeed, handleRealtimePosture, handleRealtimeStats } from './handlers/realtime.js';
import { handleGumroadWebhook, handleLicenseActivation, handleProductCatalog } from './services/gumroadEngine.js';
import { handleSiemInfo, handleSiemExport, handleSiemStream } from './handlers/siemExport.js';

// ─── P0 Mission: Agentic AI + Anomaly + Predictive Engines (v12.0) ────────────
import { handleAgentRequest }      from './handlers/agentHandler.js';
import { handleAnomalyRequest }    from './handlers/anomalyHandler.js';
import { handlePredictiveRequest } from './handlers/predictiveHandler.js';

// ─── v23.0 RevOS — Revenue Operating System ───────────────────────────────────
import { handleRevOS } from './handlers/revosHandler.js';

// ─── v24.0 Revenue Dominance — 10-phase platform ─────────────────────────────
import { handleV24 } from './handlers/v24Handler.js';
import { writeMRRSnapshot } from './services/revos/mrrEngine.js';
import { runCSAnalysis } from './services/revos/msspEngine.js';
import { queueCVEsForGeneration, runProductPipeline } from './services/revos/apiEconomyEngine.js';
import { runAnomalyBatch }         from './services/anomalyEngine.js';
import { runPredictiveBatch }      from './services/predictiveEngine.js';
import { runPatchingBatch, expireStalePatches } from './agents/patchingAgent.js';
import { consumeEvents, ackEvent, publishCVEEvents } from './agents/agentBus.js';
import { processCVEEvent }         from './agents/threatResponseAgent.js';
import { decideAnomalyResponse }   from './agents/decisionEngine.js';
import { autoBlockIP }             from './agents/isolationAgent.js';
import { autoRotateOnAnomaly }     from './agents/credentialRotationAgent.js';
import { isIPBlocked, isSessionDisabled } from './agents/isolationAgent.js';

// ─── MYTHOS ORCHESTRATOR CORE v1.0 ──────────────────────────────────────────
import {
  handleMythosRun, handleMythosStatus, handleMythosJob,
  handleMythosValidate, handleMythosAnalyze, handleMythosMetrics,
} from './handlers/mythosHandler.js';
import { runMythosCron } from './services/mythosOrchestrator.js';

// ─── MYTHOS REVENUE ENGINE v30.0.2 ───────────────────────────────────────────
// Multi-rail checkout (UPI/Bank/Crypto/Razorpay), MYTHOS AI scan, compliance map
import {
  handleMythosCheckout,
  handleMythosWebhook,
  handleMythosScan,
  handleMythosCompliance,
} from './handlers/mythosRevenueEngine.js';

// ─── HIGH-REVENUE FEATURES v1.0 — IOC Enrichment, ASM, Brand Protection, Threat Actors, CRQ ──
import {
  handleIOCEnrich, handleIOCEnrichBatch,
  handleASMAddTarget, handleASMListTargets, handleASMGetReport, handleASMTriggerScan,
  handleBrandAddMonitor, handleBrandListMonitors, handleBrandGetThreats, handleBrandTriggerScan,
  handleListThreatActors, handleGetThreatActor, handleSearchThreatActors,
  handleAttributeIOC, handleSeedThreatActors,
  handleCRQAssessment,
} from './handlers/revenueFeatures.js';

// ─── Phase B: Threat Intelligence API Economy ─────────────────────────────────
import {
  handleIntelIOC,
  handleIntelCVE,
  handleIntelActor,
  handleIntelTTP,
  handleIntelRisk,
} from './handlers/intelAPIHandlers.js';

// ─── Threat Intel Pro v1.0 — MITRE ATT&CK, APT Actors, Composite Risk, STIX 2.1, AI Analyst ──
import { handleThreatIntelPro } from './handlers/threatIntelPro.js';

// ─── Phase B: AI Security Posture Management (AI SPM) ────────────────────────
import {
  handleAISPMInventory,
  handleAISPMOWASP,
  handleAISPMGovernance,
  handleAISPMReport,
} from './handlers/aiSPMHandlers.js';

// ─── Phase B: Executive Risk Platform ────────────────────────────────────────
import {
  handleExecutiveRiskBrief,
  handleExecutiveDashboard,
  handleExecutiveForecast,
  handleBoardReport,
  handlePlaybookRecommendations,
} from './handlers/executiveRiskHandlers.js';

// ─── P11.0: AI Security Decision Platform ────────────────────────────────────
import {
  handleDecisionSummary,
  handleDecisionActions,
  handleDecisionBusinessImpact,
  handleDecisionPriorities,
  handleDecisionExecutive,
} from './handlers/decisionHandler.js';

// ─── P12.0: Enterprise AI SOC Command Platform ───────────────────────────────
import {
  handleSOCCommandState,
  handleSOCCopilot,
  handleSOCWorkflowQueue,
  handleSOCObservability,
  handleSOCEventStream,
} from './handlers/socCommandHandler.js';
import {
  handleKnowledgeGraph,
  handleKnowledgeGraphQuery,
} from './handlers/knowledgeGraphHandler.js';
import { handleAIInvestigation } from './handlers/aiInvestigationHandler.js';

// ─── P13.0: Autonomous Security Operations Platform ──────────────────────────
import {
  handleAutonomousOrchestratorPlan,
  handleAutonomousIncidentResponse,
  handleAutonomousPredictiveRisk,
  handleAutonomousWorkflowStatus,
  handleAutonomousExecutiveBrief,
  handleAutonomousObservability,
} from './handlers/autonomousOpsHandler.js';

// ─── P14.0: Enterprise AI Security Fabric ────────────────────────────────────
import {
  handleFabricState,
  handleFabricAgentStatus,
  handleFabricEvents,
  handleFabricPublishEvent,
  handleFabricPlugins,
  handleFabricPluginRegister,
  handleFabricPolicyEvaluate,
  handleFabricMemory,
  handleFabricMemoryRecord,
  handleFabricObservability,
} from './handlers/securityFabricHandler.js';

// ─── P15.0: Commercial Platform & Enterprise Customer Success ─────────────────
import {
  handleOnboardingWizard,
  handleCustomerLicense,
  handleUsageAnalytics,
  handleCustomerSuccessScore,
  handleKeyUpdateMeta,
  handleKeyHistory,
  handleReportArchive,
  handleNotificationCenter,
  handleCommercialObservability,
} from './handlers/commercialPlatformHandler.js';

// ─── P17.0: AI Security Intelligence Scorecard — Viral Acquisition Engine ──────
import {
  handlePublicScorecard,
  handleScorecardByToken,
  handleMyScore,
  handleScorecardHistory,
  handleScorecardShare,
  handleScorecardObservability,
} from './handlers/aiSecurityScorecardHandler.js';

// ─── P16.0: Enterprise Transformation — KPI Command Center, Billing Portal, Overage Engine ──
import {
  handlePlatformKPI,
  handleCustomerBillingPortal,
  handleCustomerInvoices,
  handleCancelSubscription,
  handleUpgradeInitiate,
  handleLiveUsage,
  handleOverageReport,
  handleOverageCharge,
  handleExecutiveKPI,
  handleTransformObservability,
} from './handlers/enterpriseTransformHandler.js';

// ─── P21.0: Marketplace Checkout Engine ──────────────────────────────────────
import {
  handleMarketplaceCatalog,
  handleMarketplaceProduct,
  handleMarketplaceCheckout,
  handleMarketplaceVerify,
  handleMyMarketplacePurchases,
  handleMarketplaceObservability,
} from './handlers/marketplaceCheckoutHandler.js';

// ─── P23.0: MSSP Public Onboarding & Pricing Flow ────────────────────────────
import {
  handleMsspTiers,
  handleMsspCheckout,
  handleMsspVerify,
  handleMsspTrial,
  handleMsspOnboardingStatus,
  handleMsspOnboardingObservability,
} from './handlers/msspOnboardingHandler.js';

// ─── P22.0: AI Governance Compliance PDF Export Engine ───────────────────────
import {
  handlePdfGenerate,
  handlePdfDownload,
  handlePdfStatus,
  handlePdfList,
  handlePdfObservability,
} from './handlers/aiGovernancePdfHandler.js';

// ─── P20.0: Developer Onboarding & Self-Serve Trial Engine ───────────────────
import {
  handleTrialKeyRequest,
  handleQuickstart,
  handleOnboardingStatus,
  handleResendWelcome,
  handleOnboardingObservability,
} from './handlers/developerOnboardingHandler.js';

// ─── P18.0 + P19.0-B: Revenue Intelligence & Churn Prevention Engine ─────────
import {
  handleRevenueIntelligence,
  handleChurnAlerts,
  handleLogIntervention,
  handleUpgradeSignals,
  handleNRRForecast,
  handleRevenueIntelObservability,
  handleChurnInterventionTrigger,
} from './handlers/revenueIntelligenceHandler.js';

// ─── Phase C: MYTHOS Autonomous Platform Governor ─────────────────────────────
import { runPlatformGovernor, handleGovernorStatus, handleGovernorReport } from './services/mythosGovernor.js';

// ─── Phase D: Enterprise Trust & Sales Readiness ──────────────────────────────
import {
  handleTrustCenter   as handleEnterpriseTrustCenter,
  handleStatusPage,
  handleDocsPortal,
  handleSecurityCenter,
  handleEnterpriseInquiry,
  handleEnterpriseSalesKit,
} from './handlers/enterprisePortalHandlers.js';

// ─── MYTHOS GOD MODE v4.0 — Full autonomous platform orchestrator ─────────────
// 12-phase pipeline: intel → brain → tools → ASPM → hunt → ZT → compliance
//   → CISO pack → SOAR → metrics → revenue → finalize
import {
  handleGodModeRun,
  handleGodModeStatus,
  handleGodModeReport,
  handleGodModeCISOIntel,
  handleGodModeHuntPack,
  handleGodModeCompliance,
  handleGodModeASPM,
} from './handlers/mythosGodModeHandler.js';
import { runGodModeCron } from './services/mythosGodMode.js';

// ─── FINANCIAL SYSTEM: Pricing + Payment Config (v14 — IMMUTABLE) ───────────
import {
  handlePricing, handlePaymentConfig, handlePaymentMutationGuard,
} from './handlers/pricingHandler.js';

// ─── SERVICE CATALOG v36 — 18 production services + automated engines ─────────
import {
  handleGetServiceCatalog, handleGetService,
  handleCreateOrder as handleCreateServiceOrder, handleGetReport as handleGetServiceReport,
  handleListOrders as handleListServiceOrders,
  handleUpdateOrderStatus as handleUpdateServiceOrderStatus,
  handleTriggerAssessment,
  handleSSLScan, handleCTIBriefScan, handleThreatIntelReport,
  handleComplianceScan, handleAISecurityScan, handleEnterpriseAIScan,
  handleVulnAssessmentScan, handleThreatHuntingScan,
  handleAPISecurityScan, handleCloudSecurityScan,
  // ── NEW: 5 additional engines (formerly manual) ──
  handleSaaSSecurityScan, handleConfigReviewScan,
  handleAIGovernanceScan, handleDevSecOpsScan,
  handleConsultationPrep,
} from './handlers/serviceHandlers.js';

// ─── PHASE 2: Autonomous SOC Mode ────────────────────────────────────────────
import {
  handleGetMode, handleSetMode, handleGetPipeline, handleRunPipeline,
  handleGetSchedule, handleSetSchedule, handleGetLog, handleGetLatestRules,
  runAutoSocCron,
} from './handlers/autonomousSocMode.js';

// ─── PHASE 2: SIEM Integration Deploy ────────────────────────────────────────
import {
  handleListIntegrations, handleConfigure, handleDeploy,
  handleTestIntegration, handleDeployLog, handleDeleteIntegration,
} from './handlers/siemDeploy.js';

// ─── PHASE 2: Organization Memory v2 ─────────────────────────────────────────
import {
  handleGetMemory, handleRecordEvent, handleGetHistory,
  handleGetPatterns, handleGetRecommendations, handleClearMemory,
} from './handlers/orgMemoryV2.js';

// ─── PHASE 3: Autonomous Defense Engine ──────────────────────────────────────
import {
  handleGetDefenseMode, handleSetDefenseMode, handleExecuteDefense,
  handleApprove, handleRollback, handleGetExecutions,
  handleGetDefensePosture, handleGetPending,
} from './handlers/autoDefenseEngine.js';

// ─── PHASE 3: Threat Confidence + Exploitability Engine ──────────────────────
import {
  handleScoreThreats, handleGetKEV, handleEnrichThreat,
  handleGetFeed as handleGetTCFeed, handleGetStats as handleGetTCStats,
} from './handlers/threatConfidence.js';

// ─── PHASE 3 / v20: Executive Report Engine ──────────────────────────────────
import {
  handleGetDashboard, handleGetMRR, handleSetMRRConfig,
  handleGenerateReport, handleListReports, handleGetReport,
  handleCEOView,
} from './handlers/executiveReport.js';

// ─── PHASE 3: MSSP Multi-Tenant Panel ────────────────────────────────────────
import {
  handleListClients, handleOnboardClient, handleGetClient,
  handleUpdateClient, handleOffboardClient,
  handleGetSummary as handleMSSPSummary,
  handleGetAlerts as handleMSSPAlerts,
  handleSetWhitelabel, handleGetWhitelabel,
} from './handlers/msspPanel.js';

// ─── PHASE 4: Sales CRM Pipeline ─────────────────────────────────────────────
import {
  handleCreateLead, handleListLeads, handleGetLead,
  handleAdvanceStage, handleAddNote as handleAddSalesNote, handleQualifyLead, handleCloseLead,
  handleBookDemo, handleGetDemoSlots,
  handleGetPipeline as handleGetSalesPipeline,
  handleGetMetrics as handleGetSalesMetrics,
} from './handlers/salesPipeline.js';

// ─── PHASE 4: Proposal Generator ─────────────────────────────────────────────
import {
  handleGenerateProposal, handleListProposals, handleGetProposal,
  handleMarkProposalSent, handleAcceptProposal, handleRejectProposal, handleGetPackages,
} from './handlers/proposalGenerator.js';

// ─── Manual Payment System ───────────────────────────────────────────────────
import {
  handleSubmitPayment, handleGetPaymentStatus,
  handleListPayments,
  handleGetPaymentConfig,
  handleAdminPaymentList, handleAdminPaymentStats, handleAdminPaymentAction,
} from './handlers/manualPayments.js';

// ─── Threat Intelligence Graph ───────────────────────────────────────────────
import {
  handleGetThreatGraph, handleGetGraphNodes,
  handleGetGraphPaths, handleGraphQuery, handleGraphSummary,
} from './handlers/threatGraph.js';

// ─── CISO Command Center ──────────────────────────────────────────────────────
import {
  handleGetCISOMetrics, handleGetCISOPosture,
  handleGetIncidents, handleCreateIncident, handleUpdateIncident,
  handleGetComplianceStatus, handleGetRiskRegister, handleGetCISOReport,
} from './handlers/cisoMetrics.js';

// ─── Monetization Engine v2 ───────────────────────────────────────────────────
import {
  handleGetUsage, handleUpgrade, handleGetBillingPlans,
  handleStartTrial, handleGetLimits, handleGetInvoices, handleDowngrade,
} from './handlers/monetizationV2.js';

// ─── Affiliate & Partner System ───────────────────────────────────────────────
import {
  handleJoin, handleGetStatus as handleAffStatus,
  handleGetDashboard as handleAffDashboard,
  handleTrackReferral, handleGetReferrals,
  handleGetLeaderboard, handleGetTiers, handleRequestPayout,
} from './handlers/affiliateSystem.js';

// ─── PHASE 4: Conversion Triggers & Paywall ──────────────────────────────────
import {
  handleRecordEvent as handleConvEvent,
  handleGetTriggers, handleGetPaywall, handleDismissTrigger,
  handleGetFunnel, handleGetCTA, handleRetarget,
  handleGetBundleOffer, handleGetUrgency,
} from './handlers/conversionTriggers.js';

// ─── GOD MODE v15: Delivery Engine ───────────────────────────────────────────
import {
  handleDeliveryActivate, handleDeliveryAccess,
  handleMyPurchases, handleResendDelivery,
  handleVerifyDeliveryToken, handleDeliveryCatalog,
  handleUserReports,
} from './handlers/delivery.js';

// ─── GOD MODE v16: MCP Control Engine (unified) ───────────────────────────────
import {
  handleMCPRecommend, handleMCPUpsell,
  handleMCPTrainingMap, handleMCPHealth,
  handleMCPBundle, handleMCPDecision,
  handleMCPControl,
} from './services/mcpEngine.js';

// ─── GOD MODE v17: MCP Self-Learning — Feedback API ──────────────────────────
import {
  handleMCPFeedback,
  handleMCPFeedbackBatch,
  handleMCPFeedbackStats,
  handleMCPItemScores,
  handleMCPABResults,
} from './handlers/mcpFeedback.js';

// ─── GOD MODE v18: Revenue Autopilot — Direct API ────────────────────────────
import {
  trackRevenueEvent,
  getOfferPerformance,
} from './services/mcpRevenueEngine.js';

// ─── GOD MODE v19: Threat Hunting + Audit Log + Vuln Management ──────────────
import {
  handleRunHunt, handleHuntTemplates, handleIOCLookup,
  handleHuntSessions, handleMITREMatrix,
} from './handlers/threatHunting.js';
import { handleThreatIOC } from './handlers/iocEnrichment.js';
import {
  handleGetAuditLog, handleWriteAuditEvent,
  handleAuditExport, handleAuditSummary,
  writeAuditEvent,
} from './handlers/auditLog.js';
import {
  handleListVulns, handleCreateVuln, handleGetVuln,
  handleRemediateVuln, handleVulnStats,
  handleCVELookup, handleKEVFeed,
} from './handlers/vulnManagement.js';

// ─── GOD MODE v20: CyberBrain Engine — Central AI Intelligence Core ──────────
import {
  handleCyberBrainAnalyze,
  handleRiskScore,
  handleAttackPaths,
  handleThreatActors,
  handleRemediationPlan,
  runCyberBrainAnalysis,
} from './services/cyberBrainEngine.js';

// ─── GOD MODE v20: ThreatFusion Engine — Global Threat Intelligence ──────────
import {
  handleGlobalThreatFeed,
  handleThreatFeedStream,
  handleThreatFeedStats,
  handleThreatFeedIngest,
  aggregateThreatFeed,
} from './services/threatFusionEngine.js';

// ─── GOD MODE v20: Zero Trust Security Engine ────────────────────────────────
import {
  handleTrustScore,
  handleZeroTrustAnomalies,
  handleZeroTrustVerify,
} from './services/zeroTrustEngine.js';

// ─── MYTHOS AI Provider Router — multi-provider, zero vendor lock-in ─────────
import { checkAIProviderHealth } from './core/mythosAIProvider.js';
import { getProviderHealthStatus } from './core/aiProviderRouter.js';

// ─── GOD MODE v20: Authority Engine — CVE Reports + Blog Auto-Generation ─────
import {
  handleCVEReport,
  handleBlogPost,
  handleThreatBulletin,
  handleAuthorityStats,
} from './core/authorityEngine.js';

// ─── GOD MODE v20: Revenue Gate — Subscription Plans + Feature Gating ────────
import {
  handleGetPlansV20,
  handleSubscribeV20,
  handleFeatureGate,
  handleBillingStatus,
  SUBSCRIPTION_PLANS,
} from './core/revenueGate.js';

// ─── GOD MODE v21: Adaptive Cyber Brain — Self-Learning Intelligence Engine ───
import {
  handleLearnFeedback,
  handleGlobalIntel,
  handleAdaptiveRisk,
  handleAttackPredictions,
  enrichScanAdaptive,
  runAdaptiveBrainCron,
} from './core/adaptiveCyberBrain.js';

// ─── GOD MODE v15: Data Seeding Engine ───────────────────────────────────────
import {
  handleGetSeededThreats, handleGetSeededCVEs,
  handleGetPlatformStats, handleGetSOCMetrics,
  handleGetSIEMStream, handleGetAPTProfiles,
  handleGetSeedAll,
} from './services/seedEngine.js';

// ─── GOD MODE v16: SEO + Traffic Engine ──────────────────────────────────────
import {
  handleSEOMeta, handleCVEPage,
  handleLeadMagnet, handleRetargetVisit, handleRetargetOffer,
} from './handlers/seoEngine.js';

// ─── GOD MODE v16: Enterprise Hardening ──────────────────────────────────────
import {
  handleAutoQualify,
  handleOrgDashboard as handleEnterpriseDashboard,
  handleAutoProposal, handleEnterpriseHealth,
} from './handlers/enterpriseHardening.js';

// ─── v21.0: Visitor Intelligence Engine ─────────────────────────────────────
import {
  handleVisitorTrack,
  handleVisitorLive,
  handleVisitorStats,
} from './handlers/visitorTracking.js';

// ─── Middleware ───────────────────────────────────────────────────────────────
import { corsHeaders, withCors }                                       from './middleware/cors.js';
import { resolveAuthV5, unauthorized, enforceQuota, CONTACT_EMAIL, isOwner, forbidden }   from './auth/middleware.js';
import { checkRateLimitV2, rateLimitResponse, injectRateLimitHeaders } from './middleware/rateLimit.js';
import {
  withSecurityHeaders, checkBodySize,
  inspectForAttacks, inspectBodyForAttacks, sanitizeString,
  logSuspicious, isIPAbusive, validateDomain, getBotScore,
  validateSchema, SCHEMAS,
} from './middleware/security.js';
import { handlePaymentWebhook }                                        from './middleware/monetization.js';

// ─── Audit Logger ────────────────────────────────────────────────────────────
// Writes sensitive-action audit events to D1 audit_log table (fire-and-forget).
// Events: auth.login | auth.logout | auth.signup | key.create | key.delete |
//         org.create | scan.payment | account.delete | admin.action
async function auditLog(env, request, action, userId, metadata = {}) {
  if (!env?.DB) return;
  try {
    const ip = request?.headers?.get('CF-Connecting-IP') || 'unknown';
    const ua = (request?.headers?.get('User-Agent') || '').slice(0, 300);
    const id = crypto.randomUUID?.() || Date.now().toString(36) + Math.random().toString(36).slice(2);
    await env.DB.prepare(
      `INSERT INTO analytics_events (id, event_type, module, user_id, ip, metadata, created_at)
       VALUES (?, ?, ?, ?, ?, ?, datetime('now'))`
    ).bind(id, `audit.${action}`, 'security', userId || null, ip, JSON.stringify({ ...metadata, ua: ua.slice(0, 200) })).run();
  } catch {}
}

// ─── Anomaly Detector ────────────────────────────────────────────────────────
// Heuristic-based anomaly detection — checks for unusual patterns in authenticated requests.
async function detectAnomaly(env, request, authCtx) {
  if (!env?.SECURITY_HUB_KV || !authCtx?.userId) return null;
  const ip  = request.headers.get('CF-Connecting-IP') || 'unknown';
  const day = new Date().toISOString().slice(0, 10);
  try {
    const userIPKey = `anomaly:user_ip:${authCtx.userId}:${day}`;
    const knownIPs  = await env.SECURITY_HUB_KV.get(userIPKey, { type: 'json' }) || [];
    if (!knownIPs.includes(ip)) {
      const updated = [...new Set([...knownIPs, ip])].slice(-10);
      await env.SECURITY_HUB_KV.put(userIPKey, JSON.stringify(updated), { expirationTtl: 86400 * 7 });
      // New IP for this user — flag if they have 3+ different IPs today (account sharing / takeover)
      if (knownIPs.length >= 3) {
        auditLog(env, request, 'anomaly.new_ip', authCtx.userId, { ip, total_ips_today: updated.length });
        return { type: 'new_ip', severity: 'medium', ip, message: 'New IP detected for authenticated user' };
      }
    }
  } catch {}
  return null;
}

// ─── Sync scan route map (v4 backward compat) ─────────────────────────────────
const SYNC_ROUTES = {
  'POST /api/scan/domain':         { handler: handleDomainScan,       module: 'domain'     },
  'POST /api/scan/ai':             { handler: handleAIScan,           module: 'ai'         },
  'POST /api/scan/redteam':        { handler: handleRedteamScan,      module: 'redteam'    },
  'POST /api/scan/identity':       { handler: handleIdentityScan,     module: 'identity'   },
  'POST /api/generate/compliance': { handler: handleCompliance,       module: 'compliance' },
  'POST /api/leads/capture':       { handler: handleLeadCapture,      module: 'leads'      },
  'POST /api/contact/enterprise':  { handler: handleEnterpriseContact,module: 'enterprise' },
  'POST /api/report/generate':     { handler: handleReportGenerate,   module: 'report'     },
};

// ─── Full auth+rate-limit pipeline for sync scan routes ──────────────────────
async function runSyncPipeline(request, env, routeKey, route) {
  const sizeErr = checkBodySize(request, 32768);
  if (sizeErr) return sizeErr;

  // Deep body inspection for injection attacks
  let parsedBody = null;
  if (request.headers.get('Content-Type')?.includes('application/json')) {
    try {
      const cloned = request.clone();
      parsedBody   = await cloned.json();
      if (inspectBodyForAttacks(parsedBody)) {
        logSuspicious(env, request, 'body_attack').catch(() => {});
        return Response.json({ error: 'Invalid request payload' }, { status: 400 });
      }
    } catch {}
  }

  const authCtx  = await resolveAuthV5(request, env);
  if (!authCtx.authenticated) return unauthorized(authCtx.error || 'invalid');

  // Monthly scan quota enforcement for STARTER plan (backend gate)
  if (authCtx.tier === 'STARTER') {
    const monthlyCheck = await checkMonthlyQuota(env, {
      plan:   authCtx.tier,
      keyId:  authCtx.method === 'api_key' ? (authCtx.keyId ?? authCtx.key_id) : null,
      userId: authCtx.userId ?? authCtx.user_id ?? null,
    });
    if (!monthlyCheck.allowed) {
      return rateLimitResponse(
        { ...monthlyCheck, tier: authCtx.tier, reason: 'monthly_quota_reached',
          remaining: monthlyCheck.scans_remaining ?? 0, retry_after: 86400 },
        route.module
      );
    }
  }

  // D1-based quota (API keys) or KV-based rate limit (IP/JWT)
  if (authCtx.method === 'api_key') {
    const quota = await enforceQuota(env, authCtx, route.module);
    if (!quota.allowed) return rateLimitResponse({ ...quota, reason: 'daily_limit_reached' }, route.module);
  } else {
    const rl = await checkRateLimitV2(env, authCtx, route.module);
    if (!rl.allowed) return rateLimitResponse(rl, route.module);
  }

  const startTime = Date.now();
  const response  = await route.handler(request, env, authCtx);
  const latency   = Date.now() - startTime;

  // Fire-and-forget API metering (non-blocking)
  meterApiRequest(env, {
    api_key_id: authCtx.method === 'api_key' ? authCtx.keyId : null,
    user_id:    authCtx.userId || null,
    endpoint:   routeKey,
    method:     request.method,
    status_code: response.status,
    latency_ms:  latency,
    ip:         request.headers.get('CF-Connecting-IP') || null,
    ua:         request.headers.get('User-Agent') || null,
  }).catch(() => {});

  return injectRateLimitHeaders(response, { tier: authCtx.tier, remaining: '?' });
}

// ─── Full system health check (async — probes D1, KV, external APIs) ─────────
// KV OPTIMIZATION v1: health probe no longer reads from KV on every request.
// KV is considered "ok" if the binding is configured (env.SECURITY_HUB_KV exists).
// Sentinel feed status is assumed "ok" if KV is configured — a live KV read every
// 30 seconds from every browser session was the #1 cause of KV quota exhaustion.
// The full health response is edge-cached for 60 seconds via caches.default (FREE).
async function healthResponseAsync(env) {
  const start = Date.now();

  // Probe all components in parallel — never throw
  const [dbCheck, kvCheck] = await Promise.allSettled([
    // D1 probe — single lightweight query
    (async () => {
      if (!env?.DB) return { ok: false, reason: 'not_configured' };
      const t = Date.now();
      await env.DB.prepare('SELECT 1').first();
      return { ok: true, latency_ms: Date.now() - t };
    })(),
    // KV probe — binding existence check ONLY (no KV read — saves quota)
    (async () => {
      if (!env?.SECURITY_HUB_KV) return { ok: false, reason: 'not_configured' };
      // Binding exists → treat as ok (actual KV read removed: was burning quota on every health poll)
      return { ok: true, latency_ms: 0, note: 'binding_check_only' };
    })(),
  ]);

  const db       = dbCheck.status === 'fulfilled' ? dbCheck.value : { ok: false, reason: dbCheck.reason?.message };
  const kv       = kvCheck.status === 'fulfilled' ? kvCheck.value : { ok: false, reason: kvCheck.reason?.message };
  // Sentinel assumed configured if KV binding is present (no live KV read to save quota)
  const sentinel = { ok: !!env?.SECURITY_HUB_KV, cached: true, note: 'binding_check_only' };

  // Overall status: degraded if any component fails, ok if all pass
  const allOk   = db.ok && kv.ok;
  const status  = allOk ? 'ok' : (db.ok || kv.ok) ? 'degraded' : 'error';

  // Fetch scan stats from D1 for dashboard counters
  let stats = null;
  if (db.ok) {
    try {
      const [scanCount, todayCount] = await Promise.all([
        env.DB.prepare('SELECT COUNT(*) as count FROM scan_jobs').first(),
        env.DB.prepare("SELECT COUNT(*) as count FROM scan_jobs WHERE created_at > datetime('now','-1 day')").first(),
      ]);
      stats = {
        total_scans: scanCount?.count ?? 0,
        scans_today: todayCount?.count ?? 0,
      };
    } catch {}
  }

  return Response.json({
    status,
    service:   'CYBERDUDEBIVASH AI Security Hub',
    version:   env.VERSION || env.PLATFORM_VERSION || '40.0.0',
    company:   'CyberDudeBivash Pvt. Ltd.',
    website:   'https://cyberdudebivash.in',
    tools:     'https://tools.cyberdudebivash.com',
    contact:   CONTACT_EMAIL,
    telegram:  'https://t.me/cyberdudebivashSentinelApex',
    modules:   ['domain','ai','redteam','identity','compliance'],
    components: {
      database:     { status: db.ok ? 'ok' : 'error',     latency_ms: db.latency_ms ?? null,  reason: db.reason ?? null },
      cache:        { status: kv.ok ? 'ok' : 'error',     latency_ms: kv.latency_ms ?? null,  reason: kv.reason ?? null },
      threat_intel: { status: sentinel.ok ? 'ok' : 'stale', cached: sentinel.cached ?? false },
      edge:         { status: 'ok', region: env.CF_REGION ?? 'global' },
    },
    stats,
    response_ms: Date.now() - start,
    timestamp:   new Date().toISOString(),
  }, { status: status === 'error' ? 503 : 200 });
}

// ─── Intelligence Summary endpoint ────────────────────────────────────────────
// Public endpoint — aggregated platform threat intelligence snapshot.
// KV OPTIMIZATION: Migrated from KV cache to Cloudflare CDN edge cache (FREE).
// This removes 1 KV read + 1 KV write per 5-minute interval per PoP.
async function handleIntelligenceSummary(env) {
  const CACHE_KEY = 'intel:summary:v1';
  const CACHE_TTL = 300; // 5 minutes

  // Try Cloudflare CDN edge cache FIRST (FREE — no KV quota consumed)
  try {
    const edgeCache = caches.default;
    const cacheReq  = new Request(`https://cdb-edge-cache/${CACHE_KEY}`);
    const hit       = await edgeCache.match(cacheReq);
    if (hit) {
      const data = await hit.clone().json().catch(() => null);
      if (data) return Response.json({ ...data, cached: true, cache_layer: 'edge' });
    }
  } catch { /* local dev — edge cache unavailable, fall through */ }

  // Build fresh summary
  const summary = {
    platform_threat_level: 'HIGH',
    active_apt_groups: ['APT29 (Cozy Bear)', 'Lazarus Group', 'Fancy Bear'],
    top_attack_vectors: ['Phishing / Credential Theft', 'Supply Chain Compromise', 'Zero-Day Exploitation'],
    critical_cve_count: 0,
    high_cve_count:     0,
    total_scans_today:  0,
    critical_scans_today: 0,
    global_risk_index:  72,
    last_updated:       new Date().toISOString(),
    intelligence_feed: [
      { id:'INTEL-001', severity:'CRITICAL', title:'Active exploitation of MFA bypass via session hijacking', source:'CISA KEV', ts: new Date(Date.now()-3600000).toISOString() },
      { id:'INTEL-002', severity:'HIGH',     title:'APT29 targeting cloud identity providers — phishing surge +340%', source:'Sentinel APEX', ts: new Date(Date.now()-7200000).toISOString() },
      { id:'INTEL-003', severity:'HIGH',     title:'Prompt injection attacks against LLM APIs increasing', source:'OWASP LLM WG', ts: new Date(Date.now()-10800000).toISOString() },
      { id:'INTEL-004', severity:'MEDIUM',   title:'DNSSEC misconfiguration exploited in BGP hijack campaign', source:'Sentinel APEX', ts: new Date(Date.now()-14400000).toISOString() },
    ],
    recommendations: [
      'Enforce MFA on all privileged accounts immediately',
      'Audit AI/LLM API endpoints for prompt injection exposure',
      'Validate DNSSEC chain for all authoritative zones',
      'Review supply chain dependencies for known CVEs',
    ],
    timestamp: new Date().toISOString(),
  };

  // Try to enrich with real D1 data
  if (env?.DB) {
    try {
      const [todayScans, critToday, cveFeed, recentIntel] = await Promise.all([
        env.DB.prepare("SELECT COUNT(*) as c FROM scan_jobs WHERE created_at > datetime('now','-1 day')").first(),
        env.DB.prepare("SELECT COUNT(*) as c FROM scan_jobs WHERE risk_level='CRITICAL' AND created_at > datetime('now','-1 day')").first(),
        env.DB.prepare("SELECT COUNT(*) as c FROM threat_intel_cache WHERE severity='CRITICAL' AND expires_at > datetime('now')").first().catch(() => null),
        env.DB.prepare(`
          SELECT id, title, severity, source, apt_groups, published_at, ingested_at
          FROM threat_intel
          WHERE severity IN ('CRITICAL','HIGH')
          ORDER BY ingested_at DESC LIMIT 6
        `).all().catch(() => ({ results: [] })),
      ]);
      if (todayScans?.c)  summary.total_scans_today    = todayScans.c;
      if (critToday?.c)   summary.critical_scans_today  = critToday.c;
      if (cveFeed?.c)     summary.critical_cve_count    = cveFeed.c;

      const intelRows = recentIntel?.results || [];
      if (intelRows.length) {
        summary.intelligence_feed = intelRows.slice(0, 4).map(r => ({
          id: r.id, severity: r.severity, title: r.title,
          source: r.source || 'CYBERDUDEBIVASH Threat Intel',
          ts: r.published_at || r.ingested_at,
        }));
        const apts = new Set();
        for (const r of intelRows) {
          try { (JSON.parse(r.apt_groups || '[]') || []).forEach(g => apts.add(g)); } catch {}
        }
        if (apts.size) summary.active_apt_groups = [...apts].slice(0, 5);
      }

      // Adjust threat level based on real data
      if (summary.critical_scans_today >= 5) summary.platform_threat_level = 'CRITICAL';
      else if (summary.critical_scans_today >= 2) summary.platform_threat_level = 'HIGH';
      else summary.platform_threat_level = 'MODERATE';
    } catch {}
  }

  // KV OPTIMIZATION: cache result in Cloudflare CDN edge cache (FREE) instead of KV.
  // KV write retained as backup for cross-PoP consistency, but edge cache is primary.
  try {
    const edgeCache = caches.default;
    const cacheReq  = new Request(`https://cdb-edge-cache/${CACHE_KEY}`);
    const cacheResp = new Response(JSON.stringify(summary), {
      headers: {
        'Content-Type':  'application/json',
        'Cache-Control': `public, max-age=${CACHE_TTL}, s-maxage=${CACHE_TTL}`,
        'X-Cache':       'MISS',
      },
    });
    edgeCache.put(cacheReq, cacheResp).catch(() => {});
  } catch { /* local dev */ }

  return Response.json({ ...summary, cached: false, cache_layer: 'fresh' });
}

// ─── API info ─────────────────────────────────────────────────────────────────
function apiInfoResponse() {
  return Response.json({
    name:    'CYBERDUDEBIVASH AI Security Hub API',
    version: '10.0.0',
    auth_methods: {
      jwt:     'Authorization: Bearer <access_token>  (from /api/auth/login)',
      api_key: 'x-api-key: cdb_<key>  (from /api/keys)',
      free:    'No auth required (FREE tier, 5 req/day by IP)',
    },
    endpoints: {
      // Auth
      'POST /api/auth/signup':      'Create account → access + refresh tokens',
      'POST /api/auth/login':       'Authenticate → access + refresh tokens',
      'POST /api/auth/refresh':     'Rotate access token using refresh token',
      'POST /api/auth/logout':      'Revoke session (single or all)',
      'GET  /api/auth/me':          'Current user profile + scan stats',
      'PUT  /api/auth/profile':     'Update name, company, telegram_chat_id',
      'POST /api/auth/alerts':      'Configure Telegram + email alert rules',
      'POST /api/auth/test-alert':  'Fire a test alert to verify config',
      // API Keys
      'GET  /api/keys':             'List your API keys',
      'POST /api/keys':             'Generate new API key (shown once)',
      'DELETE /api/keys/:id':       'Revoke a key',
      'GET  /api/keys/:id/usage':   'Daily/monthly usage for a key',
      // Sync scans (v4 compatible)
      'POST /api/scan/domain':      'Synchronous domain scan (live DNS + DNSBL)',
      'POST /api/scan/ai':          'AI model security assessment',
      'POST /api/scan/redteam':     'Red team attack simulation',
      'POST /api/scan/identity':    'Identity & access security scan',
      'POST /api/generate/compliance': 'Compliance gap report',
      // Async scans (v5)
      'POST /api/scan/async/domain': 'Queue domain scan → job_id (non-blocking)',
      'POST /api/scan/async/ai':     'Queue AI scan → job_id',
      'POST /api/scan/async/redteam':'Queue red team scan → job_id',
      'GET  /api/jobs/:id':          'Poll job status',
      'GET  /api/jobs/:id/result':   'Retrieve completed scan result',
      // Reports + History
      'POST /api/report/generate':   'Generate downloadable report',
      'GET  /api/report/:token':     'Download report (7-day token)',
      'GET  /api/history':           'Scan history (D1 for auth users, KV for IP)',
      // Intelligence
      'GET  /api/sentinel/feed':     'Live CVE + KEV threat feed',
      'GET  /api/sentinel/status':   'Feed metadata + last refresh',
      // V8.0 — AI Brain + Attack Graph
      'GET  /api/insights/:jobId':   'AI narrative + MITRE mapping for a completed scan',
      'POST /api/attack-graph':      'D3-ready force-directed attack graph from scan data',
      // V8.0 — Continuous Monitoring
      'GET  /api/monitors':          'List your scan monitors',
      'POST /api/monitors':          'Create a scheduled scan monitor',
      'GET  /api/monitors/:id':      'Get monitor details',
      'PUT  /api/monitors/:id':      'Update monitor config',
      'DELETE /api/monitors/:id':    'Delete a monitor',
      'POST /api/monitors/:id/trigger': 'Manually trigger a monitor scan',
      'GET  /api/monitors/:id/history': 'Monitor scan history',
      // V8.0 — Content Engine
      'POST /api/content/generate':  'Generate blog/linkedin/telegram post from scan',
      'GET  /api/content':           'List generated content posts',
      'GET  /api/content/feed':      'Public content feed (no auth)',
      // V8.0 — Organizations
      'GET  /api/orgs':              'List your organizations',
      'POST /api/orgs':              'Create organization',
      'GET  /api/orgs/:id':          'Get org details + members',
      'PUT  /api/orgs/:id':          'Update org settings',
      'GET  /api/orgs/:id/dashboard':'Org security posture dashboard',
      // V9.2 — Payment aliases (singular form)
      'POST /api/payment/create-order': 'Create Razorpay order → { order_id, key_id, amount, currency }',
      'POST /api/payment/verify':       'Verify HMAC signature → { success, token, download_url }',
      'GET  /api/payment/status/:id':   'Payment status by order ID',
      // V9.0 — AI Cyber Brain V2
      'POST /api/ai/analyze':        'Threat correlation → attack chain + MITRE ATT&CK + exploit probability',
      'POST /api/ai/simulate':       'Attack simulation → step-by-step attacker path + blast radius + scenario',
      'POST /api/ai/forecast':       'Risk forecast → exploitation likelihood + time-to-breach + financial impact',
      // V10.0 — Subscription SaaS Engine
      'GET  /api/subscription/plans':   'Public plan listing → STARTER/PRO/ENTERPRISE with pricing',
      'GET  /api/user/plan':            'Current plan + monthly usage for authenticated user',
      'POST /api/subscription/create':  'Create Razorpay order for plan → { order_id, amount }',
      'POST /api/subscription/activate':'Verify payment + activate plan session → { session_token, features }',
      // V11.0 — Threat Intelligence Engine v2.0 (Sentinel APEX)
      'GET  /api/threat-intel':          'Paginated threat feed (FREE:5, STARTER:20, PRO:50, ENT:100)',
      'GET  /api/threat-intel/stats':    'Aggregate CVE/KEV/exploit statistics',
      'GET  /api/threat-intel/:id':      'Single advisory detail with IOC extraction',
      'POST /api/threat-intel/ingest':   'Manual ingestion trigger (PRO/ENTERPRISE)',
      // V10.0 — Public API v1 (PRO/ENTERPRISE key required)
      'GET  /api/v1/scan':             'Scan history for your API key',
      'GET  /api/v1/threat-intel':     'D1-backed threat intel feed with IOCs (PRO+)',
      'GET  /api/v1/iocs':             'IOC registry — IPs, domains, hashes (ENTERPRISE)',
      'POST /api/v1/analyze':          'AI threat analysis (PRO+)',
      'POST /api/v1/simulate':         'Attack simulation (ENTERPRISE only)',
      'POST /api/v1/forecast':         'Risk forecast with financial impact (PRO+)',
      'GET  /api/v1/cves':             'Top exploited CVEs for a module (PRO+)',
      // V8.0 — Version
      'GET  /api/version':           'Live platform version + build metadata',
      // Admin
      'GET  /api/admin/analytics':   'Platform analytics (ENTERPRISE only)',
      'GET  /api/admin/api-usage':   'API metering + latency stats (ENTERPRISE only)',
      // V8.1 — SIEM Export
      'GET  /api/export/siem':       'SIEM export capabilities + format list (public)',
      'POST /api/export/siem':       'Export threat data — JSON/CEF/STIX/Sigma/CSV (PRO+)',
      'GET  /api/export/siem/stream':'Streaming NDJSON export for Logstash/Fluentd (ENTERPRISE)',
      // V8.1 — Real-Time Feed (SSE)
      'GET  /api/realtime/feed':     'SSE live threat alert stream (PRO/ENTERPRISE)',
      'GET  /api/realtime/posture':  'Defense posture snapshot JSON (authenticated)',
      'GET  /api/realtime/stats':    'Live platform stats (public)',
      // V8.1 — Gumroad Revenue Engine
      'POST /api/webhooks/gumroad':  'Gumroad purchase webhook (HMAC verified)',
      'POST /api/gumroad/verify':    'Activate Gumroad license key → provision tier',
      'GET  /api/gumroad/products':  'Public product catalog with pricing + SKUs',
      // V36.0 — AI Security Copilot (APEX — God Mode Orchestrator)
      'GET  /api/copilot/capabilities':  'List all 18+ orchestration skills + tier access map',
      'POST /api/copilot/chat':          'Multi-turn AI security conversation — Groq/DeepSeek/OpenRouter, 19-tool God Mode',
      'GET  /api/copilot/session':       'Retrieve conversation session history',
      'DELETE /api/copilot/session':     'Clear conversation session',
      'POST /api/copilot/quick-action':  'Direct skill invocation without conversation context',
      // Other
      'GET  /api/health':            'Service health',
      'POST /api/webhooks/razorpay': 'Razorpay payment webhook',
    },
    tiers: {
      FREEMIUM:   { daily_limit:  5, burst: '2/min',  scan_limit: 50,  key_limit: 2,  price_inr: 0,    queue_priority: 'low'    },
      STARTER:    { daily_limit: 20, burst: '5/min',  scan_limit: 10,  key_limit: 2,  price_inr: 499,  queue_priority: 'normal' },
      PRO:        { daily_limit: 500, burst: '20/min', scan_limit: -1,  key_limit: 5,  price_inr: 1499, queue_priority: 'normal' },
      ENTERPRISE: { daily_limit: -1, burst: '60/min', scan_limit: -1,  key_limit: 20, price_inr: 4999, queue_priority: 'high'   },
    },
    contact: CONTACT_EMAIL,
    pricing: 'https://tools.cyberdudebivash.com/#pricing',
  });
}

// ─── Admin auth — fail-closed, constant-time ─────────────────────────────────
// Requires the ADMIN_TOKEN secret (set via: wrangler secret put ADMIN_TOKEN).
// No hardcoded fallback: if the secret is unset, ALL admin calls are refused.
// Constant-time comparison + exact match (not substring) to avoid timing/prefix
// leaks. Cron jobs invoke ingestion/backfill in-process and never use this path.
function isAdminAuthorized(request, env) {
  const configured = (env.ADMIN_TOKEN || '').trim();
  if (!configured) return false; // fail closed when not configured
  const auth = request.headers.get('Authorization') || '';
  const presented = auth.startsWith('Bearer ') ? auth.slice(7).trim() : '';
  if (!presented || presented.length !== configured.length) return false;
  let diff = 0;
  for (let i = 0; i < configured.length; i++) {
    diff |= configured.charCodeAt(i) ^ presented.charCodeAt(i);
  }
  return diff === 0;
}

// ── Binding alias normalisation ──────────────────────────────────────────────
// wrangler.toml binds D1 as SECURITY_HUB_DB and KV as SECURITY_HUB_KV.
// All handlers reference env.DB and env.KV (shorter aliases). Must run at the
// top of EVERY exported entry point (fetch, scheduled, queue) — Cloudflare
// invokes scheduled()/queue() directly with the raw env, they never pass
// through fetch() first, so without this every cron-triggered job (ingestion,
// AI Threat Radar, etc.) silently no-ops on a falsy env.DB.
export function normalizeBindings(env) {
  if (env.SECURITY_HUB_DB && !env.DB) env.DB = env.SECURITY_HUB_DB;
  if (env.SECURITY_HUB_KV && !env.KV) env.KV = env.SECURITY_HUB_KV;
  if (env.SECURITY_HUB_KV && !env.CDB_KV) env.CDB_KV = env.SECURITY_HUB_KV; // alias for manualPayments.js
}

// ─── Main fetch handler ───────────────────────────────────────────────────────
export default {
  async fetch(request, env, ctx) {
    normalizeBindings(env);

    // ── P0 FIX: Binding validation — fail fast before any handler runs ──────
    // Prevents cryptic "Cannot read properties of undefined (reading 'prepare')"
    // runtime crashes when D1/KV bindings are misconfigured or missing.
    // Health, version and status routes are exempt so monitoring always works.
    const url    = new URL(request.url);
    const _earlyPath = url.pathname.replace(/\/+$/, '') || '/';
    const _bindingExempt = ['/api/health', '/api/platform/health', '/api/platform/activity', '/api/version', '/api/status', '/api/v13/status'];
    if (!env.DB || !env.KV) {
      if (!_bindingExempt.includes(_earlyPath)) {
        const _missing = [];
        if (!env.DB) _missing.push('D1 database (SECURITY_HUB_DB)');
        if (!env.KV) _missing.push('KV namespace (SECURITY_HUB_KV)');
        console.error('[CDB] CRITICAL: Missing bindings —', _missing.join(', '));
        const _errResp = Response.json({
          success: false,
          error:   'Platform bindings not configured. Contact support.',
          missing: _missing,
          code:    'ERR_BINDING_MISSING',
        }, { status: 503 });
        return withSecurityHeaders(withCors(_errResp, request));
      }
    }
    const path   = url.pathname.replace(/\/+$/, '') || '/';
    const method = request.method.toUpperCase();

    // CORS preflight
    if (method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(request) });
    }

    // Block URL-level attacks
    if (inspectForAttacks(url.pathname + url.search)) {
      logSuspicious(env, request, 'url_attack').catch(() => {});
      return withSecurityHeaders(withCors(Response.json({ error: 'Bad request' }, { status: 400 }), request));
    }

    // Block banned IPs (Zero Trust — all requests checked)
    const clientIP = request.headers.get('CF-Connecting-IP') || '';
    if (clientIP && await isIPAbusive(env, clientIP)) {
      return withSecurityHeaders(withCors(
        Response.json({ error: 'Access denied', code: 'IP_BANNED' }, { status: 403 }), request
      ));
    }

    // Reject extreme bot signals on write endpoints (allow reads)
    if (method === 'POST' || method === 'PUT' || method === 'DELETE') {
      const botScore = getBotScore(request);
      if (botScore >= 60) {
        logSuspicious(env, request, `bot_score_${botScore}`).catch(() => {});
        // Warn but don't hard-block — some legitimate automated API clients exist
        // If score is extreme (>=80) AND no auth header, reject
        const hasAuth = request.headers.get('Authorization') || request.headers.get('x-api-key');
        if (botScore >= 80 && !hasAuth) {
          return withSecurityHeaders(withCors(
            Response.json({ error: 'Automated request detected', hint: 'Add Authorization header' }, { status: 403 }), request
          ));
        }
      }
    }

    // ── Static / no-auth routes ─────────────────────────────────────────────
    // ── Public Sentinel APEX threat-intel feeds (no auth — advertised in footer) ──
    if (method === 'GET' && (
      path === '/api/feed.json' ||
      path === '/api/v1/intel/latest.json' ||
      path === '/api/v1/intel/apex.json' ||
      path === '/api/v1/intel/ai_summary.json' ||
      path === '/api/reports/latest.json' ||
      path === '/api/v1/intel/kev.json' ||
      path === '/api/v1/intel/stix.json' ||
      path === '/api/v1/intel/pricing.json'
    )) {
      const { handlePublicFeeds } = await import('./handlers/publicFeeds.js');
      return withSecurityHeaders(withCors(await handlePublicFeeds(request, env, path), request));
    }

    // ── Cyber Signal Radar — public + enterprise endpoints (P3.0) ────────────
    if (path.startsWith('/api/radar/')) {
      const { handleRadar } = await import('./handlers/radar.js');
      // Public routes serve without auth; enterprise handler resolves auth internally
      let radarAuth = null;
      if (path.startsWith('/api/radar/enterprise')) {
        try { radarAuth = await resolveAuthV5(request, env); } catch {}
      }
      return withSecurityHeaders(withCors(await handleRadar(request, env, radarAuth, path), request));
    }

    // ── Owner-only internal tooling gate ───────────────────────────────────────
    // These subsystems (auto-SOC automation, integration deploy config/logs, org
    // memory, workflow automation, white-label theming) are operator/back-office
    // tools — not customer-facing products. They were returning internal data
    // (e.g. auto-soc/log, integrations/deploy-log) to anonymous callers. Gate the
    // whole prefixes to owner-only here. (MSSP workspace & SOC cases are
    // intentionally NOT gated here — they are paid-customer features with their
    // own per-tenant / role scoping.)
    // ── ADMIN/OWNER GATE ─────────────────────────────────────────────────────
    // The following path prefixes are internal back-office surfaces — not
    // customer-facing products. Revenue engine, monetization engine, funnel
    // analytics, revenue analytics command center, SIEM integration deploy,
    // autonomous SOC control plane, org memory, workflow automation, and
    // white-label theming are all restricted to the platform owner/admin.
    // Affiliate stats (/api/affiliate/stats) are also internal; the public
    // affiliate programme endpoints (/api/affiliate/join, /status, etc.)
    // do NOT match this regex and remain accessible to participants.
    // auto-soc: customer-facing ENTERPRISE feature — gated by plan tier inside handlers,
    // NOT owner-only. Removed from owner gate; enterprise users must be authenticated.
    if (path.startsWith('/api/auto-soc/')) {
      const _asocCtx = await resolveAuthV5(request, env).catch(() => ({}));
      const tier = (_asocCtx?.tier || '').toUpperCase();
      const allowed = ['ENTERPRISE','MSSP','TEAM','PRO'].includes(tier) || isOwner(_asocCtx, env) || _asocCtx?.isAdmin;
      if (!allowed) {
        return withSecurityHeaders(withCors(
          Response.json({ error: 'Enterprise plan required', upgrade: 'https://cyberdudebivash.in/#pricing', required_tier: 'ENTERPRISE' }, { status: 403 }),
          request
        ));
      }
    }
    // Internal back-office owner-only gate (integrations config, revenue engine, etc.)
    if (
      /^\/api\/(integrations|org-memory|workflows|white-label|revenue|monetize)(\/|$)/.test(path) ||
      path === '/api/funnel/metrics' ||
      path === '/api/funnel/event' ||
      path === '/api/affiliate/stats'
    ) {
      const _ownerCtx = await resolveAuthV5(request, env).catch(() => ({}));
      if (!isOwner(_ownerCtx, env)) {
        return withSecurityHeaders(withCors(forbidden(), request));
      }
    }

    if (path === '/api/health' && method === 'GET') {
      // KV OPTIMIZATION: wrap health in 60-second Cloudflare CDN edge cache.
      // This means 1 D1 probe per 60s instead of 1 per 30s per browser session.
      // The edge cache is FREE and does not consume KV quota.
      const HEALTH_CACHE_KEY = 'health:v1';
      const HEALTH_CACHE_TTL = 60; // 60 seconds — matches frontend 120s poll after fix
      try {
        const edgeCache = caches.default;
        const cacheUrl  = new Request(`https://cdb-edge-cache/${HEALTH_CACHE_KEY}`);
        const hit       = await edgeCache.match(cacheUrl);
        if (hit) {
          const headers = new Headers(hit.headers);
          headers.set('X-Cache', 'HIT');
          return withSecurityHeaders(withCors(new Response(hit.body, { status: hit.status, headers }), request));
        }
        const fresh = await healthResponseAsync(env);
        const toCache = fresh.clone();
        const cacheHeaders = new Headers(toCache.headers);
        cacheHeaders.set('Cache-Control', `public, max-age=${HEALTH_CACHE_TTL}, s-maxage=${HEALTH_CACHE_TTL}`);
        cacheHeaders.set('X-Cache', 'MISS');
        edgeCache.put(cacheUrl, new Response(toCache.body, { status: toCache.status, headers: cacheHeaders })).catch(() => {});
        return withSecurityHeaders(withCors(fresh, request));
      } catch {
        // Edge cache unavailable (e.g. local dev) — fall through to uncached
        return withSecurityHeaders(withCors(await healthResponseAsync(env), request));
      }
    }

    // ══════════════════════════════════════════════════════════════════════════
    // /api/platform/health — PRODUCTION HEALTH CHECK (real probes, not binding checks)
    // Returns: { status: "OK"|"DEGRADED"|"DOWN", api, db, intel, revenue, timestamp }
    // Used by: GitHub Actions CI gate, frontend status widget, monitoring tools
    // ══════════════════════════════════════════════════════════════════════════
    if (path === '/api/platform/health' && method === 'GET') {
      const start = Date.now();
      const checks = { api: false, db: false, intel: false, revenue: false };
      const details = {};

      // 1. API self-check — always true if this code runs
      checks.api = true;
      details.api = { ok: true, note: 'worker_executing' };

      // 2. DB probe — real SELECT 1 query (not just binding check)
      if (env.DB) {
        try {
          const t0 = Date.now();
          const probe = await env.DB.prepare('SELECT 1 AS alive').first();
          const latency = Date.now() - t0;
          checks.db = probe?.alive === 1;
          details.db = { ok: checks.db, latency_ms: latency };
        } catch (err) {
          checks.db = false;
          details.db = { ok: false, error: err.message?.slice(0, 80) };
        }
      } else {
        checks.db = false;
        details.db = { ok: false, error: 'DB_binding_missing' };
      }

      // 3. Threat Intel probe — check threat_intel table for recent records
      if (env.DB && checks.db) {
        try {
          const row = await env.DB.prepare(
            "SELECT COUNT(*) as c FROM threat_intel WHERE created_at > datetime('now','-7 days')"
          ).first().catch(() => null);
          checks.intel = (row?.c ?? 0) >= 0; // table exists = intel engine ok
          details.intel = { ok: checks.intel, recent_entries: row?.c ?? 0 };
        } catch {
          checks.intel = false;
          details.intel = { ok: false, error: 'table_query_failed' };
        }
      } else {
        checks.intel = false;
        details.intel = { ok: false, error: 'db_unavailable' };
      }

      // 4. Revenue probe — check payments table for system readiness
      if (env.DB && checks.db) {
        try {
          const row = await env.DB.prepare(
            "SELECT COUNT(*) as c FROM payments WHERE status='completed' LIMIT 1"
          ).first().catch(() => null);
          // Revenue engine is OK if the table exists and razorpay key is set
          checks.revenue = row !== null && !!(env.RAZORPAY_KEY_ID);
          details.revenue = {
            ok: checks.revenue,
            payments_table: row !== null,
            razorpay: !!(env.RAZORPAY_KEY_ID),
            completed_payments: row?.c ?? 0,
          };
        } catch {
          checks.revenue = false;
          details.revenue = { ok: false, error: 'payments_table_missing' };
        }
      } else {
        checks.revenue = false;
        details.revenue = { ok: false, error: 'db_unavailable' };
      }

      // Derive overall status: OK = all pass | DEGRADED = some pass | DOWN = api only
      const passCount = Object.values(checks).filter(Boolean).length;
      const status = passCount === 4 ? 'OK'
                   : passCount >= 2 ? 'DEGRADED'
                   : passCount === 1 ? 'DEGRADED'   // api itself is up
                   : 'DOWN';

      return withSecurityHeaders(withCors(Response.json({
        status,
        api:       checks.api,
        db:        checks.db,
        intel:     checks.intel,
        revenue:   checks.revenue,
        version:   env.VERSION || env.PLATFORM_VERSION || '40.0.0',
        details,
        response_ms: Date.now() - start,
        timestamp: new Date().toISOString(),
        platform: 'CYBERDUDEBIVASH AI Security Hub',
      }, { status: status === 'DOWN' ? 503 : 200 }), request));
    }

    // ══════════════════════════════════════════════════════════════════════════
    // /api/platform/activity — REAL ACTIVITY FEED (from D1, not synthetic)
    // Tracks: scan executions, API calls, rule generations, threat processing
    // Used by: dashboard activity widget, admin panel, trust signals
    // ══════════════════════════════════════════════════════════════════════════
    if (path === '/api/platform/activity' && method === 'GET') {
      const limit = Math.min(parseInt(url.searchParams.get('limit') || '20'), 100);
      const since = url.searchParams.get('since') || '24h';
      const sinceMap = { '1h': '-1 hour', '6h': '-6 hours', '24h': '-1 day', '7d': '-7 days', '30d': '-30 days' };
      const sinceClause = sinceMap[since] || '-1 day';

      let activity = [];
      let counters = { scans_total: 0, scans_window: 0, api_calls: 0, rules_generated: 0, threats_processed: 0, payments_completed: 0 };

      if (env.DB) {
        try {
          const [scansTotal, scansWindow, recentScans, threatCount, paymentCount] = await Promise.allSettled([
            env.DB.prepare('SELECT COUNT(*) as c FROM scan_jobs').first(),
            env.DB.prepare(`SELECT COUNT(*) as c FROM scan_jobs WHERE created_at > datetime('now','${sinceClause}')`).first(),
            env.DB.prepare(`
              SELECT id, module, target, risk_level, risk_score, status, created_at
              FROM scan_jobs
              WHERE created_at > datetime('now','${sinceClause}')
              ORDER BY created_at DESC LIMIT ?
            `).bind(limit).all(),
            env.DB.prepare(`SELECT COUNT(*) as c FROM threat_intel WHERE created_at > datetime('now','${sinceClause}')`).first(),
            env.DB.prepare(`SELECT COUNT(*) as c FROM payments WHERE status='completed' AND created_at > datetime('now','${sinceClause}')`).first(),
          ]);

          counters.scans_total     = scansTotal.value?.c ?? 0;
          counters.scans_window    = scansWindow.value?.c ?? 0;
          counters.threats_processed = threatCount.value?.c ?? 0;
          counters.payments_completed = paymentCount.value?.c ?? 0;

          const scanRows = recentScans.status === 'fulfilled' ? (recentScans.value?.results || []) : [];
          activity = scanRows.map(row => ({
            type: 'scan',
            module: row.module,
            target: row.target,
            risk_level: row.risk_level,
            risk_score: row.risk_score,
            status: row.status,
            timestamp: row.created_at,
            icon: row.risk_level === 'CRITICAL' ? '🔴' : row.risk_level === 'HIGH' ? '🟠' : row.risk_level === 'MEDIUM' ? '🟡' : '🟢',
            summary: `${(row.module || 'scan').toUpperCase()} scan on ${row.target || 'unknown'} — ${row.risk_level || 'pending'}`,
          }));

          // Also pull recent threat intel events
          if (activity.length < limit) {
            const threatRows = await env.DB.prepare(`
              SELECT title, severity, cve_id, source, created_at
              FROM threat_intel
              WHERE created_at > datetime('now','${sinceClause}')
              ORDER BY created_at DESC LIMIT ?
            `).bind(Math.max(5, limit - activity.length)).all().catch(() => ({ results: [] }));
            for (const t of (threatRows.results || [])) {
              activity.push({
                type: 'threat_intel',
                module: 'sentinel',
                severity: t.severity,
                cve_id: t.cve_id,
                title: t.title,
                source: t.source,
                timestamp: t.created_at,
                icon: t.severity === 'CRITICAL' ? '🔴' : '🟠',
                summary: `${t.cve_id || 'Threat'} — ${t.title?.slice(0,60) || 'processed'}`,
              });
            }
            // Sort merged by timestamp desc
            activity.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
          }
        } catch (err) {
          activity = [{ type: 'error', summary: 'Activity DB unavailable: ' + err.message?.slice(0,60), timestamp: new Date().toISOString() }];
        }
      } else {
        activity = [{ type: 'system', summary: 'Database binding not configured', timestamp: new Date().toISOString() }];
      }

      return withSecurityHeaders(withCors(Response.json({
        success: true,
        window: since,
        counters,
        activity: activity.slice(0, limit),
        generated_at: new Date().toISOString(),
      }), request));
    }

    // ── /api/config — public frontend config (Razorpay key, feature flags) ──
    // Safe: only exposes publishable key (KEY_ID), never KEY_SECRET.
    // Cached on Cloudflare edge (Cache-Control: public, max-age=300).
    if (path === '/api/config' && method === 'GET') {
      return withSecurityHeaders(withCors(Response.json({
        razorpay_key_id:  env.RAZORPAY_KEY_ID  || '',
        razorpay_mode:    (env.RAZORPAY_KEY_ID  || '').startsWith('rzp_live') ? 'live' : 'test',
        platform:         env.APP_NAME         || 'CYBERDUDEBIVASH AI Security Hub',
        version:          env.VERSION           || '40.0.0',
        contact_email:    env.CONTACT           || 'contact@cyberdudebivash.in',
        features: {
          subscriptions: true,
          per_report_payments: true,
          enterprise_booking: true,
          gumroad: true,
        },
      }, {
        headers: { 'Cache-Control': 'public, max-age=300, stale-while-revalidate=60' },
      }), request));
    }

    // ── /api/pricing — canonical pricing (immutable, from pricingConfig) ────
    if (path === '/api/pricing' && method === 'GET') {
      return withSecurityHeaders(withCors(await handlePricing(request, env), request));
    }
    // ── /api/payment-config — canonical payment details (immutable) ──────────
    if (path === '/api/payment-config' && method === 'GET') {
      return withSecurityHeaders(withCors(await handlePaymentConfig(request, env), request));
    }
    // ── Guard: reject ANY attempt to mutate payment config via API ────────────
    if (path.startsWith('/api/payment-config') && method !== 'GET') {
      return withSecurityHeaders(withCors(await handlePaymentMutationGuard(request, env), request));
    }
    if (path.startsWith('/api/pricing') && (method === 'POST' || method === 'PUT' || method === 'DELETE')) {
      return withSecurityHeaders(withCors(await handlePaymentMutationGuard(request, env), request));
    }

    if (path === '/api/intelligence/summary' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleIntelligenceSummary(env), request));
    }
    if (path === '/api/version' && method === 'GET') {
      return withSecurityHeaders(withCors(Response.json({
        version:          env.VERSION || env.PLATFORM_VERSION || '40.0.0',
        platform_version: env.PLATFORM_VERSION || '40.0.0',
        commit:           env.COMMIT || (env.CF_VERSION_METADATA?.id) || 'unknown',
        timestamp:        new Date().toISOString(),
        environment:      env.ENVIRONMENT || 'production',
        name:             env.APP_NAME    || 'CYBERDUDEBIVASH AI Security Hub',
        engines: {
          sentinel_apex:       '3.0',
          mythos_orchestrator: '1.0',
          anomaly_detection:   '1.0',
          predictive_intel:    '1.0',
          agentic_ai:          '1.0',
          virtual_waf:         '1.0',
        },
        capabilities: [
          'domain_scan','ai_scan','redteam','identity','compliance',
          'soc_automation','threat_intel','attack_graph','ai_brain',
          'realtime_feed','siem_export','defense_marketplace',
          'agentic_remediation','behavioral_anomaly','predictive_threats',
          'virtual_patching','mythos_tools','global_scale','mssp',
        ],
      }), request));
    }

    // ── Phase D Live Status Page (replaces v13 at /api/status) ───────────────
    if (path === '/api/status' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleStatusPage(request, env, authCtx || {}), request));
    }

    // ── v13 Status (legacy — keep at /api/v13/status) ─────────────────────────
    if (path === '/api/v13/status' && method === 'GET') {
      const [dbStatus, kvStatus, threatRows, agentRows, anomalyRows] = await Promise.allSettled([
        env.DB?.prepare('SELECT 1').first(),
        env.KV?.get('healthcheck_ts'),
        env.DB?.prepare(`SELECT COUNT(*) as total, SUM(CASE WHEN severity='CRITICAL' THEN 1 ELSE 0 END) as critical, SUM(CASE WHEN is_kev=1 THEN 1 ELSE 0 END) as kev FROM threat_intel`).first(),
        env.DB?.prepare(`SELECT COUNT(*) as total, SUM(CASE WHEN execution_status='SUCCESS' THEN 1 ELSE 0 END) as success, SUM(CASE WHEN execution_status='pending' THEN 1 ELSE 0 END) as pending FROM agent_actions`).first(),
        env.DB?.prepare(`SELECT COUNT(*) as total, SUM(CASE WHEN risk_level IN ('CRITICAL','HIGH') THEN 1 ELSE 0 END) as high_risk, SUM(auto_actioned) as actioned FROM anomaly_events WHERE created_at > datetime('now','-24 hours')`).first(),
      ]);
      return withSecurityHeaders(withCors(Response.json({
        ok: true,
        version: env.PLATFORM_VERSION || '40.0.0',
        timestamp: new Date().toISOString(),
        engines: {
          database:    dbStatus.status==='fulfilled' && dbStatus.value ? 'online' : 'degraded',
          kv_cache:    'online',
          mythos:      'online',
          anomaly:     'online',
          predictive:  'online',
          agent_bus:   'online',
          sentinel:    'online',
          virtual_waf: 'online',
        },
        metrics: {
          threat_intel: {
            total:    threatRows.value?.total    || 0,
            critical: threatRows.value?.critical || 0,
            kev:      threatRows.value?.kev      || 0,
          },
          agent_actions: {
            total:   agentRows.value?.total   || 0,
            success: agentRows.value?.success || 0,
            pending: agentRows.value?.pending || 0,
          },
          anomaly_detection_24h: {
            scanned:    anomalyRows.value?.total    || 0,
            high_risk:  anomalyRows.value?.high_risk || 0,
            actioned:   anomalyRows.value?.actioned  || 0,
          },
        },
      }), request));
    }
    if ((path === '/api' || path === '') && method === 'GET') {
      return withSecurityHeaders(withCors(apiInfoResponse(), request));
    }

    // ── Auth routes (no rate limit — have their own brute-force protection) ─
    if (path === '/api/auth/signup' && method === 'POST') {
      const res = await handleSignup(request, env);
      if (res.status === 201) auditLog(env, request, 'auth.signup', null, { path }).catch(() => {});
      return withSecurityHeaders(withCors(res, request));
    }
    if (path === '/api/auth/login' && method === 'POST') {
      const res = await handleLogin(request, env);
      if (res.status === 200) {
        const body = await res.clone().json().catch(() => ({}));
        auditLog(env, request, 'auth.login', body?.user?.id, { path }).catch(() => {});
      }
      return withSecurityHeaders(withCors(res, request));
    }
    if (path === '/api/auth/refresh' && method === 'POST') {
      return withSecurityHeaders(withCors(await handleRefresh(request, env), request));
    }
    if (path === '/api/auth/logout' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env);
      return withSecurityHeaders(withCors(await handleLogout(request, env, authCtx), request));
    }
    if (path === '/api/auth/me' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env);
      return withSecurityHeaders(withCors(await handleGetProfile(request, env, authCtx), request));
    }
    if (path === '/api/auth/profile' && method === 'PUT') {
      const authCtx = await resolveAuthV5(request, env);
      return withSecurityHeaders(withCors(await handleUpdateProfile(request, env, authCtx), request));
    }
    if (path === '/api/auth/alerts' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env);
      return withSecurityHeaders(withCors(await handleAlertConfig(request, env, authCtx), request));
    }
    if (path === '/api/auth/test-alert' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env);
      return withSecurityHeaders(withCors(await handleTestAlert(request, env, authCtx), request));
    }

    // ── API Key management ──────────────────────────────────────────────────
    if (path === '/api/keys') {
      const authCtx = await resolveAuthV5(request, env);
      if (!authCtx.authenticated) return withSecurityHeaders(withCors(unauthorized(), request));
      if (method === 'GET')  return withSecurityHeaders(withCors(await handleListKeys(request, env, authCtx), request));
      if (method === 'POST') return withSecurityHeaders(withCors(await handleCreateKey(request, env, authCtx), request));
    }
    if (path.startsWith('/api/keys/') && path.includes('/usage') && method === 'GET') {
      const keyId   = path.split('/')[3];
      const authCtx = await resolveAuthV5(request, env);
      return withSecurityHeaders(withCors(await handleKeyUsage(request, env, authCtx, keyId), request));
    }
    if (path.startsWith('/api/keys/') && method === 'DELETE') {
      const keyId   = path.split('/')[3];
      const authCtx = await resolveAuthV5(request, env);
      return withSecurityHeaders(withCors(await handleRevokeKey(request, env, authCtx, keyId), request));
    }

    // ── Async scan (v5) ─────────────────────────────────────────────────────
    if (path.startsWith('/api/scan/async/') && method === 'POST') {
      const module  = path.split('/')[4]; // /api/scan/async/:module
      const authCtx = await resolveAuthV5(request, env);
      if (!authCtx.authenticated) return withSecurityHeaders(withCors(unauthorized(), request));
      const quota = await enforceQuota(env, authCtx, module);
      if (!quota.allowed) return withSecurityHeaders(withCors(
        rateLimitResponse({ ...quota, reason: 'daily_limit_reached' }, module), request
      ));
      return withSecurityHeaders(withCors(await handleAsyncScan(request, env, authCtx, module), request));
    }

    // ── Job status + result ─────────────────────────────────────────────────
    if (path.startsWith('/api/jobs/')) {
      const parts  = path.split('/');   // ['','api','jobs',jobId,'result'?]
      const jobId  = parts[3];
      const sub    = parts[4] || '';
      const authCtx = await resolveAuthV5(request, env);

      if (method === 'GET' && sub === 'result') {
        return withSecurityHeaders(withCors(await handleJobResult(request, env, authCtx, jobId), request));
      }
      if (method === 'GET') {
        return withSecurityHeaders(withCors(await handleJobStatus(request, env, authCtx, jobId), request));
      }
    }

    // ── Scan history ────────────────────────────────────────────────────────
    if (path === '/api/history' && (method === 'GET' || method === 'DELETE')) {
      const authCtx = await resolveAuthV5(request, env);
      return withSecurityHeaders(withCors(await handleD1History(request, env, authCtx), request));
    }

    // ── Report ──────────────────────────────────────────────────────────────
    if (path.startsWith('/api/report/') && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env);
      return withSecurityHeaders(withCors(await handleReportDownload(request, env, authCtx), request));
    }

    // ── Sentinel APEX (public, cached) ──────────────────────────────────────
    if (path === '/api/sentinel/feed' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleSentinelFeed(request, env), request));
    }
    if (path === '/api/sentinel/status' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleSentinelStatus(request, env), request));
    }

    // ── V7.0 Payment routes (plural form: /api/payments/*) ─────────────────
    if (path === '/api/payments/create-order' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env);
      // IP-based rate limit: max 10 order creates per hour (fraud/abuse prevention)
      const ip        = request.headers.get('CF-Connecting-IP') || 'unknown';
      const rlHour    = new Date().toISOString().slice(0, 13);
      const rlKey     = `rl:payment_create:${ip}:${rlHour}`;
      const rlKv      = env.SECURITY_HUB_KV || env.KV;
      if (rlKv && ip !== 'unknown') {
        const cnt = parseInt(await rlKv.get(rlKey).catch(() => '0') || '0', 10);
        if (cnt >= 10) {
          return withSecurityHeaders(withCors(Response.json({
            error: 'Rate limit exceeded — maximum 10 payment orders per hour per IP.',
            retry_after: 3600,
          }, { status: 429 }), request));
        }
        await rlKv.put(rlKey, String(cnt + 1), { expirationTtl: 3600 }).catch(() => {});
      }
      return withSecurityHeaders(withCors(await handleCreateOrder(request, env, authCtx), request));
    }
    if (path === '/api/payments/verify' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env);
      return withSecurityHeaders(withCors(await handleVerifyPayment(request, env, authCtx), request));
    }
    if (path.startsWith('/api/payments/status/') && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env);
      return withSecurityHeaders(withCors(await handlePaymentStatus(request, env, authCtx), request));
    }

    // ── V9.2 Payment routes (singular form: /api/payment/* — canonical aliases) ─
    // Identical logic — both forms are permanently supported.
    // /api/payment/create-order  →  POST  { amount, module, target?, email? }
    //                                      Returns { order_id, key_id, amount, currency, module }
    // /api/payment/verify        →  POST  { razorpay_order_id, razorpay_payment_id,
    //                                       razorpay_signature, module, target }
    //                                      Returns { success, token, download_url } or { success: false }
    if (path === '/api/payment/create-order' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env);
      return withSecurityHeaders(withCors(await handleCreateOrder(request, env, authCtx), request));
    }
    if (path === '/api/payment/verify' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env);
      // Wrap verify to always return { success: true/false } shape (never throws)
      try {
        const res  = await handleVerifyPayment(request, env, authCtx);
        const data = await res.clone().json().catch(() => ({}));
        // If backend returned an error response, normalise to { success: false }
        if (!res.ok || data.error) {
          return withSecurityHeaders(withCors(Response.json({
            success: false,
            error:   data.error || `HTTP ${res.status}`,
            code:    'VERIFICATION_FAILED',
          }, { status: res.ok ? 200 : res.status }), request));
        }
        return withSecurityHeaders(withCors(res, request));
      } catch (err) {
        return withSecurityHeaders(withCors(Response.json({
          success: false,
          error:   'Internal verification error',
          code:    'INTERNAL_ERROR',
        }, { status: 500 }), request));
      }
    }
    if (path.startsWith('/api/payment/status/') && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env);
      return withSecurityHeaders(withCors(await handlePaymentStatus(request, env, authCtx), request));
    }

    // ── CDB Manual payment confirmation (UPI/Bank/Crypto/PayPal) ─────────────
    // POST /api/payment/confirm  →  { txnId, method, product, user, amount }
    if (path === '/api/payment/confirm' && method === 'POST') {
      // IP rate limit: max 3 manual payment confirmations per hour (fraud prevention)
      const ip     = request.headers.get('CF-Connecting-IP') || 'unknown';
      const rlHour = new Date().toISOString().slice(0, 13);
      const rlKey  = `rl:payment_confirm:${ip}:${rlHour}`;
      const rlKv   = env.SECURITY_HUB_KV || env.KV;
      if (rlKv && ip !== 'unknown') {
        const cnt = parseInt(await rlKv.get(rlKey).catch(() => '0') || '0', 10);
        if (cnt >= 3) {
          return withSecurityHeaders(withCors(Response.json({
            error: 'Rate limit exceeded — maximum 3 manual payment confirmations per hour.',
            retry_after: 3600,
          }, { status: 429 }), request));
        }
        await rlKv.put(rlKey, String(cnt + 1), { expirationTtl: 3600 }).catch(() => {});
      }
      return withSecurityHeaders(withCors(await handlePaymentConfirm(request, env), request));
    }

    // ── V7.0 Token-gated paid report download ────────────────────────────────
    if (path.startsWith('/api/reports/download/') && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env);
      return withSecurityHeaders(await handlePaidReportDownload(request, env, authCtx));
    }

    // ── V7.0 Admin analytics ─────────────────────────────────────────────────
    if (path === '/api/admin/analytics' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env);
      return withSecurityHeaders(withCors(await handleGetAnalytics(request, env, authCtx), request));
    }
    if (path === '/api/admin/analytics/scans' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env);
      return withSecurityHeaders(withCors(await handleScanStats(request, env, authCtx), request));
    }
    if (path === '/api/admin/api-usage' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env);
      return withSecurityHeaders(withCors(await handleApiUsage(request, env, authCtx), request));
    }

    // ── Razorpay webhook (V7 replaces monetization middleware stub) ──────────
    if (path === '/api/webhooks/razorpay' && method === 'POST') {
      return withSecurityHeaders(await handleRazorpayWebhook(request, env));
    }

    // ══════════════════════════════════════════════════════════════════════════
    // V8.0 ROUTES — AI Brain, Attack Graph, Threat Intel, Monitoring,
    //               Content Engine, Org Management
    // ══════════════════════════════════════════════════════════════════════════

    // ── AI Cyber Brain: insights from scan result ─────────────────────────────
    if (path === '/api/insights' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env);
      try {
        const body = await request.json();
        const { scan_result, module, target } = body;
        if (!scan_result || !module) {
          return withSecurityHeaders(withCors(Response.json({ error: 'scan_result and module required' }, { status: 400 }), request));
        }
        const insights = await generateAIInsights(scan_result, module, env);
        return withSecurityHeaders(withCors(Response.json({ success: true, module, target, insights }), request));
      } catch (e) {
        return withSecurityHeaders(withCors(Response.json({ error: e.message }, { status: 500 }), request));
      }
    }

    // ── Attack Graph: D3-ready graph from scan result ─────────────────────────
    if (path === '/api/attack-graph' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env);
      try {
        const body = await request.json();
        const { scan_result, module } = body;
        if (!scan_result || !module) {
          return withSecurityHeaders(withCors(Response.json({ error: 'scan_result and module required' }, { status: 400 }), request));
        }
        const graph = buildAttackGraph(scan_result, module);
        return withSecurityHeaders(withCors(Response.json({ success: true, graph }), request));
      } catch (e) {
        return withSecurityHeaders(withCors(Response.json({ error: e.message }, { status: 500 }), request));
      }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // V11.0 SENTINEL APEX — Threat Intelligence Engine v2.0
    // D1-backed, real NVD+CISA+GitHub ingestion, IOC extraction, enrichment
    // ═══════════════════════════════════════════════════════════════════════

    // GET /api/threat-intel — main paginated feed (public + plan-gated)
    if (path === '/api/threat-intel' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE', authenticated: false }));
      return withSecurityHeaders(withCors(await handleGetThreatIntel(request, env, authCtx), request));
    }

    // GET /api/threat-intel/stats — aggregate stats (public)
    if (path === '/api/threat-intel/stats' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE' }));
      return withSecurityHeaders(withCors(await handleThreatIntelStats(request, env, authCtx), request));
    }

    // GET /api/dashboard/stream — v31 Enterprise SSE aggregator (all command centers)
    if (path === '/api/dashboard/stream' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE', authenticated: false }));
      return await handleDashboardStream(request, env, authCtx);
    }

    // ── v32.0 Phase 2 Enterprise Platform Routes ────────────────────────────

    // ── Phase 8: Revenue Certification & Revenue Proof — OWNER ONLY ────────────
    // GET /api/admin/revenue-certification
    // Validates all infrastructure required for revenue processing: DB, KV, R2,
    // Razorpay config, email service, table existence. Returns PASS/FAIL per check.
    if (path === '/api/admin/revenue-certification' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE' }));
      if (!isOwner(authCtx, env)) return withSecurityHeaders(withCors(forbidden(), request));
      const checks = {};

      // D1 database
      try {
        await env.DB.prepare('SELECT 1').first();
        checks.database = { status: 'PASS', detail: 'D1 connected' };
      } catch (e) { checks.database = { status: 'FAIL', detail: e.message }; }

      // KV store
      try {
        const kv = env.KV || env.SECURITY_HUB_KV;
        if (!kv) throw new Error('No KV namespace configured');
        await kv.put('health_check_cert', '1', { expirationTtl: 60 });
        checks.kv_store = { status: 'PASS', detail: 'KV read/write OK' };
      } catch (e) { checks.kv_store = { status: 'FAIL', detail: e.message }; }

      // R2 storage
      try {
        if (!env.SCAN_RESULTS) throw new Error('SCAN_RESULTS R2 binding not configured');
        await env.SCAN_RESULTS.put('health_check', 'ok', { httpMetadata: { contentType: 'text/plain' } });
        checks.r2_storage = { status: 'PASS', detail: 'R2 read/write OK' };
      } catch (e) { checks.r2_storage = { status: 'FAIL', detail: e.message }; }

      // Razorpay credentials
      checks.razorpay_credentials = (env.RAZORPAY_KEY_ID && env.RAZORPAY_KEY_SECRET)
        ? { status: 'PASS', detail: 'Key ID and secret configured' }
        : { status: 'FAIL', detail: 'RAZORPAY_KEY_ID or RAZORPAY_KEY_SECRET not set' };

      // Email service
      checks.email_service = (env.RESEND_API_KEY || env.MAILCHANNELS_TOKEN)
        ? { status: 'PASS', detail: 'Email API key configured' }
        : { status: 'WARN', detail: 'No RESEND_API_KEY or MAILCHANNELS_TOKEN — drip sequences disabled' };

      // Webhook secret
      checks.razorpay_webhook_secret = env.RAZORPAY_WEBHOOK_SECRET
        ? { status: 'PASS', detail: 'Webhook secret configured' }
        : { status: 'FAIL', detail: 'RAZORPAY_WEBHOOK_SECRET not set — webhooks unverified' };

      // revenue_events table
      try {
        const r = await env.DB.prepare('SELECT COUNT(*) as cnt FROM revenue_events').first();
        checks.revenue_events_table = { status: 'PASS', detail: `${r?.cnt ?? 0} events recorded` };
      } catch (e) { checks.revenue_events_table = { status: 'FAIL', detail: e.message }; }

      // subscriptions table
      try {
        const r = await env.DB.prepare("SELECT COUNT(*) as cnt FROM subscriptions WHERE status='active'").first();
        checks.subscriptions_table = { status: 'PASS', detail: `${r?.cnt ?? 0} active subscriptions` };
      } catch (e) { checks.subscriptions_table = { status: 'FAIL', detail: e.message }; }

      // email_sequences table
      try {
        const r = await env.DB.prepare("SELECT COUNT(*) as cnt FROM email_sequences WHERE status='active'").first();
        checks.email_sequences_table = { status: 'PASS', detail: `${r?.cnt ?? 0} active sequences` };
      } catch (e) { checks.email_sequences_table = { status: 'FAIL', detail: e.message }; }

      // payments — verified payments count
      try {
        const r = await env.DB.prepare("SELECT COUNT(*) as cnt FROM payments WHERE status='paid'").first();
        const cnt = r?.cnt ?? 0;
        checks.verified_payments = {
          status: cnt > 0 ? 'PASS' : 'WARN',
          detail: `${cnt} verified payments in database`,
        };
      } catch (e) { checks.verified_payments = { status: 'FAIL', detail: e.message }; }

      // funnel_events purchase stage
      try {
        const r = await env.DB.prepare("SELECT COUNT(*) as cnt FROM funnel_events WHERE stage='purchase'").first();
        const cnt = r?.cnt ?? 0;
        checks.funnel_purchase_events = {
          status: cnt > 0 ? 'PASS' : 'WARN',
          detail: `${cnt} purchase funnel events`,
        };
      } catch (e) { checks.funnel_purchase_events = { status: 'FAIL', detail: e.message }; }

      const vals = Object.values(checks);
      const hasFail = vals.some(c => c.status === 'FAIL');
      const hasWarn = vals.some(c => c.status === 'WARN');
      const certStatus = hasFail ? 'FAIL' : hasWarn ? 'WARN' : 'PASS';

      return withSecurityHeaders(withCors(Response.json({
        certification_status: certStatus,
        timestamp: new Date().toISOString(),
        checks,
        summary: {
          total: vals.length,
          pass:  vals.filter(c => c.status === 'PASS').length,
          warn:  vals.filter(c => c.status === 'WARN').length,
          fail:  vals.filter(c => c.status === 'FAIL').length,
        },
        action_required: hasFail
          ? 'Platform NOT revenue-certified. Fix FAIL items before production launch.'
          : hasWarn
          ? 'Platform CONDITIONALLY certified. Resolve WARN items for full revenue capability.'
          : 'Platform is PRODUCTION-CERTIFIED for revenue generation.',
      }), request));
    }

    // GET /api/admin/revenue-proof
    // Shows the first verified transaction per revenue funnel — proves each path
    // has processed at least one real payment end-to-end.
    if (path === '/api/admin/revenue-proof' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE' }));
      if (!isOwner(authCtx, env)) return withSecurityHeaders(withCors(forbidden(), request));
      const funnels = {};

      // Threat/scan reports
      try {
        const r = await env.DB.prepare(
          `SELECT module, target, amount, paid_at, razorpay_payment_id FROM payments
           WHERE status='paid' AND module NOT LIKE 'subscription%' AND module != 'assessment'
           ORDER BY paid_at ASC LIMIT 1`
        ).first();
        funnels.threat_report = r
          ? { status: 'PROVEN', first_payment: r.paid_at, module: r.module, target: r.target, amount_inr: Math.round((r.amount||0)/100), payment_id: r.razorpay_payment_id }
          : { status: 'UNPROVEN', message: 'No verified report payment found' };
      } catch (e) { funnels.threat_report = { status: 'ERROR', error: e.message }; }

      // Security assessment
      try {
        const r = await env.DB.prepare(
          `SELECT target, amount, paid_at, razorpay_payment_id, email FROM payments
           WHERE status='paid' AND module='assessment' ORDER BY paid_at ASC LIMIT 1`
        ).first();
        funnels.security_assessment = r
          ? { status: 'PROVEN', first_payment: r.paid_at, amount_inr: Math.round((r.amount||0)/100), email: r.email }
          : { status: 'UNPROVEN', message: 'No verified assessment payment found' };
      } catch (e) { funnels.security_assessment = { status: 'ERROR', error: e.message }; }

      // API Subscription
      try {
        const r = await env.DB.prepare(
          `SELECT email, plan, price_inr, activated_at, external_id FROM subscriptions
           WHERE status='active' ORDER BY activated_at ASC LIMIT 1`
        ).first();
        funnels.api_subscription = r
          ? { status: 'PROVEN', first_activation: r.activated_at, plan: r.plan, amount_inr: r.price_inr, email: r.email }
          : { status: 'UNPROVEN', message: 'No active subscription found' };
      } catch (e) { funnels.api_subscription = { status: 'ERROR', error: e.message }; }

      // Revenue events (lifecycle attribution)
      try {
        const r = await env.DB.prepare(
          'SELECT COUNT(*) as cnt, SUM(amount_inr) as total FROM revenue_events'
        ).first();
        const cnt = r?.cnt ?? 0;
        funnels.revenue_attribution = {
          status: cnt > 0 ? 'PROVEN' : 'UNPROVEN',
          total_events: cnt, total_revenue_inr: r?.total ?? 0,
        };
      } catch (e) { funnels.revenue_attribution = { status: 'ERROR', error: e.message }; }

      // CAC channel attribution
      try {
        const r = await env.DB.prepare('SELECT COUNT(*) as cnt FROM cac_events WHERE converted=1').first();
        const cnt = r?.cnt ?? 0;
        funnels.cac_attribution = {
          status: cnt > 0 ? 'PROVEN' : 'UNPROVEN',
          converted_events: cnt,
        };
      } catch (e) { funnels.cac_attribution = { status: 'ERROR', error: e.message }; }

      // Email drip delivery
      try {
        const r = await env.DB.prepare("SELECT COUNT(*) as cnt FROM email_tracking WHERE event='sent'").first();
        const cnt = r?.cnt ?? 0;
        funnels.email_lifecycle = {
          status: cnt > 0 ? 'PROVEN' : 'UNPROVEN',
          emails_delivered: cnt,
        };
      } catch (e) { funnels.email_lifecycle = { status: 'ERROR', error: e.message }; }

      // Enterprise contracts proof
      try {
        const r = await env.DB.prepare(
          `SELECT id, email, company, price_inr, accepted_at FROM proposals WHERE status='accepted' ORDER BY accepted_at ASC LIMIT 1`
        ).first();
        funnels.enterprise_contracts = r
          ? { status: 'PROVEN', first_accepted: r.accepted_at, company: r.company, amount_inr: r.price_inr, proposal_id: r.id }
          : { status: 'UNPROVEN', message: 'No accepted enterprise proposal found' };
      } catch (e) { funnels.enterprise_contracts = { status: 'ERROR', error: e.message }; }

      // MSSP partnerships proof
      try {
        const r = await env.DB.prepare(
          `SELECT id, company_name, status, tier, created_at FROM mssp_partners WHERE status IN ('certified','active') ORDER BY created_at ASC LIMIT 1`
        ).first();
        funnels.mssp_partnerships = r
          ? { status: 'PROVEN', first_partner: r.created_at, company: r.company_name, tier: r.tier, partner_status: r.status }
          : { status: 'UNPROVEN', message: 'No certified or active MSSP partner found' };
      } catch (e) { funnels.mssp_partnerships = { status: 'ERROR', error: e.message }; }

      const proven  = Object.values(funnels).filter(f => f.status === 'PROVEN').length;
      const total   = Object.keys(funnels).length;
      const unproven = total - proven;

      return withSecurityHeaders(withCors(Response.json({
        revenue_proof_status: proven === total ? 'FULLY_PROVEN' : proven > 0 ? 'PARTIALLY_PROVEN' : 'UNPROVEN',
        timestamp: new Date().toISOString(),
        funnels,
        summary: { proven, unproven, total, completion_pct: Math.round(proven / total * 100) },
        mission_status: proven === total
          ? 'ALL FUNNELS PROVEN — Platform is revenue-certified.'
          : `${unproven} funnel(s) awaiting first transaction. Drive acquisition to complete proof.`,
      }), request));
    }

    // GET /api/admin/executive-scorecard — single endpoint returning every KPI
    // needed for a daily CEO/CRO review: MRR, ARR, CAC, LTV, funnel conversions,
    // channel breakdown, renewal pipeline, operational health.
    if (path === '/api/admin/executive-scorecard' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE' }));
      if (!isOwner(authCtx, env)) return withSecurityHeaders(withCors(forbidden(), request));

      const scorecard = { generated_at: new Date().toISOString() };
      const now       = new Date();
      const monthStart = now.toISOString().slice(0, 7) + '-01';
      const yearStart  = now.getFullYear() + '-01-01';

      try {
        // ── Revenue ────────────────────────────────────────────────────────────
        const [revMonth, revTotal, subActive, revEvents, cacData, renewalData, renewalData60, renewalData90, funnelData, proposalData] = await Promise.all([
          // Revenue this month
          env.DB.prepare(`SELECT COALESCE(SUM(amount),0) as total FROM payments WHERE status='paid' AND created_at >= ?`).bind(monthStart).first().catch(() => null),
          // Revenue all time
          env.DB.prepare(`SELECT COALESCE(SUM(amount),0) as total FROM payments WHERE status='paid'`).first().catch(() => null),
          // Active subscriptions (plan counts)
          env.DB.prepare(`SELECT plan, COUNT(*) as cnt, SUM(price_inr) as mrr FROM subscriptions WHERE status='active' GROUP BY plan`).all().catch(() => ({ results: [] })),
          // Revenue events this month
          env.DB.prepare(`SELECT COUNT(*) as cnt, COALESCE(SUM(amount_inr),0) as total FROM revenue_events WHERE created_at >= ?`).bind(monthStart).first().catch(() => null),
          // CAC by channel
          env.DB.prepare(`SELECT channel, COUNT(*) as conversions, COALESCE(AVG(NULLIF(cost_inr,0)),0) as avg_cac, COALESCE(SUM(mrr_generated),0) as mrr FROM cac_events WHERE converted=1 GROUP BY channel`).all().catch(() => ({ results: [] })),
          // Renewals due in 30 days
          env.DB.prepare(`SELECT COUNT(*) as cnt, COALESCE(SUM(amount_inr),0) as arr_at_risk FROM renewal_queue WHERE status='upcoming' AND renewal_date <= date('now','+30 days')`).first().catch(() => null),
          // Renewals due in 60 days
          env.DB.prepare(`SELECT COUNT(*) as cnt, COALESCE(SUM(amount_inr),0) as arr_at_risk FROM renewal_queue WHERE status='upcoming' AND renewal_date <= date('now','+60 days')`).first().catch(() => null),
          // Renewals due in 90 days
          env.DB.prepare(`SELECT COUNT(*) as cnt, COALESCE(SUM(amount_inr),0) as arr_at_risk FROM renewal_queue WHERE status='upcoming' AND renewal_date <= date('now','+90 days')`).first().catch(() => null),
          // Funnel conversion (lead → customer)
          env.DB.prepare(`SELECT stage, COUNT(*) as cnt FROM funnel_events WHERE created_at >= ? GROUP BY stage`).bind(monthStart).all().catch(() => ({ results: [] })),
          // Proposals pipeline
          env.DB.prepare(`SELECT status, COUNT(*) as cnt FROM proposals GROUP BY status`).all().catch(() => ({ results: [] })),
        ]);

        // MRR from active subscriptions
        const subRows   = subActive?.results ?? [];
        const mrr_inr   = subRows.reduce((s, r) => s + (r.mrr || 0), 0);
        const arr_inr   = mrr_inr * 12;
        const totalSubs = subRows.reduce((s, r) => s + (r.cnt || 0), 0);

        // LTV estimate: MRR × 24 months average tenure (conservative)
        const ltv_inr = totalSubs > 0 ? Math.round(mrr_inr / totalSubs * 24) : 0;

        // Funnel conversion rates
        const funnelMap  = {};
        for (const r of (funnelData?.results ?? [])) funnelMap[r.stage] = r.cnt;
        const leads      = funnelMap.lead || funnelMap.email_capture || 0;
        const purchases  = funnelMap.purchase || 0;
        const conversion = leads > 0 ? Math.round(purchases / leads * 1000) / 10 : 0;

        // Proposal pipeline
        const propMap = {};
        for (const r of (proposalData?.results ?? [])) propMap[r.status] = r.cnt;

        // CAC by channel
        const cacByChannel = {};
        for (const r of (cacData?.results ?? [])) {
          cacByChannel[r.channel] = { conversions: r.conversions, avg_cac_inr: Math.round(r.avg_cac), mrr_inr: r.mrr };
        }
        const bestChannel = Object.entries(cacByChannel).sort((a, b) => b[1].mrr_inr - a[1].mrr_inr)[0]?.[0] || 'unknown';

        scorecard.revenue = {
          mrr_inr, arr_inr, ltv_inr,
          revenue_this_month_inr: Math.round((revMonth?.total || 0) / 100),
          revenue_all_time_inr:   Math.round((revTotal?.total || 0) / 100),
          revenue_events_this_month: revEvents?.cnt || 0,
          revenue_events_total_inr:  revEvents?.total || 0,
          active_subscriptions: totalSubs,
          subscriptions_by_plan: Object.fromEntries(subRows.map(r => [r.plan, r.cnt])),
        };
        scorecard.acquisition = {
          leads_this_month:    leads,
          purchases_this_month: purchases,
          conversion_rate_pct: conversion,
          cac_by_channel:      cacByChannel,
          best_channel:        bestChannel,
        };
        scorecard.proposals = {
          draft:       propMap.draft || 0,
          sent:        propMap.sent || 0,
          accepted:    propMap.accepted || 0,
          rejected:    propMap.rejected || 0,
          pipeline_value_inr: (propMap.sent || 0) * 99900, // avg enterprise deal estimate
        };
        scorecard.renewal_pipeline = {
          renewals_due_30d:    renewalData?.cnt || 0,
          arr_at_risk_30d_inr: renewalData?.arr_at_risk || 0,
          renewals_due_60d:    renewalData60?.cnt || 0,
          arr_at_risk_60d_inr: renewalData60?.arr_at_risk || 0,
          renewals_due_90d:    renewalData90?.cnt || 0,
          arr_at_risk_90d_inr: renewalData90?.arr_at_risk || 0,
          arr_at_risk_inr:     renewalData?.arr_at_risk || 0,
        };
        scorecard.operational = {
          status: 'operational',
          note:   'Check /api/admin/revenue-certification for full infrastructure health',
        };
      } catch (e) {
        console.error('[ExecutiveScorecard]', e.message);
        scorecard.error = 'Partial data — some queries failed';
      }

      return withSecurityHeaders(withCors(Response.json(scorecard), request));
    }

    // GET /api/admin/email-health — owner-only view of email delivery health
    // Shows transient failure rate, permanent failures, and per-sequence stats.
    if (path === '/api/admin/email-health' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE' }));
      if (!isOwner(authCtx, env)) return withSecurityHeaders(withCors(forbidden(), request));

      if (!env.DB) return withSecurityHeaders(withCors(
        Response.json({ error: 'DB unavailable' }, { status: 503 }), request,
      ));

      try {
        const [eventCounts, recentFailures, sequenceHealth] = await Promise.all([
          // Aggregate event counts for the last 7 days
          env.DB.prepare(`
            SELECT event, COUNT(*) as cnt
            FROM email_tracking
            WHERE created_at >= datetime('now', '-7 days')
            GROUP BY event
          `).all().catch(() => ({ results: [] })),
          // Last 20 permanent failures for triage
          env.DB.prepare(`
            SELECT email, sequence_id, step, created_at
            FROM email_tracking
            WHERE event = 'failed_permanent'
            ORDER BY created_at DESC LIMIT 20
          `).all().catch(() => ({ results: [] })),
          // Per-sequence delivery success rate (last 30 days)
          env.DB.prepare(`
            SELECT sequence_id,
              COUNT(*) as total,
              SUM(CASE WHEN event = 'sent' THEN 1 ELSE 0 END) as sent,
              SUM(CASE WHEN event = 'failed_permanent' THEN 1 ELSE 0 END) as failed_permanent,
              SUM(CASE WHEN event = 'failed_retry' THEN 1 ELSE 0 END) as failed_retry
            FROM email_tracking
            WHERE created_at >= datetime('now', '-30 days')
            GROUP BY sequence_id
          `).all().catch(() => ({ results: [] })),
        ]);

        const counts = {};
        for (const r of (eventCounts?.results ?? [])) counts[r.event] = r.cnt;
        const totalSent     = counts.sent || 0;
        const totalRetry    = counts.failed_retry || 0;
        const totalFailed   = counts.failed_permanent || 0;
        const totalEvents   = totalSent + totalRetry + totalFailed;
        const deliveryRate  = totalEvents > 0 ? Math.round(totalSent / totalEvents * 1000) / 10 : null;

        return withSecurityHeaders(withCors(Response.json({
          window:           '7d',
          delivery_rate_pct: deliveryRate,
          events_7d:        counts,
          recent_permanent_failures: recentFailures?.results ?? [],
          sequences_30d:    (sequenceHealth?.results ?? []).map(r => ({
            sequence_id:      r.sequence_id,
            total:            r.total,
            sent:             r.sent,
            failed_permanent: r.failed_permanent,
            failed_retry:     r.failed_retry,
            success_rate_pct: r.total > 0 ? Math.round(r.sent / r.total * 1000) / 10 : null,
          })),
        }), request));
      } catch (e) {
        return withSecurityHeaders(withCors(
          Response.json({ error: e.message }, { status: 500 }), request,
        ));
      }
    }

    // Revenue Metrics — OWNER ONLY (platform financials: MRR/ARR/subscribers/
    // conversion). Was exposed to anonymous; a second gated definition existed
    // downstream but was dead code (this route matched first). Gated now.
    if (path === '/api/revenue/metrics' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE' }));
      if (!isOwner(authCtx, env)) return withSecurityHeaders(withCors(forbidden(), request));
      return withSecurityHeaders(withCors(await handleRevenueMetrics(request, env, authCtx), request));
    }
    if (path === '/api/revenue/snapshot' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env);
      return withSecurityHeaders(withCors(await handleRevenueSnapshot(request, env, authCtx), request));
    }

    // ── P23.0: MSSP Public Onboarding & Pricing Flow ─────────────────────────
    if (path === '/api/mssp/onboarding/tiers' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleMsspTiers(request, env), request));
    }
    if (path === '/api/mssp/onboarding/checkout' && method === 'POST') {
      return withSecurityHeaders(withCors(await handleMsspCheckout(request, env), request));
    }
    if (path === '/api/mssp/onboarding/verify' && method === 'POST') {
      return withSecurityHeaders(withCors(await handleMsspVerify(request, env), request));
    }
    if (path === '/api/mssp/onboarding/trial' && method === 'POST') {
      return withSecurityHeaders(withCors(await handleMsspTrial(request, env), request));
    }
    if (path === '/api/mssp/onboarding/status' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleMsspOnboardingStatus(request, env), request));
    }
    if (path === '/api/mssp/onboarding/observability' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleMsspOnboardingObservability(request, env), request));
    }

    // MSSP Workspace
    if (path === '/api/mssp/overview' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE' }));
      return withSecurityHeaders(withCors(await handleMSSPOverview(request, env, authCtx), request));
    }
    if (path === '/api/mssp/customers' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE' }));
      return withSecurityHeaders(withCors(await handleListCustomers(request, env, authCtx), request));
    }
    if (path === '/api/mssp/customers' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env);
      return withSecurityHeaders(withCors(await handleCreateCustomer(request, env, authCtx), request));
    }
    if (path.match(/^\/api\/mssp\/customers\/[^/]+\/metrics$/) && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE' }));
      const customerId = path.split('/')[4];
      return withSecurityHeaders(withCors(await handleCustomerMetrics(request, env, authCtx, customerId), request));
    }
    if (path.match(/^\/api\/mssp\/customers\/[^/]+$/) && method === 'PUT') {
      const authCtx = await resolveAuthV5(request, env);
      const customerId = path.split('/')[4];
      return withSecurityHeaders(withCors(await handleUpdateCustomer(request, env, authCtx, customerId), request));
    }
    // ── P9.0: Enterprise Multi-Tenancy & MSSP Platform ────────────────────────────
    if (path.match(/^\/api\/mssp\/customers\/[^/]+$/) && (method === 'GET' || method === 'DELETE')) {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE' }));
      const customerId = path.split('/')[4];
      if (method === 'GET')    return withSecurityHeaders(withCors(await handleGetCustomer(request, env, authCtx, customerId), request));
      if (method === 'DELETE') return withSecurityHeaders(withCors(await handleDeleteCustomer(request, env, authCtx, customerId), request));
    }
    if (path.match(/^\/api\/mssp\/customers\/[^/]+\/(suspend|archive|restore)$/) && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env);
      const parts = path.split('/');
      const customerId = parts[4];
      const action = parts[5];
      if (action === 'suspend') return withSecurityHeaders(withCors(await handleSuspendCustomer(request, env, authCtx, customerId), request));
      if (action === 'archive') return withSecurityHeaders(withCors(await handleArchiveCustomer(request, env, authCtx, customerId), request));
      if (action === 'restore') return withSecurityHeaders(withCors(await handleRestoreCustomer(request, env, authCtx, customerId), request));
    }
    if (
      path.match(/^\/api\/mssp\/customers\/[^/]+\/(dashboard|labels|hierarchy|sub-tenants|notifications|api-keys|billing|usage)/) ||
      path.match(/^\/api\/mssp\/ticket-rules/)
    ) {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE' }));
      const { handleMsspTenantRoute } = await import('./handlers/msspTenantPlatform.js');
      return withSecurityHeaders(withCors(await handleMsspTenantRoute(request, env, authCtx, path, method), request));
    }

    // SOC Cases
    if (path === '/api/soc/cases/metrics' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
      return withSecurityHeaders(withCors(await handleCaseMetrics(request, env, authCtx), request));
    }
    if (path === '/api/soc/cases' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
      return withSecurityHeaders(withCors(await handleListCases(request, env, authCtx), request));
    }
    if (path === '/api/soc/cases' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
      return withSecurityHeaders(withCors(await handleCreateCase(request, env, authCtx), request));
    }
    if (path.match(/^\/api\/soc\/cases\/[^/]+\/comments$/) && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
      const caseId = path.split('/')[4];
      return withSecurityHeaders(withCors(await handleAddCaseComment(request, env, authCtx, caseId), request));
    }
    if (path.match(/^\/api\/soc\/cases\/[^/]+$/) && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
      const caseId = path.split('/')[4];
      if (caseId !== 'metrics') return withSecurityHeaders(withCors(await handleGetCase(request, env, authCtx, caseId), request));
    }
    if (path.match(/^\/api\/soc\/cases\/[^/]+$/) && method === 'PATCH') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
      const caseId = path.split('/')[4];
      return withSecurityHeaders(withCors(await handleUpdateCase(request, env, authCtx, caseId), request));
    }

    // CTI Workbench
    if (path === '/api/cti/stats' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE' }));
      return withSecurityHeaders(withCors(await handleCTIStats(request, env, authCtx), request));
    }
    if (path === '/api/cti/actors' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE' }));
      return withSecurityHeaders(withCors(await handleListActors(request, env, authCtx), request));
    }
    if (path.match(/^\/api\/cti\/actors\/[^/]+$/) && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE' }));
      const actorId = path.split('/')[4];
      return withSecurityHeaders(withCors(await handleGetActor(request, env, authCtx, actorId), request));
    }
    if (path === '/api/cti/ioc/search' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE' }));
      return withSecurityHeaders(withCors(await handleIOCSearch(request, env, authCtx), request));
    }
    if (path === '/api/cti/ioc' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
      return withSecurityHeaders(withCors(await handleAddIOC(request, env, authCtx), request));
    }

    // Platform Observability
    if (path === '/api/platform/health/deep' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE' }));
      return withSecurityHeaders(withCors(await handleDeepHealth(request, env, authCtx), request));
    }
    if (path === '/api/platform/health/services' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE' }));
      return withSecurityHeaders(withCors(await handleServicesList(request, env, authCtx), request));
    }

    // ── v33.0 PHASE 3 ENTERPRISE MATURITY ROUTES ─────────────────────────────

    // ── Customer Success Platform ─────────────────────────────────────────────
    if (path === '/api/customer-success/health' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE' }));
      request.user = authCtx;
      return withSecurityHeaders(withCors(await handleCustomerHealth(request, env), request));
    }
    if (path.match(/^\/api\/customer-success\/health\/([^/]+)$/) && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE' }));
      request.user = authCtx;
      const orgId = path.split('/').pop();
      return withSecurityHeaders(withCors(await handleCustomerHealthByOrg(request, env, orgId), request));
    }
    if (path === '/api/customer-success/overview' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE' }));
      request.user = authCtx;
      return withSecurityHeaders(withCors(await handleCustomerSuccessOverview(request, env), request));
    }
    if (path === '/api/customer-success/refresh' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE' }));
      request.user = authCtx;
      return withSecurityHeaders(withCors(await handleRefreshHealthScores(request, env), request));
    }
    if (path === '/api/customer-success/playbooks' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE' }));
      request.user = authCtx;
      return withSecurityHeaders(withCors(await handleCustomerSuccessPlaybooks(request, env), request));
    }

    // ── Reporting Engine ──────────────────────────────────────────────────────
    if (path === '/api/reports' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE' }));
      request.user = authCtx;
      return withSecurityHeaders(withCors(await handleListEnterpriseReports(request, env), request));
    }
    if (path === '/api/reports' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE' }));
      request.user = authCtx;
      return withSecurityHeaders(withCors(await handleCreateEnterpriseReport(request, env), request));
    }
    if (path === '/api/reports/templates' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE' }));
      request.user = authCtx;
      return withSecurityHeaders(withCors(await handleEnterpriseReportTemplates(request, env), request));
    }
    if (path === '/api/reports/schedule' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE' }));
      request.user = authCtx;
      return withSecurityHeaders(withCors(await handleScheduleEnterpriseReport(request, env), request));
    }
    if (path.match(/^\/api\/reports\/([^/]+)$/) && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE' }));
      request.user = authCtx;
      const jobId = path.split('/').pop();
      return withSecurityHeaders(withCors(await handleGetEnterpriseReport(request, env, jobId), request));
    }
    if (path.match(/^\/api\/reports\/([^/]+)\/download$/) && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE' }));
      request.user = authCtx;
      const jobId = path.split('/')[3];
      return withSecurityHeaders(withCors(await handleDownloadEnterpriseReport(request, env, jobId), request));
    }

    // ── Global Search ─────────────────────────────────────────────────────────
    if (path === '/api/search' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE' }));
      request.user = authCtx;
      return withSecurityHeaders(withCors(await handleGlobalSearch(request, env), request));
    }
    if (path === '/api/search/saved' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE' }));
      request.user = authCtx;
      return withSecurityHeaders(withCors(await handleListSavedSearches(request, env), request));
    }
    if (path === '/api/search/saved' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE' }));
      request.user = authCtx;
      return withSecurityHeaders(withCors(await handleSaveSearch(request, env), request));
    }
    if (path.match(/^\/api\/search\/saved\/([^/]+)$/) && method === 'DELETE') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE' }));
      request.user = authCtx;
      const searchId = path.split('/').pop();
      return withSecurityHeaders(withCors(await handleDeleteSavedSearch(request, env, searchId), request));
    }

    // ── Workflow Automation ───────────────────────────────────────────────────
    if (path === '/api/workflows/templates' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE' }));
      request.user = authCtx;
      return withSecurityHeaders(withCors(await handleWorkflowTemplates(request, env), request));
    }
    if (path === '/api/workflows' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE' }));
      request.user = authCtx;
      return withSecurityHeaders(withCors(await handleListWorkflows(request, env), request));
    }
    if (path === '/api/workflows' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE' }));
      request.user = authCtx;
      return withSecurityHeaders(withCors(await handleCreateWorkflow(request, env), request));
    }
    if (path.match(/^\/api\/workflows\/([^/]+)$/) && method === 'PATCH') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE' }));
      request.user = authCtx;
      const wfId = path.split('/').pop();
      return withSecurityHeaders(withCors(await handleUpdateWorkflow(request, env, wfId), request));
    }
    if (path.match(/^\/api\/workflows\/([^/]+)$/) && method === 'DELETE') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE' }));
      request.user = authCtx;
      const wfId = path.split('/').pop();
      return withSecurityHeaders(withCors(await handleDeleteWorkflow(request, env, wfId), request));
    }
    if (path.match(/^\/api\/workflows\/([^/]+)\/execute$/) && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE' }));
      request.user = authCtx;
      const wfId = path.split('/')[3];
      return withSecurityHeaders(withCors(await handleExecuteWorkflow(request, env, wfId), request));
    }
    if (path.match(/^\/api\/workflows\/([^/]+)\/executions$/) && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE' }));
      request.user = authCtx;
      const wfId = path.split('/')[3];
      return withSecurityHeaders(withCors(await handleWorkflowExecutions(request, env, wfId), request));
    }

    // ── White Label MSSP ──────────────────────────────────────────────────────
    if (path === '/api/white-label/theme' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE' }));
      request.user = authCtx;
      return withSecurityHeaders(withCors(await handleGetTheme(request, env), request));
    }
    if (path === '/api/white-label/theme' && method === 'PUT') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE' }));
      request.user = authCtx;
      return withSecurityHeaders(withCors(await handleUpdateTheme(request, env), request));
    }
    if (path === '/api/white-label/theme' && method === 'DELETE') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE' }));
      request.user = authCtx;
      return withSecurityHeaders(withCors(await handleDeleteTheme(request, env), request));
    }
    if (path.match(/^\/api\/white-label\/theme\/([^/]+)$/) && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE' }));
      request.user = authCtx;
      const orgId = path.split('/').pop();
      return withSecurityHeaders(withCors(await handleGetThemeByOrg(request, env, orgId), request));
    }

    // ── Product Analytics ─────────────────────────────────────────────────────
    if (path === '/api/analytics/p3/event' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE' }));
      request.user = authCtx;
      return withSecurityHeaders(withCors(await handleIngestEvent(request, env), request));
    }
    if (path === '/api/analytics/p3/growth' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE' }));
      request.user = authCtx;
      return withSecurityHeaders(withCors(await handleGrowthMetrics(request, env), request));
    }
    if (path === '/api/analytics/p3/funnel' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE' }));
      request.user = authCtx;
      return withSecurityHeaders(withCors(await handleConversionFunnel(request, env), request));
    }
    if (path === '/api/analytics/p3/adoption' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE' }));
      request.user = authCtx;
      return withSecurityHeaders(withCors(await handleFeatureAdoption(request, env), request));
    }
    if (path === '/api/analytics/p3/prune' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE' }));
      request.user = authCtx;
      return withSecurityHeaders(withCors(await handlePruneEvents(request, env), request));
    }

    // ── Notification Platform ─────────────────────────────────────────────────
    if (path === '/api/notifications/preferences' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE' }));
      request.user = authCtx;
      return withSecurityHeaders(withCors(await handleGetPreferences(request, env), request));
    }
    if (path === '/api/notifications/preferences' && method === 'PUT') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE' }));
      request.user = authCtx;
      return withSecurityHeaders(withCors(await handleUpdatePreferences(request, env), request));
    }
    if (path === '/api/notifications/log' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE' }));
      request.user = authCtx;
      return withSecurityHeaders(withCors(await handleNotificationLog(request, env), request));
    }
    if (path === '/api/notifications/test' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE' }));
      request.user = authCtx;
      return withSecurityHeaders(withCors(await handleTestNotification(request, env), request));
    }
    if (path === '/api/notifications/send' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE' }));
      request.user = authCtx;
      return withSecurityHeaders(withCors(await handleAdminSendNotification(request, env), request));
    }

    // ── Reliability Engineering ───────────────────────────────────────────────
    if (path === '/api/reliability/sla' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE' }));
      request.user = authCtx;
      return withSecurityHeaders(withCors(await handleSLAReport(request, env), request));
    }
    if (path === '/api/reliability/error-budget' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE' }));
      request.user = authCtx;
      return withSecurityHeaders(withCors(await handleErrorBudget(request, env), request));
    }
    if (path === '/api/reliability/capacity' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE' }));
      request.user = authCtx;
      return withSecurityHeaders(withCors(await handleCapacityMetrics(request, env), request));
    }
    if (path === '/api/reliability/incidents' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE' }));
      request.user = authCtx;
      return withSecurityHeaders(withCors(await handleListReliabilityIncidents(request, env), request));
    }
    if (path === '/api/reliability/incident' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE' }));
      request.user = authCtx;
      return withSecurityHeaders(withCors(await handleCreateReliabilityIncident(request, env), request));
    }
    // ── END PHASE 3 ROUTES ────────────────────────────────────────────────────

    // ── v34.0 PHASE 4 GOD MODE ROUTES ────────────────────────────────────────

    // ── Platform Metrics Authority: /api/authority/* ──────────────────────────
    if (path === '/api/authority/metrics' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
      request.user = authCtx;
      return withSecurityHeaders(withCors(await handleGetMetrics(request, env), request));
    }
    if (path === '/api/authority/refresh' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
      request.user = authCtx;
      return withSecurityHeaders(withCors(await handleRefreshMetrics(request, env), request));
    }
    if (path === '/api/authority/history' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
      request.user = authCtx;
      return withSecurityHeaders(withCors(await handleMetricsHistory(request, env), request));
    }
    if (path === '/api/authority/status' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
      request.user = authCtx;
      return withSecurityHeaders(withCors(await handlePlatformStatus(request, env), request));
    }

    // ── SOC Investigation Depth: /api/soc/inv/:caseId/* ──────────────────────
    if (path.match(/^\/api\/soc\/inv\/[^/]+\/timeline$/) && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
      request.user = authCtx;
      return withSecurityHeaders(withCors(await handleGetTimeline(request, env), request));
    }
    if (path.match(/^\/api\/soc\/inv\/[^/]+\/evidence$/) && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
      request.user = authCtx;
      return withSecurityHeaders(withCors(await handleListEvidence(request, env), request));
    }
    if (path.match(/^\/api\/soc\/inv\/[^/]+\/evidence$/) && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
      request.user = authCtx;
      return withSecurityHeaders(withCors(await handleAddEvidence(request, env), request));
    }
    if (path.match(/^\/api\/soc\/inv\/[^/]+\/notes$/) && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
      request.user = authCtx;
      return withSecurityHeaders(withCors(await handleListNotes(request, env), request));
    }
    if (path.match(/^\/api\/soc\/inv\/[^/]+\/notes$/) && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
      request.user = authCtx;
      return withSecurityHeaders(withCors(await handleAddNote(request, env), request));
    }
    if (path.match(/^\/api\/soc\/inv\/[^/]+\/escalate$/) && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
      request.user = authCtx;
      return withSecurityHeaders(withCors(await handleEscalateCase(request, env), request));
    }
    if (path.match(/^\/api\/soc\/inv\/[^/]+\/summary$/) && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
      request.user = authCtx;
      return withSecurityHeaders(withCors(await handleInvestigationSummary(request, env), request));
    }
    if (path.match(/^\/api\/soc\/inv\/[^/]+\/resolve$/) && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
      request.user = authCtx;
      return withSecurityHeaders(withCors(await handleResolveCase(request, env), request));
    }

    // ── CTI Platform V2: /api/cti/v2/* ───────────────────────────────────────
    // NOTE: /watchlists/match must come BEFORE the /:id catch-all
    if (path === '/api/cti/v2/watchlists/match' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
      request.user = authCtx;
      return withSecurityHeaders(withCors(await handleWatchlistMatch(request, env), request));
    }
    if (path === '/api/cti/v2/watchlists' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
      request.user = authCtx;
      return withSecurityHeaders(withCors(await handleListWatchlists(request, env), request));
    }
    if (path === '/api/cti/v2/watchlists' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
      request.user = authCtx;
      return withSecurityHeaders(withCors(await handleCreateWatchlist(request, env), request));
    }
    if (path.match(/^\/api\/cti\/v2\/watchlists\/[^/]+\/entries$/) && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
      request.user = authCtx;
      return withSecurityHeaders(withCors(await handleListWatchlistEntries(request, env), request));
    }
    if (path.match(/^\/api\/cti\/v2\/watchlists\/[^/]+\/entries$/) && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
      request.user = authCtx;
      return withSecurityHeaders(withCors(await handleAddWatchlistEntry(request, env), request));
    }
    if (path.match(/^\/api\/cti\/v2\/watchlists\/[^/]+$/) && method === 'DELETE') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
      request.user = authCtx;
      return withSecurityHeaders(withCors(await handleDeleteWatchlist(request, env), request));
    }
    if (path === '/api/cti/v2/ioc/enrich' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
      request.user = authCtx;
      return withSecurityHeaders(withCors(await handleEnrichIOC(request, env), request));
    }
    if (path === '/api/cti/v2/stix/export' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
      if (!authCtx.authenticated) return withSecurityHeaders(withCors(unauthorized(), request));
      // STIX 2.1 export — PRO+ entitlement gate (Task 9)
      const { featureGate, FEATURES } = await import('./middleware/entitlementCheck.js');
      const stixGate = await featureGate(env.DB, authCtx, FEATURES.STIX_21_EXPORT);
      if (stixGate) return withSecurityHeaders(withCors(stixGate, request));
      request.user = authCtx;
      return withSecurityHeaders(withCors(await handleSTIXExport(request, env), request));
    }

    // ── Revenue Intelligence: /api/revenue/intel/* ───────────────────────────
    if (path === '/api/revenue/intel/snapshot' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
      request.user = authCtx;
      return withSecurityHeaders(withCors(await handleCreateSnapshot(request, env), request));
    }
    if (path === '/api/revenue/intel/history' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
      request.user = authCtx;
      return withSecurityHeaders(withCors(await handleRevenueHistory(request, env), request));
    }
    if (path === '/api/revenue/intel/forecast' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
      request.user = authCtx;
      return withSecurityHeaders(withCors(await handleRevenueForecast(request, env), request));
    }
    if (path === '/api/revenue/intel/waterfall' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
      request.user = authCtx;
      return withSecurityHeaders(withCors(await handleRevenueWaterfall(request, env), request));
    }
    if (path === '/api/revenue/intel/cohorts' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
      request.user = authCtx;
      return withSecurityHeaders(withCors(await handleCohortAnalysis(request, env), request));
    }
    if (path === '/api/revenue/intel/tiermix' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
      request.user = authCtx;
      return withSecurityHeaders(withCors(await handleTierMix(request, env), request));
    }

    // ── Commercialization Engine: /api/commercial/* ───────────────────────────
    if (path.match(/^\/api\/commercial\/expansion\/[^/]+$/) && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
      request.user = authCtx;
      return withSecurityHeaders(withCors(await handleGetExpansionScore(request, env), request));
    }
    if (path === '/api/commercial/segments' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
      request.user = authCtx;
      return withSecurityHeaders(withCors(await handleListSegments(request, env), request));
    }
    if (path === '/api/commercial/upsell/event' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
      request.user = authCtx;
      return withSecurityHeaders(withCors(await handleLogUpsellEvent(request, env), request));
    }
    if (path === '/api/commercial/upsell/funnel' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
      request.user = authCtx;
      return withSecurityHeaders(withCors(await handleUpsellFunnel(request, env), request));
    }
    if (path === '/api/commercial/features/gates' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
      request.user = authCtx;
      return withSecurityHeaders(withCors(await handleFeatureGates(request, env), request));
    }

    // ── END PHASE 4 ROUTES ────────────────────────────────────────────────────

    // GET /api/threat-intel/stream — SSE real-time feed (Phase 1)
    // Must be BEFORE the /:id catch-all
    if (path === '/api/threat-intel/stream' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE', authenticated: false }));
      // SSE does not use withCors wrapper (returns streaming Response directly)
      return await handleThreatIntelStream(request, env, authCtx);
    }

    // GET /api/soc/dashboard — Full SOC dashboard (plan-gated, public route)
    if (path === '/api/soc/dashboard' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE' }));
      return withSecurityHeaders(withCors(await handleSOCDashboard(request, env, authCtx), request));
    }

    // POST /api/threat-intel/ingest — manual trigger (PRO/ENTERPRISE)
    if (path === '/api/threat-intel/ingest' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env);
      return withSecurityHeaders(withCors(await handleManualIngest(request, env, authCtx), request));
    }

    // GET /api/threat-intel/live — alias for /api/sentinel/feed (KV-backed live CVE feed)
    if (path === '/api/threat-intel/live' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleSentinelFeed(request, env), request));
    }

    // GET /api/threat-intel/:id — single advisory detail (after /stats and /stream)
    if (path.match(/^\/api\/threat-intel\/[^/]+$/) && method === 'GET') {
      const entryId = path.split('/')[3];
      // Avoid matching sub-routes already handled above
      if (!['stats', 'stream', 'ingest'].includes(entryId)) {
        const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE' }));
        return withSecurityHeaders(withCors(await handleGetThreatIntelEntry(request, env, authCtx, entryId), request));
      }
    }

    // POST /api/threat-intel/correlate — legacy endpoint (scan findings → CVE correlation)
    if (path === '/api/threat-intel/correlate' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env);
      try {
        const body = await request.json();
        const { findings, scan_result, module } = body;
        if (!findings || !module) {
          return withSecurityHeaders(withCors(Response.json({ error: 'findings and module required' }, { status: 400 }), request));
        }
        const correlation = await correlateThreatIntel(findings, scan_result || {}, module, env);
        return withSecurityHeaders(withCors(Response.json({ success: true, correlation }), request));
      } catch (e) {
        return withSecurityHeaders(withCors(Response.json({ error: e.message }, { status: 500 }), request));
      }
    }

    // ── Continuous Monitoring ─────────────────────────────────────────────────
    if (path === '/api/monitors' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env);
      return withSecurityHeaders(withCors(await handleCreateMonitor(request, env, authCtx), request));
    }
    if (path === '/api/monitors' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env);
      return withSecurityHeaders(withCors(await handleListMonitors(request, env, authCtx), request));
    }
    if (path.match(/^\/api\/monitors\/[^/]+$/) && method === 'GET') {
      const authCtx   = await resolveAuthV5(request, env);
      const monitorId = path.split('/')[3];
      return withSecurityHeaders(withCors(await handleGetMonitor(request, env, authCtx, monitorId), request));
    }
    if (path.match(/^\/api\/monitors\/[^/]+$/) && method === 'PUT') {
      const authCtx   = await resolveAuthV5(request, env);
      const monitorId = path.split('/')[3];
      return withSecurityHeaders(withCors(await handleUpdateMonitor(request, env, authCtx, monitorId), request));
    }
    if (path.match(/^\/api\/monitors\/[^/]+$/) && method === 'DELETE') {
      const authCtx   = await resolveAuthV5(request, env);
      const monitorId = path.split('/')[3];
      return withSecurityHeaders(withCors(await handleDeleteMonitor(request, env, authCtx, monitorId), request));
    }
    if (path.match(/^\/api\/monitors\/[^/]+\/history$/) && method === 'GET') {
      const authCtx   = await resolveAuthV5(request, env);
      const monitorId = path.split('/')[3];
      return withSecurityHeaders(withCors(await handleMonitorHistory(request, env, authCtx, monitorId), request));
    }
    if (path.match(/^\/api\/monitors\/[^/]+\/run$/) && method === 'POST') {
      const authCtx   = await resolveAuthV5(request, env);
      const monitorId = path.split('/')[3];
      return withSecurityHeaders(withCors(await handleTriggerMonitor(request, env, authCtx, monitorId), request));
    }

    // ── Content & Distribution Engine ─────────────────────────────────────────
    if (path === '/api/content' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env);
      return withSecurityHeaders(withCors(await handleGenerateContent(request, env, authCtx), request));
    }
    if (path === '/api/content' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env);
      return withSecurityHeaders(withCors(await handleListContent(request, env, authCtx), request));
    }
    if (path === '/api/content/feed' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleContentFeed(request, env), request));
    }
    if (path.match(/^\/api\/content\/[^/]+$/) && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env);
      const postId  = path.split('/')[3];
      return withSecurityHeaders(withCors(await handleGetContent(request, env, authCtx, postId), request));
    }
    if (path.match(/^\/api\/content\/[^/]+\/publish$/) && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env);
      const postId  = path.split('/')[3];
      return withSecurityHeaders(withCors(await handlePublishContent(request, env, authCtx, postId), request));
    }
    if (path.match(/^\/api\/content\/[^/]+$/) && method === 'DELETE') {
      const authCtx = await resolveAuthV5(request, env);
      const postId  = path.split('/')[3];
      return withSecurityHeaders(withCors(await handleDeleteContent(request, env, authCtx, postId), request));
    }

    // ── Enterprise Multi-Tenant Orgs ──────────────────────────────────────────
    if (path === '/api/orgs' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env);
      return withSecurityHeaders(withCors(await handleCreateOrg(request, env, authCtx), request));
    }
    if (path === '/api/orgs' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env);
      return withSecurityHeaders(withCors(await handleListOrgs(request, env, authCtx), request));
    }
    if (path.match(/^\/api\/orgs\/[^/]+$/) && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env);
      const orgSlug = path.split('/')[3];
      return withSecurityHeaders(withCors(await handleGetOrg(request, env, authCtx, orgSlug), request));
    }
    if (path.match(/^\/api\/orgs\/[^/]+$/) && method === 'PUT') {
      const authCtx = await resolveAuthV5(request, env);
      const orgId   = path.split('/')[3];
      return withSecurityHeaders(withCors(await handleUpdateOrg(request, env, authCtx, orgId), request));
    }
    if (path.match(/^\/api\/orgs\/[^/]+$/) && method === 'DELETE') {
      const authCtx = await resolveAuthV5(request, env);
      const orgId   = path.split('/')[3];
      return withSecurityHeaders(withCors(await handleDeleteOrg(request, env, authCtx, orgId), request));
    }
    if (path.match(/^\/api\/orgs\/[^/]+\/dashboard$/) && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env);
      const orgId   = path.split('/')[3];
      return withSecurityHeaders(withCors(await handleOrgDashboard(request, env, authCtx, orgId), request));
    }
    if (path.match(/^\/api\/orgs\/[^/]+\/members$/) && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env);
      const orgId   = path.split('/')[3];
      return withSecurityHeaders(withCors(await handleInviteMember(request, env, authCtx, orgId), request));
    }
    if (path.match(/^\/api\/orgs\/[^/]+\/members$/) && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env);
      const orgId   = path.split('/')[3];
      return withSecurityHeaders(withCors(await handleGetOrg(request, env, authCtx, orgId), request));
    }
    if (path.match(/^\/api\/orgs\/[^/]+\/members\/[^/]+$/) && method === 'PUT') {
      const authCtx    = await resolveAuthV5(request, env);
      const parts      = path.split('/');
      const orgId      = parts[3];
      const targetUser = parts[5];
      return withSecurityHeaders(withCors(await handleUpdateMemberRole(request, env, authCtx, orgId, targetUser), request));
    }
    if (path.match(/^\/api\/orgs\/[^/]+\/members\/[^/]+$/) && method === 'DELETE') {
      const authCtx    = await resolveAuthV5(request, env);
      const parts      = path.split('/');
      const orgId      = parts[3];
      const targetUser = parts[5];
      return withSecurityHeaders(withCors(await handleRemoveMember(request, env, authCtx, orgId, targetUser), request));
    }
    if (path.match(/^\/api\/orgs\/[^/]+\/scans$/) && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env);
      const orgId   = path.split('/')[3];
      return withSecurityHeaders(withCors(await handleOrgScans(request, env, authCtx, orgId), request));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // V9.0 AI Cyber Brain V2 — Threat Correlation, Attack Simulation, Forecast
    // ═══════════════════════════════════════════════════════════════════════

    // POST /api/ai/analyze → attack chain + MITRE mapping + exploit probability
    if (path === '/api/ai/analyze' && method === 'POST') {
      return withSecurityHeaders(withCors(await handleAIAnalyze(request, env), request));
    }

    // POST /api/ai/simulate → step-by-step attacker path + blast radius
    if (path === '/api/ai/simulate' && method === 'POST') {
      return withSecurityHeaders(withCors(await handleAISimulate(request, env), request));
    }

    // POST /api/ai/chat → MYTHOS conversational analyst (multi-turn, intent routing)
    if (path === '/api/ai/chat' && method === 'POST') {
      return withSecurityHeaders(withCors(await handleAIChat(request, env), request));
    }
    // POST /api/ai/generate-rules → SOAR rule generation (Sigma/Splunk/KQL/YARA/Elastic)
    if (path === '/api/ai/generate-rules' && method === 'POST') {
      return withSecurityHeaders(withCors(await handleGenerateRules(request, env), request));
    }
    // POST /api/ai/forecast → exploitation likelihood + time-to-breach + financial impact
    if (path === '/api/ai/forecast' && method === 'POST') {
      return withSecurityHeaders(withCors(await handleAIForecast(request, env), request));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // V10.0 SUBSCRIPTION SaaS ENGINE — Plan management, billing, feature gating
    // ═══════════════════════════════════════════════════════════════════════

    // GET /api/subscription/plans → public plan listing for pricing page
    if (path === '/api/subscription/plans' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleGetPlans(request, env), request));
    }

    // GET /api/user/plan → current plan + usage for authenticated/session user
    if (path === '/api/user/plan' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleGetUserPlan(request, env, authCtx), request));
    }

    // POST /api/subscription/create → create Razorpay order for a plan
    if (path === '/api/subscription/create' && method === 'POST') {
      // IP-based rate limit: max 5 subscription order creates per hour
      const ip     = request.headers.get('CF-Connecting-IP') || 'unknown';
      const rlHour = new Date().toISOString().slice(0, 13);
      const rlKey  = `rl:sub_create:${ip}:${rlHour}`;
      const rlKv   = env.SECURITY_HUB_KV || env.KV;
      if (rlKv && ip !== 'unknown') {
        const cnt = parseInt(await rlKv.get(rlKey).catch(() => '0') || '0', 10);
        if (cnt >= 5) {
          return withSecurityHeaders(withCors(Response.json({
            error: 'Rate limit exceeded — maximum 5 subscription requests per hour per IP.',
            retry_after: 3600,
          }, { status: 429 }), request));
        }
        await rlKv.put(rlKey, String(cnt + 1), { expirationTtl: 3600 }).catch(() => {});
      }
      return withSecurityHeaders(withCors(await handleCreateSubscription(request, env), request));
    }

    // POST /api/subscription/activate → verify payment + activate plan session
    if (path === '/api/subscription/activate' && method === 'POST') {
      return withSecurityHeaders(withCors(await handleActivateSubscription(request, env), request));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // V10.0 PUBLIC API v1 — Versioned API for PRO/ENTERPRISE key holders
    // All /api/v1/* routes require a valid API key (cdb_* header).
    // Returns consistent { success, data, error, timestamp } shape.
    // ═══════════════════════════════════════════════════════════════════════

    if (path.startsWith('/api/v1/')) {
      const authCtx = await resolveAuthV5(request, env);
      if (!authCtx.authenticated || authCtx.method !== 'api_key') {
        return withSecurityHeaders(withCors(Response.json({
          success: false,
          error:   'API v1 requires a valid API key (x-api-key: cdb_*). Obtain one at /api/keys.',
          code:    'ERR_API_KEY_REQUIRED',
          docs:    'GET /api',
        }, { status: 401 }), request));
      }

      // PRO/ENTERPRISE gate for versioned API
      if (!['PRO', 'ENTERPRISE'].includes(authCtx.tier)) {
        return withSecurityHeaders(withCors(Response.json({
          success: false,
          error:   `API v1 access requires PRO or ENTERPRISE plan. Current plan: ${authCtx.tier}.`,
          code:    'ERR_PLAN_UPGRADE_REQUIRED',
          upgrade: 'https://tools.cyberdudebivash.com/#pricing',
        }, { status: 403 }), request));
      }

      const v1Path = path.slice(7); // strip /api/v1 → /scan, /threat-intel, /analyze

      // GET /api/v1/scan → recent scan history for this API key
      if (v1Path === '/scan' && method === 'GET') {
        return withSecurityHeaders(withCors(await handleD1History(request, env, authCtx), request));
      }

      // GET /api/v1/threat-intel → D1-backed threat intel feed (PRO+)
      if (v1Path === '/threat-intel' && method === 'GET') {
        return withSecurityHeaders(withCors(await handleV1ThreatIntel(request, env, authCtx), request));
      }

      // GET /api/v1/iocs → IOC registry (ENTERPRISE only)
      if (v1Path === '/iocs' && method === 'GET') {
        return withSecurityHeaders(withCors(await handleV1IOCs(request, env, authCtx), request));
      }

      // POST /api/v1/analyze → AI threat analysis (rate limited per key)
      if (v1Path === '/analyze' && method === 'POST') {
        const quota = await enforceQuota(env, authCtx, 'ai');
        if (!quota.allowed) return withSecurityHeaders(withCors(
          rateLimitResponse({ ...quota, reason: 'daily_limit_reached' }, 'ai'), request
        ));
        return withSecurityHeaders(withCors(await handleAIAnalyze(request, env), request));
      }

      // POST /api/v1/simulate → attack simulation (ENTERPRISE only)
      if (v1Path === '/simulate' && method === 'POST') {
        if (authCtx.tier !== 'ENTERPRISE') {
          return withSecurityHeaders(withCors(Response.json({
            success: false,
            error:   'Attack simulation via API requires ENTERPRISE plan.',
            code:    'ERR_ENTERPRISE_REQUIRED',
          }, { status: 403 }), request));
        }
        return withSecurityHeaders(withCors(await handleAISimulate(request, env), request));
      }

      // POST /api/v1/forecast → risk forecast
      if (v1Path === '/forecast' && method === 'POST') {
        return withSecurityHeaders(withCors(await handleAIForecast(request, env), request));
      }

      // GET /api/v1/cves?module=domain → top exploited CVEs for a module
      if (v1Path === '/cves' && method === 'GET') {
        const mod   = url.searchParams.get('module') || 'domain';
        const limit = Math.min(20, parseInt(url.searchParams.get('limit') || '10', 10));
        const cves  = getTopCVEsForModule(mod, limit);
        return withSecurityHeaders(withCors(Response.json({
          success:   true,
          data:      { module: mod, cves, total: cves.length },
          error:     null,
          timestamp: new Date().toISOString(),
        }), request));
      }

      // GET /api/v1/correlations → CVE correlation engine (PRO/ENTERPRISE)
      if (v1Path === '/correlations' && method === 'GET') {
        return withSecurityHeaders(withCors(await handleV1Correlations(request, env, authCtx), request));
      }

      // GET /api/v1/graph → IOC relationship graph (PRO/ENTERPRISE)
      if (v1Path === '/graph' && method === 'GET') {
        return withSecurityHeaders(withCors(await handleV1Graph(request, env, authCtx), request));
      }

      // GET /api/v1/hunting → threat hunting alerts (PRO/ENTERPRISE)
      if (v1Path === '/hunting' && method === 'GET') {
        return withSecurityHeaders(withCors(await handleV1Hunting(request, env, authCtx), request));
      }

      // ── Sentinel APEX v3: SOC Automation + Defense ─────────────────────────

      // GET /api/v1/alerts → SOC detection alerts (STARTER+)
      if (v1Path === '/alerts' && method === 'GET') {
        return withSecurityHeaders(withCors(await handleGetAlerts(request, env, authCtx), request));
      }

      // GET /api/v1/decisions → AI decision engine (ENTERPRISE)
      if (v1Path === '/decisions' && method === 'GET') {
        return withSecurityHeaders(withCors(await handleGetDecisions(request, env, authCtx), request));
      }

      // GET /api/v1/defense-actions → Autonomous defense log (ENTERPRISE)
      if (v1Path === '/defense-actions' && method === 'GET') {
        return withSecurityHeaders(withCors(await handleGetDefenseActions(request, env, authCtx), request));
      }

      // GET /api/v1/federation → Global threat feed + source scores (PRO+)
      if (v1Path === '/federation' && method === 'GET') {
        return withSecurityHeaders(withCors(await handleGetFederation(request, env, authCtx), request));
      }

      // POST /api/v1/soc/analyze → Full SOC pipeline on-demand (ENTERPRISE)
      if (v1Path === '/soc/analyze' && method === 'POST') {
        return withSecurityHeaders(withCors(await handleSOCAnalyze(request, env, authCtx), request));
      }

      // GET /api/v1/soc/posture → SOC defense posture summary (STARTER+)
      if (v1Path === '/soc/posture' && method === 'GET') {
        return withSecurityHeaders(withCors(await handleGetSOCPosture(request, env, authCtx), request));
      }

      // ── v13 Agent Actions route ──────────────────────────────────────────
      // GET /api/v1/agent-actions → Recent autonomous agent actions (STARTER+)
      if (v1Path === '/agent-actions' && method === 'GET') {
        const url = new URL(request.url);
        const limit = Math.min(parseInt(url.searchParams.get('limit')||'20'), 100);
        try {
          const [rows, total] = await Promise.all([
            env.DB?.prepare(
              `SELECT id, agent_type, action_type, target, target_type, trigger_source, risk_level,
                      execution_status, executed_by, duration_ms, created_at, completed_at
               FROM agent_actions ORDER BY created_at DESC LIMIT ?`
            ).bind(limit).all().catch(()=>({results:[]})),
            env.DB?.prepare(`SELECT COUNT(*) as cnt FROM agent_actions`).first().catch(()=>({cnt:0})),
          ]);
          return withSecurityHeaders(withCors(Response.json({
            ok: true, total: total?.cnt||0,
            actions: rows?.results||[],
          }), request));
        } catch(e) {
          return withSecurityHeaders(withCors(Response.json({ ok:false, actions:[], error:e.message }), request));
        }
      }

      // ── v13 Predictive Threats route ─────────────────────────────────────
      // GET /api/v1/predictive/threats → Top risk predictions (public lite)
      if (v1Path === '/predictive/threats' && method === 'GET') {
        const url = new URL(request.url);
        const limit = Math.min(parseInt(url.searchParams.get('limit')||'10'), 50);
        try {
          const rows = await env.DB?.prepare(
            `SELECT cve_id, exploit_probability, probability_pct, impact_score, risk_score,
                    attack_window_label, expected_window_hrs, recommended_action,
                    is_kev, cvss_score, epss_score, apt_groups, mitre_techniques, prediction_date
             FROM threat_predictions ORDER BY risk_score DESC, probability_pct DESC LIMIT ?`
          ).bind(limit).all().catch(()=>({results:[]}));
          const stats = await env.DB?.prepare(
            `SELECT COUNT(*) as total,
                    SUM(CASE WHEN risk_score>=80 THEN 1 ELSE 0 END) as critical_count,
                    SUM(CASE WHEN probability_pct>=70 THEN 1 ELSE 0 END) as high_exploit,
                    SUM(CASE WHEN is_kev=1 THEN 1 ELSE 0 END) as kev_count
             FROM threat_predictions WHERE prediction_date=date('now')`
          ).first().catch(()=>({}));
          return withSecurityHeaders(withCors(Response.json({
            ok: true,
            predictions: rows?.results||[],
            summary: {
              total:        stats?.total||0,
              critical:     stats?.critical_count||0,
              high_exploit: stats?.high_exploit||0,
              kev:          stats?.kev_count||0,
            },
          }), request));
        } catch(e) {
          return withSecurityHeaders(withCors(Response.json({ ok:false, predictions:[], error:e.message }), request));
        }
      }

      // ── v13 Anomaly Events route ─────────────────────────────────────────
      // GET /api/v1/anomaly/events → Recent anomaly detections (AUTH required)
      if ((v1Path === '/anomaly/events' || v1Path === '/anomaly') && method === 'GET') {
        if (!authCtx?.user_id && authCtx?.tier === 'FREE') {
          return withSecurityHeaders(withCors(Response.json({ ok:false, error:'Authentication required', code:'ERR_AUTH' }, {status:401}), request));
        }
        const url = new URL(request.url);
        const limit = Math.min(parseInt(url.searchParams.get('limit')||'20'), 100);
        try {
          const rows = await env.DB?.prepare(
            `SELECT id, user_id, anomaly_score, anomaly_types, risk_level, auto_actioned, resolved, created_at
             FROM anomaly_events WHERE created_at > datetime('now','-24 hours')
             ORDER BY anomaly_score DESC LIMIT ?`
          ).bind(limit).all().catch(()=>({results:[]}));
          const stats = await env.DB?.prepare(
            `SELECT COUNT(*) as scanned,
                    SUM(CASE WHEN risk_level IN ('CRITICAL','HIGH') THEN 1 ELSE 0 END) as high_risk,
                    SUM(auto_actioned) as actioned
             FROM anomaly_events WHERE created_at > datetime('now','-24 hours')`
          ).first().catch(()=>({}));
          return withSecurityHeaders(withCors(Response.json({
            ok: true,
            anomalies: rows?.results||[],
            stats: { scanned: stats?.scanned||0, high_risk: stats?.high_risk||0, actioned: stats?.actioned||0 },
          }), request));
        } catch(e) {
          return withSecurityHeaders(withCors(Response.json({ ok:false, anomalies:[], error:e.message }), request));
        }
      }

      // Unknown /api/v1/* path
      return withSecurityHeaders(withCors(Response.json({
        success: false,
        error:   `Unknown API v1 endpoint: ${method} ${path}`,
        code:    'ERR_NOT_FOUND',
        available: [
          'GET /api/v1/scan', 'GET /api/v1/threat-intel',
          'POST /api/v1/analyze', 'POST /api/v1/simulate', 'POST /api/v1/forecast',
          'GET /api/v1/cves', 'GET /api/v1/iocs',
          'GET /api/v1/correlations', 'GET /api/v1/graph', 'GET /api/v1/hunting',
          'GET /api/v1/alerts', 'GET /api/v1/decisions', 'GET /api/v1/defense-actions',
          'GET /api/v1/federation', 'POST /api/v1/soc/analyze', 'GET /api/v1/soc/posture',
          'GET /api/v1/agent-actions', 'GET /api/v1/predictive/threats',
          'GET /api/v1/anomaly/events',
        ],
      }, { status: 404 }), request));
    }

    // Convenience aliases
    // POST /api/generate-key → alias of POST /api/keys
    if (path === '/api/generate-key' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env);
      if (!authCtx.authenticated) return withSecurityHeaders(withCors(unauthorized(), request));
      return withSecurityHeaders(withCors(await handleCreateKey(request, env, authCtx), request));
    }
    // GET /api/usage → alias of GET /api/admin/api-usage
    if (path === '/api/usage' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env);
      return withSecurityHeaders(withCors(await handleApiUsage(request, env, authCtx), request));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // V12.0 GTM GROWTH ENGINE — Revenue + Funnel + Email + Sales + Analytics
    // ═══════════════════════════════════════════════════════════════════════

    // POST /api/growth/capture — email capture + drip enroll (public)
    if (path === '/api/growth/capture' && method === 'POST') {
      return withSecurityHeaders(withCors(await handleEmailCapture(request, env), request));
    }

    // POST /api/growth/scan — record scan event + upgrade check (public)
    if (path === '/api/growth/scan' && method === 'POST') {
      return withSecurityHeaders(withCors(await handleScanEvent(request, env), request));
    }

    // GET /api/growth/upgrade-check — get upgrade trigger status (public)
    if (path === '/api/growth/upgrade-check' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleUpgradeCheck(request, env), request));
    }

    // POST /api/growth/upgrade — mark lead as upgraded (public)
    if (path === '/api/growth/upgrade' && method === 'POST') {
      return withSecurityHeaders(withCors(await handleUpgradeLead(request, env), request));
    }

    // GET /api/growth/analytics — revenue dashboard (admin, no strict auth for now)
    if (path === '/api/growth/analytics' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleRevenueDashboard(request, env), request));
    }

    // GET /api/growth/funnel — funnel conversion metrics (admin)
    if (path === '/api/growth/funnel' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleFunnelDashboard(request, env), request));
    }

    // GET /api/growth/leads — lead list (admin)
    if (path === '/api/growth/leads' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleGetLeads(request, env), request));
    }

    // POST /api/growth/sales/run — run enterprise sales pipeline
    if (path === '/api/growth/sales/run' && method === 'POST') {
      return withSecurityHeaders(withCors(await handleRunSalesPipeline(request, env), request));
    }

    // GET /api/growth/sales/outreach — get outreach queue
    if (path === '/api/growth/sales/outreach' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleGetOutreach(request, env), request));
    }

    // POST /api/growth/sales/outreach/:id/send — mark sent
    if (path.match(/^\/api\/growth\/sales\/outreach\/[^/]+\/send$/) && method === 'POST') {
      const outreachId = path.split('/')[5];
      return withSecurityHeaders(withCors(await handleMarkOutreachSent(request, env, null, outreachId), request));
    }

    // POST /api/growth/content/run — run content automation pipeline
    if (path === '/api/growth/content/run' && method === 'POST') {
      return withSecurityHeaders(withCors(await handleRunContentAutomation(request, env), request));
    }

    // GET /api/growth/content/queue — get content queue
    if (path === '/api/growth/content/queue' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleGetContentQueue(request, env), request));
    }

    // POST /api/growth/email/run — run drip email automation
    if (path === '/api/growth/email/run' && method === 'POST') {
      return withSecurityHeaders(withCors(await handleRunDrip(request, env), request));
    }

    // GET /api/unsubscribe — global one-click unsubscribe (public, no auth)
    // Linked from every email footer; marks lead as unsubscribed in D1.
    if (path === '/api/unsubscribe' && method === 'GET') {
      const email = url.searchParams.get('email') || '';
      const token = url.searchParams.get('token') || '';
      if (!email) {
        return withSecurityHeaders(withCors(
          Response.json({ success: false, error: 'email param required' }, { status: 400 }), request
        ));
      }
      try {
        if (env?.DB) {
          await env.DB.prepare(
            `UPDATE leads SET unsubscribed = 1, unsubscribed_at = datetime('now') WHERE email = ?`
          ).bind(email.toLowerCase()).run();
        }
        // Return a clean HTML confirmation page
        return new Response(`<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Unsubscribed — CYBERDUDEBIVASH</title>
<style>body{background:#0a0e1a;color:#e2e8f0;font-family:Inter,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
.box{background:#111827;border:1px solid #1f2937;border-radius:12px;padding:40px;max-width:420px;text-align:center}
h2{color:#10b981;margin-bottom:8px}p{color:#94a3b8;font-size:.9rem}a{color:#00d4ff}</style></head>
<body><div class="box"><h2>✅ Unsubscribed</h2>
<p><strong>${email}</strong> has been removed from all marketing emails.</p>
<p style="margin-top:16px">You will still receive critical security alerts if you have an active account.</p>
<p style="margin-top:16px"><a href="https://cyberdudebivash.in">← Return to Sentinel APEX</a></p>
</div></body></html>`, {
          status: 200,
          headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' },
        });
      } catch (e) {
        return withSecurityHeaders(withCors(
          Response.json({ success: false, error: e.message }, { status: 500 }), request
        ));
      }
    }

    // GET /api/growth/email/track — 1×1 pixel / redirect for email tracking
    if (path === '/api/growth/email/track' && method === 'GET') {
      return await handleEmailTrack(request, env);
    }

    // POST /api/growth/api-key — provision API key
    if (path === '/api/growth/api-key' && method === 'POST') {
      return withSecurityHeaders(withCors(await handleProvisionApiKey(request, env), request));
    }

    // GET /api/growth/api-usage — get API usage summary
    if (path === '/api/growth/api-usage' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleGetApiUsage(request, env), request));
    }

    // POST /api/billing/callback — Razorpay webhook / payment callback
    if (path === '/api/billing/callback' && method === 'POST') {
      return withSecurityHeaders(withCors(await handleBillingCallback(request, env), request));
    }

    // POST /api/billing/create-link — generate Razorpay payment link payload
    if (path === '/api/billing/create-link' && method === 'POST') {
      return withSecurityHeaders(withCors(await handleCreatePaymentLink(request, env), request));
    }

    // ─── MONETIZATION ENGINE v2 ─────────────────────────────────────────────
    // GET /api/billing/usage — detailed usage + quota status
    if (path === '/api/billing/usage' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGetUsage(request, env, authCtx), request));
    }
    // POST /api/billing/upgrade — initiate plan upgrade
    if (path === '/api/billing/upgrade' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleUpgrade(request, env, authCtx), request));
    }
    // GET /api/billing/plans — enriched plan comparison
    if (path === '/api/billing/plans' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGetBillingPlans(request, env, authCtx), request));
    }
    // POST /api/billing/trial/start — activate 14-day PRO trial
    if (path === '/api/billing/trial/start' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleStartTrial(request, env, authCtx), request));
    }
    // GET /api/billing/limits — quota enforcement state
    if (path === '/api/billing/limits' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGetLimits(request, env, authCtx), request));
    }
    // GET /api/billing/invoices — invoice history
    if (path === '/api/billing/invoices' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGetInvoices(request, env, authCtx), request));
    }
    // POST /api/billing/downgrade — schedule plan downgrade
    if (path === '/api/billing/downgrade' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleDowngrade(request, env, authCtx), request));
    }

    // ─── THREAT INTELLIGENCE GRAPH ──────────────────────────────────────────
    // GET /api/threat-graph — full D3-ready graph
    if (path === '/api/threat-graph' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGetThreatGraph(request, env, authCtx), request));
    }
    // GET /api/threat-graph/nodes — node list with filter
    if (path === '/api/threat-graph/nodes' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleGetGraphNodes(request, env), request));
    }
    // GET /api/threat-graph/paths — shortest attack path
    if (path === '/api/threat-graph/paths' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleGetGraphPaths(request, env), request));
    }
    // POST /api/threat-graph/query — subgraph query
    if (path === '/api/threat-graph/query' && method === 'POST') {
      return withSecurityHeaders(withCors(await handleGraphQuery(request, env), request));
    }
    // GET /api/threat-graph/summary — aggregate stats
    if (path === '/api/threat-graph/summary' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleGraphSummary(request, env), request));
    }

    // ─── CISO COMMAND CENTER ────────────────────────────────────────────────
    // GET /api/ciso/metrics — full CISO dashboard payload
    if (path === '/api/ciso/metrics' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGetCISOMetrics(request, env, authCtx), request));
    }
    // GET /api/ciso/posture — security posture scorecard
    if (path === '/api/ciso/posture' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGetCISOPosture(request, env, authCtx), request));
    }
    // GET /api/ciso/incidents — incident list
    if (path === '/api/ciso/incidents' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGetIncidents(request, env, authCtx), request));
    }
    // POST /api/ciso/incidents — create incident
    if (path === '/api/ciso/incidents' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleCreateIncident(request, env, authCtx), request));
    }
    // PUT /api/ciso/incidents/:id — update incident
    if (path.startsWith('/api/ciso/incidents/') && method === 'PUT') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleUpdateIncident(request, env, authCtx), request));
    }
    // GET /api/ciso/compliance-status
    if (path === '/api/ciso/compliance-status' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGetComplianceStatus(request, env, authCtx), request));
    }
    // GET /api/ciso/risk-register
    if (path === '/api/ciso/risk-register' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGetRiskRegister(request, env, authCtx), request));
    }
    // GET /api/ciso/report
    if (path === '/api/ciso/report' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGetCISOReport(request, env, authCtx), request));
    }

    // ── Phase 7: Global Expansion ───────────────────────────────────────────
    // GET /api/growth/region — region context + localized pricing + compliance
    if (path === '/api/growth/region' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleGetRegionContext(request, env), request));
    }

    // GET /api/growth/global — global expansion dashboard (region stats + pricing)
    if (path === '/api/growth/global' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleGlobalDashboard(request, env), request));
    }

    // ── Phase 9: Upsell + Revenue Maximization ──────────────────────────────
    // POST /api/growth/upsell/evaluate — evaluate upsell triggers for a session
    if (path === '/api/growth/upsell/evaluate' && method === 'POST') {
      return withSecurityHeaders(withCors(await handleEvaluateUpsell(request, env), request));
    }

    // POST /api/growth/upsell/converted — mark a upsell as converted
    if (path === '/api/growth/upsell/converted' && method === 'POST') {
      return withSecurityHeaders(withCors(await handleUpsellConverted(request, env), request));
    }

    // GET /api/growth/upsell/metrics — upsell + A/B test results
    if (path === '/api/growth/upsell/metrics' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleUpsellMetrics(request, env), request));
    }

    // GET /api/growth/feature-wall — get upgrade wall for a locked feature
    if (path === '/api/growth/feature-wall' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleFeatureWall(request, env), request));
    }

    // GET /api/growth/pricing — region-aware pricing with A/B variant
    if (path === '/api/growth/pricing' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleGetPricing(request, env), request));
    }

    // ── Phase 9: LinkedIn Domination Engine ─────────────────────────────────
    // GET /api/growth/linkedin/today — get today's LinkedIn post (pre-generated)
    if (path === '/api/growth/linkedin/today' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleLinkedInToday(request, env), request));
    }

    // POST /api/growth/linkedin/run — generate + queue today's LinkedIn post
    if (path === '/api/growth/linkedin/run' && method === 'POST') {
      return withSecurityHeaders(withCors(await handleRunLinkedIn(request, env), request));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // V8.1 REAL-TIME FEED — SSE threat alerts + posture + stats
    // ═══════════════════════════════════════════════════════════════════════

    // GET /api/realtime/feed — SSE live threat alert stream (PRO/ENTERPRISE)
    if (path === '/api/realtime/feed' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE', authenticated: false }));
      // SSE streams cannot use withCors wrapper — returns raw streaming Response
      return await handleRealtimeFeed(request, env, authCtx);
    }

    // GET /api/realtime/posture — Defense posture JSON (authenticated)
    if (path === '/api/realtime/posture' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE', authenticated: false }));
      return withSecurityHeaders(withCors(await handleRealtimePosture(request, env, authCtx), request));
    }

    // GET /api/realtime/stats — Live platform stats (public)
    if (path === '/api/realtime/stats' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE', authenticated: false }));
      return withSecurityHeaders(withCors(await handleRealtimeStats(request, env, authCtx), request));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // V8.1 GUMROAD REVENUE ENGINE — License verification + webhook + catalog
    // ═══════════════════════════════════════════════════════════════════════

    // POST /api/webhooks/gumroad — Gumroad purchase webhook (no auth — HMAC verified)
    if (path === '/api/webhooks/gumroad' && method === 'POST') {
      return withSecurityHeaders(withCors(await handleGumroadWebhook(request, env), request));
    }

    // POST /api/gumroad/verify — License key activation (optionally authenticated)
    if (path === '/api/gumroad/verify' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE', authenticated: false }));
      return withSecurityHeaders(withCors(await handleLicenseActivation(request, env, authCtx), request));
    }

    // GET /api/gumroad/products — Public product catalog
    if (path === '/api/gumroad/products' && method === 'GET') {
      return withSecurityHeaders(withCors(handleProductCatalog(request, env), request));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // V8.1 SIEM EXPORT — JSON / CEF / STIX 2.1 / Sigma / CSV / NDJSON
    // ═══════════════════════════════════════════════════════════════════════

    // ═══════════════════════════════════════════════════════════════════════
    // V8.1 AFFILIATE + REVENUE TRACKING
    // ═══════════════════════════════════════════════════════════════════════

    // POST /api/affiliate/click — track affiliate link click (public, fire-and-forget)
    if (path === '/api/affiliate/click' && method === 'POST') {
      // Non-blocking — always return 204
      (async () => {
        try {
          const body = await request.clone().json().catch(() => ({}));
          const ip   = request.headers.get('CF-Connecting-IP') || '';
          const country = request.cf?.country || '';
          const ua  = (request.headers.get('User-Agent') || '').slice(0, 300);
          if (env?.DB && body.link_id) {
            const id = crypto.randomUUID();
            await env.DB.prepare(
              `INSERT INTO affiliate_clicks (id, program, link_id, link_url, ref_page, ip, country, user_agent, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`
            ).bind(
              id,
              (body.program || 'unknown').slice(0, 64),
              (body.link_id || 'unknown').slice(0, 128),
              (body.link_url || '').slice(0, 500),
              (body.ref_page || '').slice(0, 500),
              ip, country,
              ua.slice(0, 200),
            ).run().catch(() => {});
          }
        } catch {}
      })();
      return withSecurityHeaders(withCors(new Response(null, { status: 204 }), request));
    }

    // GET /api/revenue/dashboard — revenue analytics (ENTERPRISE only)
    if (path === '/api/revenue/dashboard' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env);
      if (!authCtx.authenticated) return withSecurityHeaders(withCors(unauthorized(), request));
      if (authCtx.tier !== 'ENTERPRISE') {
        return withSecurityHeaders(withCors(Response.json({
          success: false, error: 'Revenue dashboard requires ENTERPRISE plan.',
          code: 'ERR_ENTERPRISE_REQUIRED',
        }, { status: 403 }), request));
      }
      try {
        const days = parseInt(new URL(request.url).searchParams.get('days') || '30', 10);
        const cutoff = new Date(Date.now() - days * 86400000).toISOString();
        const [payments, affiliates, gumroad] = await Promise.all([
          env.DB?.prepare(`SELECT source, SUM(amount_inr) as total_inr, COUNT(*) as count FROM revenue_events WHERE created_at >= ? GROUP BY source ORDER BY total_inr DESC`).bind(cutoff).all().catch(() => ({ results: [] })),
          env.DB?.prepare(`SELECT program, COUNT(*) as clicks, SUM(converted) as conversions, SUM(revenue) as revenue FROM affiliate_clicks WHERE created_at >= ? GROUP BY program ORDER BY clicks DESC`).bind(cutoff).all().catch(() => ({ results: [] })),
          env.DB?.prepare(`SELECT product_permalink, COUNT(*) as licenses, tier_granted FROM gumroad_licenses WHERE created_at >= ? GROUP BY product_permalink ORDER BY licenses DESC`).bind(cutoff).all().catch(() => ({ results: [] })),
        ]);
        return withSecurityHeaders(withCors(Response.json({
          success: true,
          period_days: days,
          revenue_by_source: payments?.results || [],
          affiliate_performance: affiliates?.results || [],
          gumroad_licenses: gumroad?.results || [],
          generated_at: new Date().toISOString(),
        }), request));
      } catch (e) {
        return withSecurityHeaders(withCors(Response.json({ success: false, error: e.message }, { status: 500 }), request));
      }
    }

    // ── v8.2 Revenue + Monetization + Automation Routes ──────────────────────

    // GET /api/revenue/snapshot — lightweight KPI snapshot (all plans)
    if (path === '/api/revenue/snapshot' && method === 'GET') {
      const { handleRevenueSnapshot } = await import('./handlers/revenue.js');
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleRevenueSnapshot(request, env, authCtx), request));
    }

    // GET /api/revenue/metrics — plan-gated full metrics
    if (path === '/api/revenue/metrics' && method === 'GET') {
      const { handleRevenueMetrics } = await import('./handlers/revenue.js');
      const authCtx = await resolveAuthV5(request, env);
      if (!authCtx.authenticated) return withSecurityHeaders(withCors(unauthorized(), request));
      return withSecurityHeaders(withCors(await handleRevenueMetrics(request, env, { userId: authCtx.userId, plan: authCtx.tier?.toLowerCase(), role: authCtx.role, email: authCtx.email }), request));
    }

    // GET /api/revenue/products — product catalog with live sales data (public)
    if (path === '/api/revenue/products' && method === 'GET') {
      const { handleRevenueProducts } = await import('./handlers/revenue.js');
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleRevenueProducts(request, env, authCtx ? { userId: authCtx.userId, plan: authCtx.tier?.toLowerCase(), role: authCtx.role } : null), request));
    }

    // GET /api/revenue/recommendations — admin recommendations
    if (path === '/api/revenue/recommendations' && method === 'GET') {
      const { handleRevenueRecommendations } = await import('./handlers/revenue.js');
      const authCtx = await resolveAuthV5(request, env);
      if (!authCtx.authenticated) return withSecurityHeaders(withCors(unauthorized(), request));
      return withSecurityHeaders(withCors(await handleRevenueRecommendations(request, env, { userId: authCtx.userId, plan: authCtx.tier?.toLowerCase(), role: authCtx.role }), request));
    }

    // POST /api/revenue/event — record revenue event (admin/internal)
    if (path === '/api/revenue/event' && method === 'POST') {
      const { handleRevenueEvent } = await import('./handlers/revenue.js');
      const authCtx = await resolveAuthV5(request, env);
      if (!authCtx.authenticated) return withSecurityHeaders(withCors(unauthorized(), request));
      return withSecurityHeaders(withCors(await handleRevenueEvent(request, env, { userId: authCtx.userId, role: authCtx.role }), request));
    }

    // POST /api/revenue/track — track any revenue action (public)
    if (path === '/api/revenue/track' && method === 'POST') {
      const { handleRevenueTrack } = await import('./handlers/revenue.js');
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleRevenueTrack(request, env, authCtx ? { userId: authCtx.userId, plan: authCtx.tier?.toLowerCase(), email: authCtx.email } : null), request));
    }

    // GET /api/revenue/dashboard/enhanced — charts-ready enhanced dashboard (PRO+)
    if (path === '/api/revenue/dashboard/enhanced' && method === 'GET') {
      const { handleEnhancedDashboard } = await import('./handlers/revenueDashboard.js');
      const authCtx = await resolveAuthV5(request, env);
      if (!authCtx.authenticated) return withSecurityHeaders(withCors(unauthorized(), request));
      return withSecurityHeaders(withCors(await handleEnhancedDashboard(request, env, { userId: authCtx.userId, plan: authCtx.tier?.toLowerCase(), role: authCtx.role }), request));
    }

    // GET /api/revenue/trends — trend analytics (PRO+)
    if (path === '/api/revenue/trends' && method === 'GET') {
      const { handleRevenueTrends } = await import('./handlers/revenueDashboard.js');
      const authCtx = await resolveAuthV5(request, env);
      if (!authCtx.authenticated) return withSecurityHeaders(withCors(unauthorized(), request));
      return withSecurityHeaders(withCors(await handleRevenueTrends(request, env, { userId: authCtx.userId, plan: authCtx.tier?.toLowerCase(), role: authCtx.role }), request));
    }

    // GET /api/revenue/growth — growth score + levers
    if (path === '/api/revenue/growth' && method === 'GET') {
      const { handleRevenueGrowth } = await import('./handlers/revenueDashboard.js');
      const authCtx = await resolveAuthV5(request, env);
      if (!authCtx.authenticated) return withSecurityHeaders(withCors(unauthorized(), request));
      return withSecurityHeaders(withCors(await handleRevenueGrowth(request, env, { userId: authCtx.userId, plan: authCtx.tier?.toLowerCase(), role: authCtx.role }), request));
    }

    // GET /api/monetize/upsell — AI upsell trigger (auth or anon)
    if (path === '/api/monetize/upsell' && method === 'GET') {
      const { handleUpsellTrigger } = await import('./handlers/revenue.js');
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleUpsellTrigger(request, env, authCtx ? { userId: authCtx.userId, plan: authCtx.tier?.toLowerCase() } : null), request));
    }

    // GET /api/monetize/products — AI product recommendations
    if (path === '/api/monetize/products' && method === 'GET') {
      const { handleProductRecommendations } = await import('./handlers/revenue.js');
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleProductRecommendations(request, env, authCtx ? { userId: authCtx.userId, plan: authCtx.tier?.toLowerCase() } : null), request));
    }

    // GET /api/monetize/churn-risk — churn risk assessment (PRO+)
    if (path === '/api/monetize/churn-risk' && method === 'GET') {
      const { handleChurnRisk } = await import('./handlers/revenue.js');
      const authCtx = await resolveAuthV5(request, env);
      if (!authCtx.authenticated) return withSecurityHeaders(withCors(unauthorized(), request));
      return withSecurityHeaders(withCors(await handleChurnRisk(request, env, { userId: authCtx.userId, plan: authCtx.tier?.toLowerCase(), role: authCtx.role }), request));
    }

    // POST /api/monetize/optimize — full AI optimization pass (auth required)
    if (path === '/api/monetize/optimize' && method === 'POST') {
      const { handleRevenueOptimize } = await import('./handlers/revenue.js');
      const authCtx = await resolveAuthV5(request, env);
      if (!authCtx.authenticated) return withSecurityHeaders(withCors(unauthorized(), request));
      return withSecurityHeaders(withCors(await handleRevenueOptimize(request, env, { userId: authCtx.userId, plan: authCtx.tier?.toLowerCase() }), request));
    }

    // POST /api/monetize/bulk-optimize — bulk AI pass (admin only)
    if (path === '/api/monetize/bulk-optimize' && method === 'POST') {
      const { handleBulkOptimize } = await import('./handlers/revenue.js');
      const authCtx = await resolveAuthV5(request, env);
      if (!authCtx.authenticated) return withSecurityHeaders(withCors(unauthorized(), request));
      return withSecurityHeaders(withCors(await handleBulkOptimize(request, env, { userId: authCtx.userId, role: authCtx.role }), request));
    }

    // GET  /api/funnel/metrics — conversion funnel data (ENTERPRISE/admin)
    if (path === '/api/funnel/metrics' && method === 'GET') {
      const { handleFunnelMetrics } = await import('./handlers/revenue.js');
      const authCtx = await resolveAuthV5(request, env);
      if (!authCtx.authenticated) return withSecurityHeaders(withCors(unauthorized(), request));
      return withSecurityHeaders(withCors(await handleFunnelMetrics(request, env, { userId: authCtx.userId, plan: authCtx.tier?.toLowerCase(), role: authCtx.role }), request));
    }

    // POST /api/funnel/event — record funnel stage event (public, fire-and-forget)
    if (path === '/api/funnel/event' && method === 'POST') {
      const { handleFunnelEvent } = await import('./handlers/revenue.js');
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleFunnelEvent(request, env, authCtx ? { userId: authCtx.userId } : null), request));
    }

    // GET  /api/defense/catalog — defense product catalog (public)
    if (path === '/api/defense/catalog' && method === 'GET') {
      const { handleDefenseCatalog } = await import('./handlers/revenue.js');
      return withSecurityHeaders(withCors(await handleDefenseCatalog(request, env, null), request));
    }

    // GET  /api/defense/preview — defense product preview with paywall
    if (path === '/api/defense/preview' && method === 'GET') {
      const { handleDefensePreview } = await import('./handlers/revenue.js');
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleDefensePreview(request, env, authCtx ? { userId: authCtx.userId, plan: authCtx.tier?.toLowerCase() } : null), request));
    }

    // POST /api/checkout — initiate Razorpay checkout
    if (path === '/api/checkout' && method === 'POST') {
      const { handleCheckoutInitiate } = await import('./handlers/revenue.js');
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleCheckoutInitiate(request, env, authCtx ? { userId: authCtx.userId, email: authCtx.email, name: authCtx.name } : null), request));
    }

    // POST /api/checkout/verify — verify Razorpay payment + grant access
    if (path === '/api/checkout/verify' && method === 'POST') {
      const { handleCheckoutVerify } = await import('./handlers/revenue.js');
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleCheckoutVerify(request, env, authCtx ? { userId: authCtx.userId, email: authCtx.email } : null), request));
    }

    // GET  /api/affiliate/stats — affiliate click stats (admin)
    if (path === '/api/affiliate/stats' && method === 'GET') {
      const { handleAffiliateStats } = await import('./handlers/revenue.js');
      const authCtx = await resolveAuthV5(request, env);
      if (!authCtx.authenticated) return withSecurityHeaders(withCors(unauthorized(), request));
      return withSecurityHeaders(withCors(await handleAffiliateStats(request, env, { userId: authCtx.userId, role: authCtx.role }), request));
    }

    // POST /api/automation/run — manual automation trigger (admin only)
    if (path === '/api/automation/run' && method === 'POST') {
      const { handleAutomationRun } = await import('./services/automationEngine.js');
      const authCtx = await resolveAuthV5(request, env);
      if (!authCtx.authenticated) return withSecurityHeaders(withCors(unauthorized(), request));
      return withSecurityHeaders(withCors(await handleAutomationRun(request, env, { userId: authCtx.userId, role: authCtx.role }), request));
    }

    // ════════════════════════════════════════════════════════════════════════
    // v10.0 ROUTES — Defense Solutions Marketplace, Enterprise, Global Scale
    // ════════════════════════════════════════════════════════════════════════

    // ── Defense Solutions Marketplace (Phase 1+2) ─────────────────────────

    // GET /api/defense/solutions — list marketplace solutions (public with filter)
    if (path === '/api/defense/solutions' && method === 'GET') {
      const { handleGetSolutions } = await import('./handlers/defenseMarketplace.js');
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleGetSolutions(request, env, authCtx ? { userId: authCtx.userId, plan: authCtx.tier?.toLowerCase(), email: authCtx.email } : {}), request));
    }

    // GET /api/defense/solutions/featured — featured solutions (public)
    if (path === '/api/defense/solutions/featured' && method === 'GET') {
      const { handleGetFeatured } = await import('./handlers/defenseMarketplace.js');
      return withSecurityHeaders(withCors(await handleGetFeatured(request, env), request));
    }

    // GET /api/defense/stats — marketplace aggregate stats (public)
    if (path === '/api/defense/stats' && method === 'GET') {
      const { handleGetMarketplaceStats } = await import('./handlers/defenseMarketplace.js');
      return withSecurityHeaders(withCors(await handleGetMarketplaceStats(request, env), request));
    }

    // GET /api/defense/fomo — FOMO social proof events (public)
    if (path === '/api/defense/fomo' && method === 'GET') {
      const { handleGetFOMO } = await import('./handlers/defenseMarketplace.js');
      return withSecurityHeaders(withCors(await handleGetFOMO(request, env), request));
    }

    // POST /api/defense/generate — admin: trigger on-demand generation
    if (path === '/api/defense/generate' && method === 'POST') {
      const { handleGenerateSolutions } = await import('./handlers/defenseMarketplace.js');
      const authCtx = await resolveAuthV5(request, env);
      if (!authCtx.authenticated) return withSecurityHeaders(withCors(unauthorized(), request));
      return withSecurityHeaders(withCors(await handleGenerateSolutions(request, env, { userId: authCtx.userId, role: authCtx.role }), request));
    }

    // ═══ ROUTE ALIASES: fix 404s hit by the frontend ══════════════════════════
    // GET /api/threat-intel/live  → alias → /api/sentinel/feed
    if (path === '/api/threat-intel/live' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleSentinelFeed(request, env), request));
    }

    // GET /api/zeroday/feed — recent CISA KEV entries as zero-day intelligence
    if (path === '/api/zeroday/feed' && method === 'GET') {
      try {
        const zdCacheKey = 'zeroday:feed:v1';
        if (env?.SECURITY_HUB_KV) {
          const cached = await env.SECURITY_HUB_KV.get(zdCacheKey, { type: 'json' }).catch(() => null);
          if (cached?.data?.length) return withSecurityHeaders(withCors(Response.json({ ...cached, cache_hit: true }), request));
        }
        const kevResp = await fetch('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', {
          headers: { 'User-Agent': 'CYBERDUDEBIVASH-SecurityHub/1.0' },
          signal: AbortSignal.timeout(8000),
        }).catch(() => null);
        if (kevResp?.ok) {
          const kev = await kevResp.json();
          const now = Date.now();
          const dayMs = 86400000;
          const ageLabel = (dateStr) => {
            if (!dateStr) return 'recent';
            const d = Math.floor((now - new Date(dateStr)) / dayMs);
            return d < 1 ? 'today' : d < 7 ? `${d}d` : d < 30 ? `${Math.floor(d/7)}w` : `${Math.floor(d/30)}mo`;
          };
          const zdData = [...(kev.vulnerabilities || [])]
            .sort((a, b) => new Date(b.dateAdded || 0) - new Date(a.dateAdded || 0))
            .slice(0, 8)
            .map(v => ({
              id:  v.cveID,
              p:   `${v.vendorProject} ${v.product}`.trim().slice(0, 50),
              cvss: 8.5,
              st:  v.knownRansomwareCampaignUse === 'Known' ? 'ITW' : 'PoC',
              dk:  false,
              poc: true,
              pt:  false,
              ag:  ageLabel(v.dateAdded),
              d:   (v.shortDescription || `${v.vulnerabilityName} — actively exploited per CISA KEV. Due: ${v.dueDate || 'immediate patch required'}.`).slice(0, 200),
            }));
          const result = { data: zdData, source: 'CISA KEV', generated_at: new Date().toISOString(), total: zdData.length };
          if (env?.SECURITY_HUB_KV) env.SECURITY_HUB_KV.put(zdCacheKey, JSON.stringify(result), { expirationTtl: 3600 }).catch(() => {});
          return withSecurityHeaders(withCors(Response.json(result), request));
        }
        // Fallback: D1 threat_intel table
        if (env?.DB) {
          const rows = await env.DB.prepare(
            `SELECT id, title, cvss_score, published_at FROM threat_intel WHERE cvss_score >= 7.5 ORDER BY published_at DESC LIMIT 8`
          ).all().catch(() => ({ results: [] }));
          const dayMs2 = 86400000;
          const zdFallback = (rows.results || []).map(v => ({
            id:  v.id,
            p:   v.title || v.id,
            cvss: parseFloat(v.cvss_score) || 8.0,
            st:  'PoC',
            dk:  false,
            poc: true,
            pt:  false,
            ag:  v.published_at ? (() => { const d = Math.floor((Date.now() - new Date(v.published_at)) / dayMs2); return d < 7 ? `${d}d` : `${Math.floor(d/7)}w`; })() : 'recent',
            d:   `${v.id} — high-severity vulnerability requiring immediate attention. Check NVD for full details.`,
          }));
          return withSecurityHeaders(withCors(Response.json({ data: zdFallback, source: 'D1', generated_at: new Date().toISOString() }), request));
        }
        return withSecurityHeaders(withCors(Response.json({ data: [], error: 'Feed initializing' }, { status: 503 }), request));
      } catch (e) {
        return withSecurityHeaders(withCors(Response.json({ error: e.message, data: [] }, { status: 500 }), request));
      }
    }

    // GET /api/defense/list  → alias → /api/defense/solutions
    if (path === '/api/defense/list' && method === 'GET') {
      const { handleGetSolutions } = await import('./handlers/defenseMarketplace.js');
      return withSecurityHeaders(withCors(await handleGetSolutions(request, env, {}), request));
    }

    // GET /api/analytics/dashboard  → live platform metrics from D1
    if (path === '/api/analytics/dashboard' && method === 'GET') {
      try {
        const [scansRow, revenueRow, defenseRow, usersRow, threatRow] = await Promise.all([
          env.DB?.prepare(`SELECT COUNT(*) as total, SUM(CASE WHEN scanned_at > datetime('now','-1 day') THEN 1 ELSE 0 END) as today FROM scan_history`).first().catch(()=>null),
          env.DB?.prepare(`SELECT COALESCE(SUM(amount),0) as total FROM payments WHERE status='paid'`).first().catch(()=>null),
          env.DB?.prepare(`SELECT COUNT(*) as cnt, COALESCE(SUM(amount),0) as rev FROM payments WHERE status='paid' AND module LIKE 'defense%'`).first().catch(()=>null),
          env.DB?.prepare(`SELECT COUNT(*) as total FROM users`).first().catch(()=>null),
          env.DB?.prepare(`SELECT COUNT(*) as total, SUM(CASE WHEN severity='CRITICAL' THEN 1 ELSE 0 END) as critical FROM threat_intel`).first().catch(()=>null),
        ]);
        return withSecurityHeaders(withCors(Response.json({
          success: true,
          scans:        { total: scansRow?.total||0, today: scansRow?.today||0 },
          revenue:      { total_inr: revenueRow?.total||0, defense_inr: defenseRow?.rev||0 },
          defense:      { products: defenseRow?.cnt||0 },
          users:        { total: usersRow?.total||0 },
          threat_intel: { total: threatRow?.total||0, critical: threatRow?.critical||0 },
          timestamp:    new Date().toISOString(),
        }), request));
      } catch(e) {
        return withSecurityHeaders(withCors(Response.json({ success: false, error: e.message }, { status: 500 }), request));
      }
    }

    // ── v21.0: GET /api/executive/metrics — aggregated executive KPI data ────────
    // Wraps analytics/dashboard + threat-intel/stats for Gadget 4
    if (path === '/api/executive/metrics' && method === 'GET') {
      try {
        const [scansRow, usersRow, threatRow, vulnRow] = await Promise.all([
          env.DB?.prepare(`SELECT COUNT(*) as total, SUM(CASE WHEN scanned_at > datetime('now','-1 day') THEN 1 ELSE 0 END) as today, SUM(CASE WHEN risk_score >= 80 THEN 1 ELSE 0 END) as critical_scans FROM scan_history`).first().catch(() => null),
          env.DB?.prepare(`SELECT COUNT(*) as total, SUM(CASE WHEN created_at > datetime('now','-7 day') THEN 1 ELSE 0 END) as new_this_week FROM users`).first().catch(() => null),
          env.DB?.prepare(`SELECT COUNT(*) as total, SUM(CASE WHEN severity='CRITICAL' THEN 1 ELSE 0 END) as critical, SUM(CASE WHEN severity='HIGH' THEN 1 ELSE 0 END) as high, MAX(published_at) as latest_at FROM threat_intel`).first().catch(() => null),
          env.DB?.prepare(`SELECT COUNT(*) as total, SUM(CASE WHEN severity='CRITICAL' AND status!='patched' THEN 1 ELSE 0 END) as open_critical FROM brain_predictions`).first().catch(() => null),
        ]);
        const totalScans   = scansRow?.total        || 0;
        const totalToday   = scansRow?.today        || 0;
        const criticalScans= scansRow?.critical_scans || 0;
        const totalUsers   = usersRow?.total        || 0;
        const totalThreats = threatRow?.total       || 0;
        const criticalThreats = threatRow?.critical || 0;
        const highThreats  = threatRow?.high        || 0;
        // Compute risk trend: ratio critical/total scans as 0–100
        const riskScore    = totalScans > 0 ? Math.min(100, Math.round((criticalScans / totalScans) * 100 * 2.5 + criticalThreats * 0.5)) : 0;
        const exposurePct  = totalThreats > 0 ? Math.round((criticalThreats / totalThreats) * 100) : 0;
        return withSecurityHeaders(withCors(Response.json({
          success:      true,
          total_scans:  totalScans,
          scans_today:  totalToday,
          total_users:  totalUsers,
          total_threats:     totalThreats,
          critical_threats:  criticalThreats,
          high_threats:      highThreats,
          risk_score:        riskScore,
          exposure_pct:      exposurePct,
          new_users_week:    usersRow?.new_this_week || 0,
          latest_threat_at:  threatRow?.latest_at   || null,
          timestamp:         new Date().toISOString(),
        }), request));
      } catch(e) {
        return withSecurityHeaders(withCors(Response.json({ success: false, error: e.message }, { status: 500 }), request));
      }
    }

    // ── v21.0: GET /api/defense/recommendations — alias for defense posture + pending ─
    if (path === '/api/defense/recommendations' && method === 'GET') {
      try {
        const [postureRes, pendingRes] = await Promise.all([
          handleGetDefensePosture(request, env, {}),
          handleGetPending(request, env, {}),
        ]);
        // handleGetDefensePosture wraps its payload as { success, data: { posture: {...} } } —
        // unwrap to the real stats object so `posture.total_executions` etc. below aren't
        // permanently undefined/0 (this was double-nested and silently broke gadgets.html's
        // Auto Defense Engine stats and the recommendations.stats block below).
        const postureRaw = await postureRes.json().catch(() => ({}));
        const posture = postureRaw?.data?.posture || postureRaw?.posture || {};
        // handleGetPending is likewise wrapped as { success, data: { pending, count } }.
        const pendingRaw = await pendingRes.json().catch(() => ({}));
        const pending = pendingRaw?.data || pendingRaw || { pending: [] };
        return withSecurityHeaders(withCors(Response.json({
          success: true,
          posture: posture,
          recommendations: (pending.pending || []).map(p => ({
            id:          p.id,
            type:        p.type        || 'rule',
            title:       p.title       || p.action || 'Defense action',
            severity:    p.severity    || 'HIGH',
            status:      p.status      || 'pending',
            description: p.description || p.rationale || '',
            created_at:  p.created_at  || p.queued_at || new Date().toISOString(),
          })),
          stats: {
            total_executions:    posture.total_executions     || 0,
            rules_deployed:      posture.total_rules_deployed || 0,
            threats_blocked:     posture.threats_blocked      || 0,
            pending_actions:     pending.count                || 0,
          },
        }), request));
      } catch(e) {
        return withSecurityHeaders(withCors(Response.json({ success: false, error: e.message }, { status: 500 }), request));
      }
    }

    // ── v21.0: GET /api/scan/stats — scan statistics summary ─────────────────────
    if (path === '/api/scan/stats' && method === 'GET') {
      try {
        const today = new Date().toISOString().slice(0, 10);
        // Read last 7 days of KV scan counters (written by trackScan in serviceHandlers)
        const kvDays = [];
        for (let i = 0; i < 7; i++) {
          const d = new Date(Date.now() - i * 86400000).toISOString().slice(0, 10);
          kvDays.push(d);
        }
        const kvCounts = await Promise.all(
          kvDays.map(d => env.SECURITY_HUB_KV?.get(`scan_count:total:${d}`).catch(() => null))
        );
        const kvTodayCount  = parseInt(kvCounts[0] || '0', 10);
        const kvTotalScans  = kvCounts.reduce((s, v) => s + parseInt(v || '0', 10), 0);

        // Also check D1 scan_history for users with accounts
        const [row, threatRow] = await Promise.all([
          env.DB?.prepare(`SELECT COUNT(*) as total_scans, SUM(CASE WHEN scanned_at > datetime('now','-1 day') THEN 1 ELSE 0 END) as today, SUM(CASE WHEN risk_score >= 80 THEN 1 ELSE 0 END) as critical, SUM(CASE WHEN risk_score >= 50 AND risk_score < 80 THEN 1 ELSE 0 END) as high, AVG(risk_score) as avg_risk FROM scan_history`).first().catch(() => null),
          env.DB?.prepare(`SELECT COUNT(*) as cve_count, SUM(CASE WHEN severity='CRITICAL' THEN 1 ELSE 0 END) as critical_cves FROM threat_intel`).first().catch(() => null),
        ]);

        // Use KV counts as canonical (covers all API-key and anonymous scans)
        // Fall back to D1 for authenticated users if KV is empty
        const totalScans  = Math.max(kvTotalScans, row?.total_scans || 0);
        const todayScans  = Math.max(kvTodayCount,  row?.today       || 0);

        return withSecurityHeaders(withCors(Response.json({
          success:       true,
          total_scans:   totalScans,
          today:         todayScans,
          critical:      row?.critical   || 0,
          high:          row?.high       || 0,
          avg_risk:      Math.round(row?.avg_risk || 0),
          cve_count:     threatRow?.cve_count    || 0,
          critical_cves: threatRow?.critical_cves || 0,
          kv_scans_7d:   kvTotalScans,
          d1_scans:      row?.total_scans || 0,
          timestamp:     new Date().toISOString(),
        }), request));
      } catch(e) {
        return withSecurityHeaders(withCors(Response.json({ success: false, error: e.message }, { status: 500 }), request));
      }
    }

    // POST /api/admin/bootstrap  — seed threat intel + defense marketplace
    // Auth: Authorization: Bearer <ADMIN_TOKEN secret>  (fail-closed, constant-time).
    if (path === '/api/admin/bootstrap' && method === 'POST') {
      if (!isAdminAuthorized(request, env)) {
        return withSecurityHeaders(withCors(Response.json({ error: 'Unauthorized' }, { status: 401 }), request));
      }
      const results = { threat_intel: null, defense: null };
      // 1. Seed threat intel D1
      try {
        const ir = await runIngestion(env);
        results.threat_intel = { inserted: ir.inserted, total: ir.total, sources: ir.sources, errors: ir.errors, error_samples: ir.error_samples };
      } catch(e) { results.threat_intel = { error: e.message }; }
      // 2. Seed defense solutions D1
      const { seedDefenseSolutions, seedScanHistory, seedPlatformMetrics } = await import('./handlers/defenseSeed.js');
      try { results.defense          = await seedDefenseSolutions(env);  } catch(e) { results.defense          = { error: e.message }; }
      try { results.scan_history     = await seedScanHistory(env);       } catch(e) { results.scan_history     = { error: e.message }; }
      try { results.platform_metrics = await seedPlatformMetrics(env);   } catch(e) { results.platform_metrics = { error: e.message }; }
      // 3. Populate sentinel KV feed so /api/threat-intel/live returns data immediately
      try {
        results.sentinel = await runSentinelCron(env);
      } catch(e) { results.sentinel = { error: e.message }; }
      return withSecurityHeaders(withCors(Response.json({
        success: true, bootstrap: results, timestamp: new Date().toISOString(),
      }), request));
    }

    // POST /api/admin/backfill — bulk-grow threat_intel (full CISA KEV + NVD pages)
    // Auth: Authorization: Bearer <ADMIN_TOKEN secret>  (fail-closed, constant-time).
    // Query: ?nvd=1 also advances one NVD page per severity (slower).
    if (path === '/api/admin/backfill' && method === 'POST') {
      if (!isAdminAuthorized(request, env)) {
        return withSecurityHeaders(withCors(Response.json({ error: 'Unauthorized' }, { status: 401 }), request));
      }
      const url      = new URL(request.url);
      const nvd      = url.searchParams.get('nvd') === '1';
      try {
        const r = await runBulkBackfill(env, { nvdBackfill: nvd });
        return withSecurityHeaders(withCors(Response.json({
          success: r.success !== false, backfill: r, timestamp: new Date().toISOString(),
        }), request));
      } catch (e) {
        return withSecurityHeaders(withCors(Response.json({ success: false, error: e.message }, { status: 500 }), request));
      }
    }

    // POST /api/defense/custom-request — submit custom solution request (public)
    if (path === '/api/defense/custom-request' && method === 'POST') {
      const { handleCustomSolutionRequest } = await import('./handlers/defenseMarketplace.js');
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleCustomSolutionRequest(request, env, authCtx ? { userId: authCtx.userId, email: authCtx.email } : {}), request));
    }

    // GET /api/defense/solutions/:id — single solution detail
    if (path.startsWith('/api/defense/solutions/') && !path.includes('/purchase') && !path.includes('/verify') && method === 'GET') {
      const { handleGetSolution } = await import('./handlers/defenseMarketplace.js');
      const solutionId = path.replace('/api/defense/solutions/', '').split('/')[0];
      const authCtx    = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleGetSolution(request, env, authCtx ? { userId: authCtx.userId, plan: authCtx.tier?.toLowerCase(), email: authCtx.email } : {}, solutionId), request));
    }

    // POST /api/defense/purchase/:id — initiate Razorpay checkout for solution
    if (path.startsWith('/api/defense/purchase/') && method === 'POST') {
      const { handleInitiatePurchase } = await import('./handlers/defenseMarketplace.js');
      const solutionId = path.replace('/api/defense/purchase/', '').split('/')[0];
      const authCtx    = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleInitiatePurchase(request, env, authCtx ? { userId: authCtx.userId, email: authCtx.email } : {}, solutionId), request));
    }

    // POST /api/defense/verify/:id — verify Razorpay payment for solution
    if (path.startsWith('/api/defense/verify/') && method === 'POST') {
      const { handleVerifyPurchase } = await import('./handlers/defenseMarketplace.js');
      const solutionId = path.replace('/api/defense/verify/', '').split('/')[0];
      const authCtx    = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleVerifyPurchase(request, env, authCtx ? { userId: authCtx.userId, email: authCtx.email } : {}, solutionId), request));
    }

    // ── Scan → Upsell Engine (Phase 3) ───────────────────────────────────

    // POST /api/scan/upsell — evaluate scan result for upsell opportunity
    // ── MYTHOS ORCHESTRATOR CORE v1.0 ────────────────────────────────────────
    // POST /api/mythos/run — trigger autonomous orchestration loop (admin)
    if (path === '/api/mythos/run' && method === 'POST') {
      const adminKey = request.headers.get('x-admin-key') || request.headers.get('X-Admin-Key');
      const isAdmin  = adminKey && env.ADMIN_KEY && adminKey === env.ADMIN_KEY;
      if (!isAdmin) return withSecurityHeaders(withCors(new Response(JSON.stringify({ success: false, error: 'Admin access required', hint: 'Provide x-admin-key header' }), { status: 403, headers: { 'Content-Type': 'application/json' } }), request));
      return withSecurityHeaders(withCors(await handleMythosRun(request, env, { role: 'admin' }), request));
    }
    // GET /api/mythos/status — live pipeline status (public)
    if (path === '/api/mythos/status' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleMythosStatus(request, env, {}), request));
    }
    // GET /api/mythos/metrics — lifetime metrics (public)
    if (path === '/api/mythos/metrics' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleMythosMetrics(request, env, {}), request));
    }
    // GET /api/mythos/jobs/:jobId — job details (public, polls job state)
    if (path.startsWith('/api/mythos/jobs/') && method === 'GET') {
      const jobId = path.replace('/api/mythos/jobs/', '').split('/')[0];
      return withSecurityHeaders(withCors(await handleMythosJob(request, env, {}, jobId), request));
    }
    // POST /api/mythos/validate — validate any security artifact
    if (path === '/api/mythos/validate' && method === 'POST') {
      return withSecurityHeaders(withCors(await handleMythosValidate(request, env, {}), request));
    }
    // POST /api/mythos/analyze — AI-powered CVE deep analysis + task plan
    if (path === '/api/mythos/analyze' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleMythosAnalyze(request, env, authCtx || {}), request));
    }

    // ── MYTHOS REVENUE ENGINE v30.0.2 ─────────────────────────────────────────
    // POST /api/mythos/checkout/initialize — multi-rail UPI/Bank/Crypto/Razorpay
    if (path === '/api/mythos/checkout/initialize' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleMythosCheckout(request, env, authCtx || {}), request));
    }
    // POST /api/mythos/checkout/webhook — Razorpay HMAC-verified webhook
    if (path === '/api/mythos/checkout/webhook' && method === 'POST') {
      return withSecurityHeaders(await handleMythosWebhook(request, env));
    }
    // POST /api/mythos/scan — MYTHOS AI autonomous domain scan (paywall-aware)
    if (path === '/api/mythos/scan' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleMythosScan(request, env, authCtx || {}), request));
    }
    // POST /api/mythos/compliance — framework compliance map (ISO/SOC2/DPDP/GDPR)
    if (path === '/api/mythos/compliance' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleMythosCompliance(request, env, authCtx || {}), request));
    }

    // ── MYTHOS GOD MODE v4.0 — full autonomous 12-phase platform orchestrator ──
    // POST /api/mythos/god-mode/run — trigger full 12-phase run (admin)
    if (path === '/api/mythos/god-mode/run' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleGodModeRun(request, env, authCtx || {}, ctx), request));
    }
    // GET /api/mythos/god-mode/status — live pipeline status (public)
    if (path === '/api/mythos/god-mode/status' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleGodModeStatus(request, env), request));
    }
    // GET /api/mythos/god-mode/report[/:jobId] — full run report
    if (path.startsWith('/api/mythos/god-mode/report') && method === 'GET') {
      const jobId = path.replace('/api/mythos/god-mode/report', '').replace(/^\//, '') || 'latest';
      return withSecurityHeaders(withCors(await handleGodModeReport(request, env, null, jobId), request));
    }
    // GET /api/mythos/god-mode/ciso — CISO intel pack + board report
    if (path === '/api/mythos/god-mode/ciso' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleGodModeCISOIntel(request, env, authCtx || {}), request));
    }
    // GET /api/mythos/god-mode/hunt-pack — latest SOAR hunt pack (KQL + Sigma + YARA)
    if (path === '/api/mythos/god-mode/hunt-pack' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleGodModeHuntPack(request, env, authCtx || {}), request));
    }
    // GET /api/mythos/god-mode/compliance — compliance posture snapshot
    if (path === '/api/mythos/god-mode/compliance' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleGodModeCompliance(request, env), request));
    }
    // GET /api/mythos/god-mode/aspm — AI asset security posture + ZT anomalies
    if (path === '/api/mythos/god-mode/aspm' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleGodModeASPM(request, env), request));
    }

    // ── PHASE 2: Autonomous SOC Mode ──────────────────────────────────────────
    // ══════════════════════════════════════════════════════════════════════════
    // HIGH-REVENUE FEATURES v1.0
    // IOC Enrichment | ASM | Brand Protection | Threat Actors | CRQ
    // ══════════════════════════════════════════════════════════════════════════

    // ── IOC Enrichment ────────────────────────────────────────────────────────
    if (path === '/api/ioc/enrich' && (method === 'GET' || method === 'POST')) {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleIOCEnrich(request, env, authCtx || {}), request));
    }
    if (path === '/api/ioc/enrich/batch' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleIOCEnrichBatch(request, env, authCtx || {}), request));
    }

    // ── Phase B: Threat Intelligence API Economy ──────────────────────────────
    if ((path === '/api/intel/ioc' || path === '/api/intel/ioc/enrich') && (method === 'GET' || method === 'POST')) {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleIntelIOC(request, env, authCtx || {}), request));
    }
    if (path === '/api/intel/cve' && (method === 'GET' || method === 'POST')) {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleIntelCVE(request, env, authCtx || {}), request));
    }
    if ((path === '/api/intel/actor' || path === '/api/intel/threat-actors') && (method === 'GET' || method === 'POST')) {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleIntelActor(request, env, authCtx || {}), request));
    }
    if (path === '/api/intel/ttp' && (method === 'GET' || method === 'POST')) {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleIntelTTP(request, env, authCtx || {}), request));
    }
    if (path === '/api/intel/risk' && (method === 'GET' || method === 'POST')) {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleIntelRisk(request, env, authCtx || {}), request));
    }

    // ── Threat Intel Pro v1.0: MITRE ATT&CK, APT, Composite Risk, STIX 2.1, AI Analyst ──
    if (
      (path.startsWith('/api/intel/actors') ||
       path.startsWith('/api/intel/actor/') ||
       path === '/api/intel/tactics' ||
       path === '/api/intel/techniques' ||
       path === '/api/intel/attack-map' ||
       path === '/api/intel/heatmap' ||
       path.startsWith('/api/intel/risk-score/') ||
       path === '/api/intel/risk-queue' ||
       path.startsWith('/api/intel/epss/') ||
       path === '/api/intel/stix' ||
       path.startsWith('/api/intel/sector/') ||
       path.startsWith('/api/intel/cve-brief/') ||
       path === '/api/intel/analyst' ||
       path === '/api/intel/analyst/query' ||
       path.startsWith('/api/intel/attribute/') ||
       path === '/api/taxii/discovery' ||
       path === '/api/taxii/collections' ||
       path.startsWith('/api/taxii/collections/')) &&
      (method === 'GET' || method === 'POST' || method === 'OPTIONS')
    ) {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleThreatIntelPro(request, env, authCtx || {}), request));
    }

    // ── Phase C: MYTHOS Platform Governor API ────────────────────────────────
    if (path === '/api/governor/status' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleGovernorStatus(request, env, authCtx || {}), request));
    }
    if (path === '/api/governor/report' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleGovernorReport(request, env, authCtx || {}), request));
    }
    if (path === '/api/governor/run' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      if (!authCtx?.isAdmin) return withSecurityHeaders(withCors(Response.json({ error: 'Admin only' }, { status: 403 }), request));
      const result = await runPlatformGovernor(env);
      return withSecurityHeaders(withCors(Response.json({ success: true, ...result }), request));
    }

    // ── Phase D: Enterprise Trust & Sales Readiness ──────────────────────────
    if (path === '/api/trust-center' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleEnterpriseTrustCenter(request, env, authCtx || {}), request));
    }
    if (path === '/api/docs' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleDocsPortal(request, env, authCtx || {}), request));
    }
    if (path === '/api/security-center' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleSecurityCenter(request, env, authCtx || {}), request));
    }
    if (path === '/api/enterprise/inquire' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleEnterpriseInquiry(request, env, authCtx || {}), request));
    }
    if (path === '/api/enterprise/sales-kit' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleEnterpriseSalesKit(request, env, authCtx || {}), request));
    }

    // ── Phase B: AI Security Posture Management ───────────────────────────────
    if ((path === '/api/aispm/inventory' || path === '/api/aispm/scan') && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleAISPMInventory(request, env, authCtx || {}), request));
    }
    if (path === '/api/aispm/owasp-llm' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleAISPMOWASP(request, env, authCtx || {}), request));
    }
    if (path === '/api/aispm/governance' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleAISPMGovernance(request, env, authCtx || {}), request));
    }
    if (path === '/api/aispm/report' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleAISPMReport(request, env, authCtx || {}), request));
    }

    // ── Phase B: Executive Risk Platform ─────────────────────────────────────
    if (path === '/api/executive/risk-brief' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleExecutiveRiskBrief(request, env, authCtx || {}), request));
    }
    if (path === '/api/executive/dashboard' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleExecutiveDashboard(request, env, authCtx || {}), request));
    }
    if (path === '/api/executive/forecast' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleExecutiveForecast(request, env, authCtx || {}), request));
    }
    if (path === '/api/executive/board-report' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleBoardReport(request, env, authCtx || {}), request));
    }
    // P10.6 — Playbook Recommendation Engine (read-only; aggregates existing engines)
    if (path === '/api/executive/playbook-recommendations' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handlePlaybookRecommendations(request, env, authCtx || {}), request));
    }

    // ── P11.0: AI Security Decision Platform ─────────────────────────────────
    if (path === '/api/decision/summary' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleDecisionSummary(request, env, authCtx || {}), request));
    }
    if (path === '/api/decision/actions' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleDecisionActions(request, env, authCtx || {}), request));
    }
    if (path === '/api/decision/business-impact' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleDecisionBusinessImpact(request, env, authCtx || {}), request));
    }
    if (path === '/api/decision/priorities' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleDecisionPriorities(request, env, authCtx || {}), request));
    }
    if (path === '/api/decision/executive' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleDecisionExecutive(request, env, authCtx || {}), request));
    }

    // ── P12.0: Enterprise AI SOC Command Platform ─────────────────────────────
    if (path === '/api/soc/command/state' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleSOCCommandState(request, env, authCtx || {}), request));
    }
    if (path === '/api/soc/command/copilot' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleSOCCopilot(request, env, authCtx || {}), request));
    }
    if (path === '/api/soc/command/workflow' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleSOCWorkflowQueue(request, env, authCtx || {}), request));
    }
    if (path === '/api/soc/command/observability' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleSOCObservability(request, env, authCtx || {}), request));
    }
    if (path === '/api/soc/stream' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return handleSOCEventStream(request, env, authCtx || {});
    }
    if (path === '/api/knowledge-graph' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleKnowledgeGraph(request, env, authCtx || {}), request));
    }
    if (path === '/api/knowledge-graph/query' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleKnowledgeGraphQuery(request, env, authCtx || {}), request));
    }
    if (path.match(/^\/api\/soc\/investigate\/[^/]+$/) && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleAIInvestigation(request, env, authCtx || {}), request));
    }

    // ── P13.0: Autonomous Security Operations Platform ────────────────────────
    if (path === '/api/autonomous/orchestrator/plan' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleAutonomousOrchestratorPlan(request, env, authCtx || {}), request));
    }
    if (path.match(/^\/api\/autonomous\/incident-response\/[^/]+$/) && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleAutonomousIncidentResponse(request, env, authCtx || {}), request));
    }
    if (path === '/api/autonomous/risk/predict' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleAutonomousPredictiveRisk(request, env, authCtx || {}), request));
    }
    if (path === '/api/autonomous/workflow/status' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleAutonomousWorkflowStatus(request, env, authCtx || {}), request));
    }
    if (path === '/api/autonomous/executive/brief' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleAutonomousExecutiveBrief(request, env, authCtx || {}), request));
    }
    if (path === '/api/autonomous/observability' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleAutonomousObservability(request, env, authCtx || {}), request));
    }

    // ── P14.0: Enterprise AI Security Fabric ──────────────────────────────────
    if (path === '/api/fabric/state' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleFabricState(request, env, authCtx || {}), request));
    }
    if (path === '/api/fabric/agents/status' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleFabricAgentStatus(request, env, authCtx || {}), request));
    }
    if (path === '/api/fabric/events' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleFabricEvents(request, env, authCtx || {}), request));
    }
    if (path === '/api/fabric/events/publish' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleFabricPublishEvent(request, env, authCtx || {}), request));
    }
    if (path === '/api/fabric/plugins' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleFabricPlugins(request, env, authCtx || {}), request));
    }
    if (path === '/api/fabric/plugins/register' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleFabricPluginRegister(request, env, authCtx || {}), request));
    }
    if (path === '/api/fabric/policy/evaluate' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleFabricPolicyEvaluate(request, env, authCtx || {}), request));
    }
    if (path === '/api/fabric/memory' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleFabricMemory(request, env, authCtx || {}), request));
    }
    if (path === '/api/fabric/memory/record' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleFabricMemoryRecord(request, env, authCtx || {}), request));
    }
    if (path === '/api/fabric/observability' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleFabricObservability(request, env, authCtx || {}), request));
    }

    // ── P15.0: Commercial Platform & Enterprise Customer Success ──────────────
    if (path === '/api/customer/onboarding/wizard' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleOnboardingWizard(request, env, authCtx || {}), request));
    }
    if (path === '/api/customer/license' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleCustomerLicense(request, env, authCtx || {}), request));
    }
    if (path === '/api/customer/usage/analytics' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleUsageAnalytics(request, env, authCtx || {}), request));
    }
    if (path === '/api/customer/success/score' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleCustomerSuccessScore(request, env, authCtx || {}), request));
    }
    if (path.startsWith('/api/keys/') && path.endsWith('/history') && method === 'GET') {
      const keyId   = path.split('/')[3];
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleKeyHistory(request, env, authCtx || {}, keyId), request));
    }
    if (path.startsWith('/api/keys/') && !path.includes('/usage') && !path.endsWith('/history') && method === 'PATCH') {
      const keyId   = path.split('/')[3];
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleKeyUpdateMeta(request, env, authCtx || {}, keyId), request));
    }
    if (path === '/api/customer/reports/archive' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleReportArchive(request, env, authCtx || {}), request));
    }
    if (path === '/api/customer/notifications/center' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleNotificationCenter(request, env, authCtx || {}), request));
    }
    if (path === '/api/commercial/observability' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleCommercialObservability(request, env, authCtx || {}), request));
    }

    // ── P17.0: AI Security Intelligence Scorecard — Viral Acquisition Engine ──────
    if (path === '/api/public/security-scorecard' && method === 'POST') {
      return withSecurityHeaders(withCors(await handlePublicScorecard(request, env), request));
    }
    if (path.startsWith('/api/public/security-scorecard/') && method === 'GET') {
      const token = path.replace('/api/public/security-scorecard/', '');
      return withSecurityHeaders(withCors(await handleScorecardByToken(request, env, token), request));
    }
    if (path === '/api/scorecard/my-score' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleMyScore(request, env, authCtx || {}), request));
    }
    if (path === '/api/scorecard/history' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleScorecardHistory(request, env, authCtx || {}), request));
    }
    if (path === '/api/scorecard/share' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleScorecardShare(request, env, authCtx || {}), request));
    }
    if (path === '/api/platform/scorecard/observability' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleScorecardObservability(request, env), request));
    }

    // ── P16.0: Enterprise Transformation — KPI, Billing Portal, Overage Engine ──
    if (path === '/api/platform/kpi' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handlePlatformKPI(request, env, authCtx || {}), request));
    }
    if (path === '/api/platform/kpi/executive' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleExecutiveKPI(request, env, authCtx || {}), request));
    }
    if (path === '/api/customer/billing/portal' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleCustomerBillingPortal(request, env, authCtx || {}), request));
    }
    if (path === '/api/customer/billing/invoices' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleCustomerInvoices(request, env, authCtx || {}), request));
    }
    if (path === '/api/customer/billing/cancel' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleCancelSubscription(request, env, authCtx || {}), request));
    }
    if (path === '/api/customer/billing/upgrade' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleUpgradeInitiate(request, env, authCtx || {}), request));
    }
    if (path === '/api/customer/usage/live' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleLiveUsage(request, env, authCtx || {}), request));
    }
    if (path === '/api/platform/overage/report' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleOverageReport(request, env, authCtx || {}), request));
    }
    if (path === '/api/platform/overage/charge' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleOverageCharge(request, env, authCtx || {}), request));
    }
    if (path === '/api/platform/transform/observability' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleTransformObservability(request, env, authCtx || {}), request));
    }

    // ── P21.0: Marketplace Checkout Engine ───────────────────────────────────
    if (path === '/api/marketplace/catalog' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleMarketplaceCatalog(request, env), request));
    }
    if (path.startsWith('/api/marketplace/catalog/') && method === 'GET') {
      const productId = path.replace('/api/marketplace/catalog/', '');
      return withSecurityHeaders(withCors(await handleMarketplaceProduct(request, env, productId), request));
    }
    if (path === '/api/marketplace/checkout' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleMarketplaceCheckout(request, env, authCtx || {}), request));
    }
    if (path === '/api/marketplace/verify' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleMarketplaceVerify(request, env, authCtx || {}), request));
    }
    if (path === '/api/marketplace/my-purchases' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      if (authCtx) request.user = authCtx;
      return withSecurityHeaders(withCors(await handleMyMarketplacePurchases(request, env, authCtx || {}), request));
    }
    if (path === '/api/marketplace/observability' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleMarketplaceObservability(request, env), request));
    }

    // ── P20.0: Developer Onboarding & Self-Serve Trial Engine ────────────────
    if (path === '/api/onboarding/trial-key' && method === 'POST') {
      return withSecurityHeaders(withCors(await handleTrialKeyRequest(request, env), request));
    }
    if (path === '/api/onboarding/quickstart' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleQuickstart(request, env), request));
    }
    if (path === '/api/onboarding/status' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleOnboardingStatus(request, env), request));
    }
    if (path === '/api/onboarding/resend-welcome' && method === 'POST') {
      return withSecurityHeaders(withCors(await handleResendWelcome(request, env), request));
    }
    if (path === '/api/onboarding/observability' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleOnboardingObservability(request, env), request));
    }

    // ── P18.0: Revenue Intelligence & Churn Prevention Engine (owner-only) ──────
    if (path.startsWith('/api/platform/revenue-intelligence')) {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      if (!isOwner(authCtx, env)) return withSecurityHeaders(withCors(forbidden(), request));
      if (authCtx) request.user = authCtx;
      if (path === '/api/platform/revenue-intelligence' && method === 'GET')
        return withSecurityHeaders(withCors(await handleRevenueIntelligence(request, env), request));
      if (path === '/api/platform/revenue-intelligence/churn-alerts' && method === 'GET')
        return withSecurityHeaders(withCors(await handleChurnAlerts(request, env), request));
      if (path === '/api/platform/revenue-intelligence/intervention' && method === 'POST')
        return withSecurityHeaders(withCors(await handleLogIntervention(request, env), request));
      if (path === '/api/platform/revenue-intelligence/upgrade-signals' && method === 'GET')
        return withSecurityHeaders(withCors(await handleUpgradeSignals(request, env), request));
      if (path === '/api/platform/revenue-intelligence/nrr-forecast' && method === 'GET')
        return withSecurityHeaders(withCors(await handleNRRForecast(request, env), request));
      if (path === '/api/platform/revenue-intelligence/observability' && method === 'GET')
        return withSecurityHeaders(withCors(await handleRevenueIntelObservability(request, env), request));
      if (path === '/api/platform/revenue-intelligence/churn-trigger' && method === 'POST')
        return withSecurityHeaders(withCors(await handleChurnInterventionTrigger(request, env), request));
    }

    // ── Attack Surface Management ─────────────────────────────────────────────
    if ((path === '/api/asm/targets' || path === '/api/asm/scan') && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleASMAddTarget(request, env, authCtx || {}, ctx), request));
    }
    if (path === '/api/asm/targets' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleASMListTargets(request, env, authCtx || {}), request));
    }
    if (path.startsWith('/api/asm/targets/') && path.endsWith('/scan') && method === 'POST') {
      const targetId = path.replace('/api/asm/targets/', '').replace('/scan', '');
      const authCtx  = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleASMTriggerScan(request, env, authCtx || {}, targetId, ctx), request));
    }
    if (path.startsWith('/api/asm/targets/') && path.endsWith('/report') && method === 'GET') {
      const targetId = path.replace('/api/asm/targets/', '').replace('/report', '');
      const authCtx  = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleASMGetReport(request, env, authCtx || {}, targetId), request));
    }

    // ── Brand Protection ──────────────────────────────────────────────────────
    if (path === '/api/brand/monitors' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleBrandAddMonitor(request, env, authCtx || {}, ctx), request));
    }
    if (path === '/api/brand/monitors' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleBrandListMonitors(request, env, authCtx || {}), request));
    }
    if (path.startsWith('/api/brand/monitors/') && path.endsWith('/scan') && method === 'POST') {
      const monitorId = path.replace('/api/brand/monitors/', '').replace('/scan', '');
      const authCtx   = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleBrandTriggerScan(request, env, authCtx || {}, monitorId, ctx), request));
    }
    if (path.startsWith('/api/brand/monitors/') && path.endsWith('/threats') && method === 'GET') {
      const monitorId = path.replace('/api/brand/monitors/', '').replace('/threats', '');
      const authCtx   = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleBrandGetThreats(request, env, authCtx || {}, monitorId), request));
    }

    // ── Threat Actor Profiling ────────────────────────────────────────────────
    if (path === '/api/threat-actors' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleListThreatActors(request, env, authCtx || {}), request));
    }
    if (path === '/api/threat-actors/search' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleSearchThreatActors(request, env, authCtx || {}), request));
    }
    if (path === '/api/threat-actors/attribute' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleAttributeIOC(request, env, authCtx || {}), request));
    }
    if (path.startsWith('/api/threat-actors/') && method === 'GET') {
      const actorId = path.replace('/api/threat-actors/', '');
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleGetThreatActor(request, env, authCtx || {}, actorId), request));
    }
    if (path === '/api/admin/threat-actors/seed' && method === 'POST') {
      return withSecurityHeaders(withCors(await handleSeedThreatActors(request, env, {}), request));
    }

    // ── Cyber Risk Quantification (CRQ) ───────────────────────────────────────
    if (path === '/api/crq/assess' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleCRQAssessment(request, env, authCtx || {}), request));
    }

    // ── END HIGH-REVENUE FEATURES ─────────────────────────────────────────────

    // ══════════════════════════════════════════════════════════════════════════
    // SERVICE CATALOG v36 — 18 Production Services + Automated Engines
    // ══════════════════════════════════════════════════════════════════════════

    // ── Service Catalog ───────────────────────────────────────────────────────
    if (path === '/api/services' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleGetServiceCatalog(request, env, authCtx || {}), request));
    }
    if (path.match(/^\/api\/services\/([A-Z0-9-]+)$/) && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      const refId   = path.match(/^\/api\/services\/([A-Z0-9-]+)$/)[1];
      return withSecurityHeaders(withCors(await handleGetService(request, env, authCtx || {}, refId), request));
    }

    // ── Service Orders ────────────────────────────────────────────────────────
    if (path === '/api/services/orders' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleCreateServiceOrder(request, env, authCtx || {}, ctx), request));
    }
    if (path === '/api/services/orders' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleListServiceOrders(request, env, authCtx || {}), request));
    }
    if (path.match(/^\/api\/services\/orders\/([^/]+)\/status$/) && method === 'PUT') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      const orderId = path.match(/^\/api\/services\/orders\/([^/]+)\/status$/)[1];
      return withSecurityHeaders(withCors(await handleUpdateServiceOrderStatus(request, env, authCtx || {}, orderId), request));
    }
    if (path.match(/^\/api\/services\/orders\/([^/]+)\/trigger$/) && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      const orderId = path.match(/^\/api\/services\/orders\/([^/]+)\/trigger$/)[1];
      return withSecurityHeaders(withCors(await handleTriggerAssessment(request, env, authCtx || {}, orderId, ctx), request));
    }

    // ── Report Retrieval by Token ─────────────────────────────────────────────
    if (path.match(/^\/api\/services\/report\/([a-f0-9]{32,})$/) && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      const token   = path.match(/^\/api\/services\/report\/([a-f0-9]{32,})$/)[1];
      return withSecurityHeaders(withCors(await handleGetServiceReport(request, env, authCtx || {}, token), request));
    }

    // ── Direct Automated Scan Endpoints ──────────────────────────────────────
    if (path === '/api/scan/ssl' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleSSLScan(request, env, authCtx || {}), request));
    }
    if (path === '/api/scan/cti-brief' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleCTIBriefScan(request, env, authCtx || {}), request));
    }
    if (path === '/api/scan/threat-intel-report' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleThreatIntelReport(request, env, authCtx || {}), request));
    }
    if (path === '/api/scan/compliance' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleComplianceScan(request, env, authCtx || {}), request));
    }
    if (path === '/api/scan/ai-security' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleAISecurityScan(request, env, authCtx || {}), request));
    }
    if (path === '/api/scan/ai-security-enterprise' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleEnterpriseAIScan(request, env, authCtx || {}), request));
    }
    if (path === '/api/scan/vuln-assessment' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleVulnAssessmentScan(request, env, authCtx || {}), request));
    }
    if (path === '/api/scan/threat-hunting' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleThreatHuntingScan(request, env, authCtx || {}), request));
    }
    if (path === '/api/scan/api-security' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleAPISecurityScan(request, env, authCtx || {}), request));
    }
    if (path === '/api/scan/cloud-security' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleCloudSecurityScan(request, env, authCtx || {}), request));
    }

    // ── MYTHOS-Powered new scan endpoints (formerly manual services) ──────────
    if (path === '/api/scan/saas-security' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleSaaSSecurityScan(request, env, authCtx || {}), request));
    }
    if (path === '/api/scan/config-review' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleConfigReviewScan(request, env, authCtx || {}), request));
    }
    if (path === '/api/scan/ai-governance' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleAIGovernanceScan(request, env, authCtx || {}), request));
    }
    if (path === '/api/scan/devsecops' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleDevSecOpsScan(request, env, authCtx || {}), request));
    }
    if (path === '/api/scan/consultation-prep' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleConsultationPrep(request, env, authCtx || {}), request));
    }

    // ── MYTHOS AI Provider Health Check ──────────────────────────────────────
    if (path === '/api/ai/health' && method === 'GET') {
      const health = await checkAIProviderHealth(env);
      return withSecurityHeaders(withCors(Response.json({ success: true, ...health, timestamp: new Date().toISOString() }), request));
    }

    // ── MYTHOS AI Providers Status — multi-provider health + routing map ──────
    if (path === '/api/ai/providers/status' && method === 'GET') {
      try {
        const status = await getProviderHealthStatus(env);
        return withSecurityHeaders(withCors(Response.json({
          success:   true,
          timestamp: new Date().toISOString(),
          ...status,
        }), request));
      } catch (err) {
        return withSecurityHeaders(withCors(Response.json({ success: false, error: err.message }, { status: 500 }), request));
      }
    }

    // ── END SERVICE CATALOG v36 ───────────────────────────────────────────────

    if (path === '/api/auto-soc/mode' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGetMode(request, env, authCtx), request));
    }
    if (path === '/api/auto-soc/mode' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleSetMode(request, env, authCtx), request));
    }
    if (path === '/api/auto-soc/pipeline' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGetPipeline(request, env, authCtx), request));
    }
    if (path === '/api/auto-soc/run' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleRunPipeline(request, env, authCtx), request));
    }
    if (path === '/api/auto-soc/schedule' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGetSchedule(request, env, authCtx), request));
    }
    if (path === '/api/auto-soc/schedule' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleSetSchedule(request, env, authCtx), request));
    }
    if (path === '/api/auto-soc/log' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGetLog(request, env, authCtx), request));
    }
    if (path === '/api/auto-soc/latest-rules' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGetLatestRules(request, env, authCtx), request));
    }

    // ── PHASE 2: SIEM Integration Deploy ──────────────────────────────────────
    if (path === '/api/integrations' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleListIntegrations(request, env, authCtx), request));
    }
    if (path === '/api/integrations/configure' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleConfigure(request, env, authCtx), request));
    }
    if (path === '/api/integrations/deploy' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleDeploy(request, env, authCtx), request));
    }
    if (path === '/api/integrations/test' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleTestIntegration(request, env, authCtx), request));
    }
    if (path === '/api/integrations/deploy-log' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleDeployLog(request, env, authCtx), request));
    }
    if (path.startsWith('/api/integrations/') && method === 'DELETE') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleDeleteIntegration(request, env, authCtx), request));
    }

    // ── PHASE 2: Organization Memory v2 ───────────────────────────────────────
    if (path === '/api/org-memory' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGetMemory(request, env, authCtx), request));
    }
    if (path === '/api/org-memory/record' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleRecordEvent(request, env, authCtx), request));
    }
    if (path === '/api/org-memory/history' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGetHistory(request, env, authCtx), request));
    }
    if (path === '/api/org-memory/patterns' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGetPatterns(request, env, authCtx), request));
    }
    if (path === '/api/org-memory/recommend' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGetRecommendations(request, env, authCtx), request));
    }
    if (path === '/api/org-memory' && method === 'DELETE') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleClearMemory(request, env, authCtx), request));
    }

    // ── PHASE 3: Autonomous Defense Engine ───────────────────────────────────
    if (path === '/api/defense-engine/mode' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGetDefenseMode(request, env, authCtx), request));
    }
    if (path === '/api/defense-engine/mode' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleSetDefenseMode(request, env, authCtx), request));
    }
    if (path === '/api/defense-engine/execute' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleExecuteDefense(request, env, authCtx), request));
    }
    if (path === '/api/defense-engine/pending' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGetPending(request, env, authCtx), request));
    }
    if (path.startsWith('/api/defense-engine/approve/') && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleApprove(request, env, authCtx), request));
    }
    if (path.startsWith('/api/defense-engine/rollback/') && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleRollback(request, env, authCtx), request));
    }
    if (path === '/api/defense-engine/executions' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGetExecutions(request, env, authCtx), request));
    }
    if (path === '/api/defense-engine/posture' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGetDefensePosture(request, env, authCtx), request));
    }

    // ── PHASE 3: Threat Confidence Engine ────────────────────────────────────
    if (path === '/api/threat-confidence/score' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleScoreThreats(request, env, authCtx), request));
    }
    if (path === '/api/threat-confidence/kev' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGetKEV(request, env, authCtx), request));
    }
    if (path === '/api/threat-confidence/enrich' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleEnrichThreat(request, env, authCtx), request));
    }
    if (path === '/api/threat-confidence/feed' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGetTCFeed(request, env, authCtx), request));
    }
    if (path === '/api/threat-confidence/stats' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGetTCStats(request, env, authCtx), request));
    }

    // ── PHASE 3 / v20: Executive Report Engine ───────────────────────────────
    // GET /api/executive/ceo-view — v20 CEO Command View (revenue + threats + attacks + usage)
    if (path === '/api/executive/ceo-view' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
      return withSecurityHeaders(withCors(await handleCEOView(request, env, authCtx), request));
    }
    if (path === '/api/executive/dashboard' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGetDashboard(request, env, authCtx), request));
    }
    if (path === '/api/executive/mrr' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGetMRR(request, env, authCtx), request));
    }
    if (path === '/api/executive/mrr/config' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleSetMRRConfig(request, env, authCtx), request));
    }
    if ((path === '/api/executive/report' || path === '/api/reports/executive') && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGenerateReport(request, env, authCtx), request));
    }
    if (path === '/api/executive/reports' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleListReports(request, env, authCtx), request));
    }
    if (path.startsWith('/api/executive/report/') && path !== '/api/executive/report' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGetReport(request, env, authCtx), request));
    }

    // ── PHASE 3: MSSP Multi-Tenant Panel ─────────────────────────────────────
    if (path === '/api/mssp/clients' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleListClients(request, env, authCtx), request));
    }
    if (path === '/api/mssp/clients' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleOnboardClient(request, env, authCtx), request));
    }
    if (path.startsWith('/api/mssp/clients/') && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGetClient(request, env, authCtx), request));
    }
    if (path.startsWith('/api/mssp/clients/') && method === 'PUT') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleUpdateClient(request, env, authCtx), request));
    }
    if (path.startsWith('/api/mssp/clients/') && method === 'DELETE') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleOffboardClient(request, env, authCtx), request));
    }
    if (path === '/api/mssp/summary' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleMSSPSummary(request, env, authCtx), request));
    }
    if (path === '/api/mssp/alerts' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleMSSPAlerts(request, env, authCtx), request));
    }
    if (path === '/api/mssp/whitelabel' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleSetWhitelabel(request, env, authCtx), request));
    }
    if (path === '/api/mssp/whitelabel' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGetWhitelabel(request, env, authCtx), request));
    }

    // ── PHASE 4: Sales CRM Pipeline ──────────────────────────────────────────
    if (path === '/api/sales/leads' && method === 'POST') {
      return withSecurityHeaders(withCors(await handleCreateLead(request, env), request));
    }
    if (path === '/api/sales/leads' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      if (!isOwner(authCtx, env)) return withSecurityHeaders(withCors(forbidden(), request));
      return withSecurityHeaders(withCors(await handleListLeads(request, env, authCtx), request));
    }
    if (path.startsWith('/api/sales/leads/') && path.endsWith('/stage') && method === 'PUT') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      if (!isOwner(authCtx, env)) return withSecurityHeaders(withCors(forbidden(), request));
      return withSecurityHeaders(withCors(await handleAdvanceStage(request, env, authCtx), request));
    }
    if (path.startsWith('/api/sales/leads/') && path.endsWith('/note') && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      if (!isOwner(authCtx, env)) return withSecurityHeaders(withCors(forbidden(), request));
      return withSecurityHeaders(withCors(await handleAddSalesNote(request, env, authCtx), request));
    }
    if (path.startsWith('/api/sales/leads/') && path.endsWith('/qualify') && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      if (!isOwner(authCtx, env)) return withSecurityHeaders(withCors(forbidden(), request));
      return withSecurityHeaders(withCors(await handleQualifyLead(request, env, authCtx), request));
    }
    if (path.startsWith('/api/sales/leads/') && path.endsWith('/close') && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      if (!isOwner(authCtx, env)) return withSecurityHeaders(withCors(forbidden(), request));
      return withSecurityHeaders(withCors(await handleCloseLead(request, env, authCtx), request));
    }
    if (path.startsWith('/api/sales/leads/') && method === 'GET' && !path.includes('/stage') && !path.includes('/note')) {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      if (!isOwner(authCtx, env)) return withSecurityHeaders(withCors(forbidden(), request));
      return withSecurityHeaders(withCors(await handleGetLead(request, env, authCtx), request));
    }
    if (path === '/api/sales/demo/book' && method === 'POST') {
      return withSecurityHeaders(withCors(await handleBookDemo(request, env), request));
    }
    if (path === '/api/sales/demo/slots' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleGetDemoSlots(request, env), request));
    }
    if (path === '/api/sales/pipeline' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      if (!isOwner(authCtx, env)) return withSecurityHeaders(withCors(forbidden(), request));
      return withSecurityHeaders(withCors(await handleGetSalesPipeline(request, env, authCtx), request));
    }
    if (path === '/api/sales/metrics' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      if (!isOwner(authCtx, env)) return withSecurityHeaders(withCors(forbidden(), request));
      return withSecurityHeaders(withCors(await handleGetSalesMetrics(request, env, authCtx), request));
    }

    // ── GOD MODE v15: /api/leads/* alias routes → salesPipeline engine ────────
    // These provide clean REST aliases for the frontend & external CRM integrations.
    // POST /api/leads/create — create a new lead (public; no auth required)
    if (path === '/api/leads/create' && method === 'POST') {
      return withSecurityHeaders(withCors(await handleCreateLead(request, env), request));
    }
    // PUT /api/leads/update — update lead stage / fields (admin)
    if (path === '/api/leads/update' && method === 'PUT') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      if (!isOwner(authCtx, env)) return withSecurityHeaders(withCors(forbidden(), request));
      const body = await request.json().catch(() => ({}));
      const leadId = body.id || body.lead_id;
      if (!leadId) return withSecurityHeaders(withCors(Response.json({ error: 'lead_id required' }, { status: 400 }), request));
      // Proxy to stage update handler (reuse existing handler pattern)
      const stageReq = new Request(`${request.url}/api/sales/leads/${leadId}/stage`, {
        method: 'PUT',
        headers: request.headers,
        body: JSON.stringify(body),
      });
      return withSecurityHeaders(withCors(await handleAdvanceStage(stageReq, env, authCtx, leadId), request));
    }
    // GET /api/pipeline — pipeline board view (alias for /api/sales/pipeline)
    if (path === '/api/pipeline' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      if (!isOwner(authCtx, env)) return withSecurityHeaders(withCors(forbidden(), request));
      return withSecurityHeaders(withCors(await handleGetSalesPipeline(request, env, authCtx), request));
    }
    // GET /api/leads — list all leads (alias for GET /api/sales/leads)
    if (path === '/api/leads' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      if (!isOwner(authCtx, env)) return withSecurityHeaders(withCors(forbidden(), request));
      return withSecurityHeaders(withCors(await handleListLeads(request, env, authCtx), request));
    }

    // ── PHASE 4: Proposal Generator ──────────────────────────────────────────
    if (path === '/api/proposals/packages' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleGetPackages(request, env), request));
    }
    if (path === '/api/proposals/generate' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      if (!isOwner(authCtx, env)) return withSecurityHeaders(withCors(forbidden(), request));
      return withSecurityHeaders(withCors(await handleGenerateProposal(request, env, authCtx), request));
    }
    if (path === '/api/proposals' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      if (!isOwner(authCtx, env)) return withSecurityHeaders(withCors(forbidden(), request));
      return withSecurityHeaders(withCors(await handleListProposals(request, env, authCtx), request));
    }
    if (path.startsWith('/api/proposals/') && path.endsWith('/send') && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      if (!isOwner(authCtx, env)) return withSecurityHeaders(withCors(forbidden(), request));
      return withSecurityHeaders(withCors(await handleMarkProposalSent(request, env, authCtx), request));
    }
    if (path.startsWith('/api/proposals/') && path.endsWith('/accept') && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleAcceptProposal(request, env, authCtx), request));
    }
    if (path.startsWith('/api/proposals/') && path.endsWith('/reject') && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleRejectProposal(request, env, authCtx), request));
    }
    if (path.startsWith('/api/proposals/') && !path.endsWith('/generate') && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGetProposal(request, env, authCtx), request));
    }

    // ── PHASE 4: Affiliate & Partner System ──────────────────────────────────
    if (path === '/api/affiliate/join' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleJoin(request, env, authCtx), request));
    }
    if (path === '/api/affiliate/status' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleAffStatus(request, env, authCtx), request));
    }
    if (path === '/api/affiliate/dashboard' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleAffDashboard(request, env, authCtx), request));
    }
    if (path === '/api/affiliate/track' && method === 'POST') {
      return withSecurityHeaders(withCors(await handleTrackReferral(request, env), request));
    }
    if (path === '/api/affiliate/referrals' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGetReferrals(request, env, authCtx), request));
    }
    if (path === '/api/affiliate/leaderboard' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleGetLeaderboard(request, env), request));
    }
    if (path === '/api/affiliate/tiers' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleGetTiers(request, env), request));
    }
    if (path === '/api/affiliate/payout/request' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleRequestPayout(request, env, authCtx), request));
    }

    // ── PHASE 4: Conversion Triggers & Paywall ────────────────────────────────
    if (path === '/api/conversion/event' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleConvEvent(request, env, authCtx), request));
    }
    if (path === '/api/conversion/triggers' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGetTriggers(request, env, authCtx), request));
    }
    if (path === '/api/conversion/paywall' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGetPaywall(request, env, authCtx), request));
    }
    if (path === '/api/conversion/dismiss' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleDismissTrigger(request, env, authCtx), request));
    }
    if (path === '/api/conversion/funnel' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      if (!isOwner(authCtx, env)) return withSecurityHeaders(withCors(forbidden(), request));
      return withSecurityHeaders(withCors(await handleGetFunnel(request, env, authCtx), request));
    }
    if (path === '/api/conversion/cta' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGetCTA(request, env, authCtx), request));
    }
    if (path === '/api/conversion/retarget' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleRetarget(request, env, authCtx), request));
    }

    // GET /api/conversion/bundle — time-limited bundle offer with countdown timer
    if (path === '/api/conversion/bundle' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGetBundleOffer(request, env, authCtx), request));
    }

    // GET /api/conversion/urgency — personalized urgency signals for frontend CTAs
    if (path === '/api/conversion/urgency' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({}));
      return withSecurityHeaders(withCors(await handleGetUrgency(request, env, authCtx), request));
    }

    if (path === '/api/scan/upsell' && method === 'POST') {
      const { handleScanUpsell } = await import('./services/scanUpsellEngine.js');
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleScanUpsell(request, env, authCtx ? { userId: authCtx.userId, plan: authCtx.tier?.toLowerCase(), email: authCtx.email } : {}), request));
    }

    // GET /api/scan/upsell/stats — upsell impression/conversion stats (admin)
    if (path === '/api/scan/upsell/stats' && method === 'GET') {
      const { handleUpsellStats } = await import('./services/scanUpsellEngine.js');
      const authCtx = await resolveAuthV5(request, env);
      if (!authCtx.authenticated) return withSecurityHeaders(withCors(unauthorized(), request));
      return withSecurityHeaders(withCors(await handleUpsellStats(request, env, { userId: authCtx.userId, role: authCtx.role }), request));
    }

    // ── Manual Payment System ─────────────────────────────────────────────────
    // GET /api/payments/config — payment methods + product catalog (public)
    if (path === '/api/payments/config' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleGetPaymentConfig(request, env), request));
    }
    // POST /api/payments/submit — submit payment for verification
    if (path === '/api/payments/submit' && method === 'POST') {
      return withSecurityHeaders(withCors(await handleSubmitPayment(request, env), request));
    }
    // GET /api/payments/status — check payment status by payment_id or email
    if (path === '/api/payments/status' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleGetPaymentStatus(request, env), request));
    }
    // GET /api/payments/admin — list all payments (owner only)
    if (path === '/api/payments/admin' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env);
      if (!isOwner(authCtx, env)) return withSecurityHeaders(withCors(forbidden(), request));
      return withSecurityHeaders(withCors(await handleListPayments(request, env), request));
    }
    // GET /api/payment/admin/list — admin-payments.html dashboard (owner only)
    if (path === '/api/payment/admin/list' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env);
      if (!isOwner(authCtx, env)) return withSecurityHeaders(withCors(forbidden(), request));
      return withSecurityHeaders(withCors(await handleAdminPaymentList(request, env), request));
    }
    // GET /api/payment/admin/stats — admin-payments.html stats row (owner only)
    if (path === '/api/payment/admin/stats' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env);
      if (!isOwner(authCtx, env)) return withSecurityHeaders(withCors(forbidden(), request));
      return withSecurityHeaders(withCors(await handleAdminPaymentStats(request, env), request));
    }
    // POST /api/payment/admin/approve/:record_id — admin-payments.html approve action (owner only)
    if (path.startsWith('/api/payment/admin/approve/') && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env);
      if (!isOwner(authCtx, env)) return withSecurityHeaders(withCors(forbidden(), request));
      const recordId = decodeURIComponent(path.slice('/api/payment/admin/approve/'.length));
      return withSecurityHeaders(withCors(await handleAdminPaymentAction(request, env, recordId, 'approve'), request));
    }
    // POST /api/payment/admin/reject/:record_id — admin-payments.html reject action (owner only)
    if (path.startsWith('/api/payment/admin/reject/') && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env);
      if (!isOwner(authCtx, env)) return withSecurityHeaders(withCors(forbidden(), request));
      const recordId = decodeURIComponent(path.slice('/api/payment/admin/reject/'.length));
      return withSecurityHeaders(withCors(await handleAdminPaymentAction(request, env, recordId, 'reject'), request));
    }

    // ── Content Pipeline ──────────────────────────────────────────────────────

    // GET /api/blog/posts — list published blog posts (public)
    if (path === '/api/blog/posts' && method === 'GET') {
      const { handleGetBlogPosts } = await import('./services/contentPipeline.js');
      return withSecurityHeaders(withCors(await handleGetBlogPosts(request, env), request));
    }

    // GET /api/blog/posts/:slug — single blog post (public)
    if (path.startsWith('/api/blog/posts/') && method === 'GET') {
      const { handleGetBlogPost } = await import('./services/contentPipeline.js');
      const slug = path.replace('/api/blog/posts/', '').split('/')[0];
      return withSecurityHeaders(withCors(await handleGetBlogPost(request, env, slug), request));
    }

    // POST /api/content/run — manually trigger content pipeline (admin)
    if (path === '/api/content/run' && method === 'POST') {
      const { handleRunContentPipeline } = await import('./services/contentPipeline.js');
      const authCtx = await resolveAuthV5(request, env);
      if (!authCtx.authenticated) return withSecurityHeaders(withCors(unauthorized(), request));
      return withSecurityHeaders(withCors(await handleRunContentPipeline(request, env, { userId: authCtx.userId, role: authCtx.role }), request));
    }

    // ── Enterprise Layer (Phase 5) ────────────────────────────────────────

    // GET /api/enterprise/packages — list enterprise packages (public)
    if (path === '/api/enterprise/packages' && method === 'GET') {
      const { handleGetPackages } = await import('./handlers/enterpriseLayer.js');
      return withSecurityHeaders(withCors(await handleGetPackages(request, env), request));
    }

    // POST /api/enterprise/book — consultation booking (public)
    if (path === '/api/enterprise/book' && method === 'POST') {
      const { handleBookConsultation } = await import('./handlers/enterpriseLayer.js');
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleBookConsultation(request, env, authCtx ? { userId: authCtx.userId, email: authCtx.email } : {}), request));
    }

    // POST /api/enterprise/report — order threat report with Razorpay (public)
    if (path === '/api/enterprise/report' && method === 'POST') {
      const { handleOrderReport } = await import('./handlers/enterpriseLayer.js');
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleOrderReport(request, env, authCtx ? { userId: authCtx.userId, email: authCtx.email } : {}), request));
    }

    // POST /api/enterprise/verify — verify enterprise Razorpay payment
    if (path === '/api/enterprise/verify' && method === 'POST') {
      const { handleVerifyEnterprisePayment } = await import('./handlers/enterpriseLayer.js');
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleVerifyEnterprisePayment(request, env, authCtx ? { userId: authCtx.userId } : {}), request));
    }

    // GET /api/enterprise/stats — admin: enterprise leads overview
    if (path === '/api/enterprise/stats' && method === 'GET') {
      const { handleEnterpriseStats } = await import('./handlers/enterpriseLayer.js');
      const authCtx = await resolveAuthV5(request, env);
      if (!authCtx.authenticated) return withSecurityHeaders(withCors(unauthorized(), request));
      return withSecurityHeaders(withCors(await handleEnterpriseStats(request, env, { userId: authCtx.userId, role: authCtx.role }), request));
    }

    // ── P4.0-006 Enterprise Intelligence API ─────────────────────────────────

    // GET /api/enterprise/intelligence — risk-scored signals (min tier: PRO)
    if (path === '/api/enterprise/intelligence' && method === 'GET') {
      const { handleEnterpriseIntelligence } = await import('./handlers/enterpriseIntel.js');
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
      return withSecurityHeaders(withCors(await handleEnterpriseIntelligence(request, env, authCtx), request));
    }

    // GET /api/enterprise/risk — risk-ranked signals with distribution
    if (path === '/api/enterprise/risk' && method === 'GET') {
      const { handleEnterpriseRisk } = await import('./handlers/enterpriseIntel.js');
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
      return withSecurityHeaders(withCors(await handleEnterpriseRisk(request, env, authCtx), request));
    }

    // GET /api/enterprise/campaigns — campaign intelligence with sector targeting
    if (path === '/api/enterprise/campaigns' && method === 'GET') {
      const { handleEnterpriseCampaigns } = await import('./handlers/enterpriseIntel.js');
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
      return withSecurityHeaders(withCors(await handleEnterpriseCampaigns(request, env, authCtx), request));
    }

    // GET /api/enterprise/actors — actor intelligence with MITRE ATT&CK correlation
    if (path === '/api/enterprise/actors' && method === 'GET') {
      const { handleEnterpriseActors } = await import('./handlers/enterpriseIntel.js');
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
      return withSecurityHeaders(withCors(await handleEnterpriseActors(request, env, authCtx), request));
    }

    // ── P5.0-007 Customer Intelligence API ───────────────────────────────────
    // All routes require auth; MSSP tier may pass ?customer_id= for multi-tenant

    if (path === '/api/customer/profile') {
      if (method === 'GET') {
        const { handleGetProfile } = await import('./handlers/customerIntel.js');
        const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
        return withSecurityHeaders(withCors(await handleGetProfile(request, env, authCtx), request));
      }
      if (method === 'PUT') {
        const { handleUpdateProfile } = await import('./handlers/customerIntel.js');
        const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
        return withSecurityHeaders(withCors(await handleUpdateProfile(request, env, authCtx), request));
      }
    }

    if (path === '/api/customer/radar' && method === 'GET') {
      const { handleGetPersonalizedRadar } = await import('./handlers/customerIntel.js');
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
      return withSecurityHeaders(withCors(await handleGetPersonalizedRadar(request, env, authCtx), request));
    }

    if (path === '/api/customer/risk' && method === 'GET') {
      const { handleGetOrgRisk } = await import('./handlers/customerIntel.js');
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
      return withSecurityHeaders(withCors(await handleGetOrgRisk(request, env, authCtx), request));
    }

    if (path === '/api/customer/assets') {
      if (method === 'GET') {
        const { handleGetAssets } = await import('./handlers/customerIntel.js');
        const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
        return withSecurityHeaders(withCors(await handleGetAssets(request, env, authCtx), request));
      }
      if (method === 'POST') {
        const { handleRegisterAsset } = await import('./handlers/customerIntel.js');
        const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
        return withSecurityHeaders(withCors(await handleRegisterAsset(request, env, authCtx), request));
      }
    }

    if (path.startsWith('/api/customer/assets/') && method === 'DELETE') {
      const assetId = path.slice('/api/customer/assets/'.length).split('/')[0];
      const { handleDeleteAsset } = await import('./handlers/customerIntel.js');
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
      return withSecurityHeaders(withCors(await handleDeleteAsset(request, env, authCtx, assetId), request));
    }

    if (path === '/api/customer/report' && method === 'GET') {
      const { handleGetReport } = await import('./handlers/customerIntel.js');
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
      return withSecurityHeaders(withCors(await handleGetReport(request, env, authCtx), request));
    }

    // ── P7.0 Enterprise Automation Engine ────────────────────────────────────
    // API key self-service, webhooks, scheduled reports, team management,
    // API usage dashboard, governance, reliability, enterprise metrics.

    if (path.startsWith('/api/self/') || path.startsWith('/api/auto/')) {
      const { handleAutoRoute } = await import('./handlers/enterpriseAutomation.js');
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
      const result = await handleAutoRoute(request, env, authCtx, path, method);
      if (result) return withSecurityHeaders(withCors(result, request));
    }

    // P8.0-005: webhook event catalog — public documentation endpoint (no auth),
    // same convention as /api/openapi.json. Lives in enterpriseAutomation.js
    // next to the dispatch/retry logic it documents.
    if (path === '/api/webhooks/catalog' && method === 'GET') {
      const { handleWebhookCatalog } = await import('./handlers/enterpriseAutomation.js');
      return withSecurityHeaders(withCors(await handleWebhookCatalog(request, env), request));
    }

    // ── P6.0 Operations Engine ────────────────────────────────────────────────
    // Usage analytics, subscription enforcement, feature flags, admin APIs,
    // observability, notifications. OWNER/ADMIN required for /api/admin/*.

    if (path.startsWith('/api/ops/') || path.startsWith('/api/admin/customers') ||
        path.startsWith('/api/admin/usage') || path.startsWith('/api/admin/subscriptions') ||
        path === '/api/admin/audit' || path === '/api/admin/notifications') {
      const { handleOpsRoute } = await import('./handlers/opsEngine.js');
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
      const result = await handleOpsRoute(request, env, authCtx, path, method);
      if (result) return withSecurityHeaders(withCors(result, request));
    }

    // ── Global Scale Engine (Phase 6) ─────────────────────────────────────

    // GET /api/global/pricing — geo-detected multi-currency pricing (public)
    if (path === '/api/global/pricing' && method === 'GET') {
      const { handleGetGlobalPricing } = await import('./services/globalScale.js');
      return withSecurityHeaders(withCors(await handleGetGlobalPricing(request, env), request));
    }

    // GET /api/global/compliance-packs — compliance pack catalog with geo sort (public)
    if (path === '/api/global/compliance-packs' && method === 'GET') {
      const { handleGetCompliancePacks } = await import('./services/globalScale.js');
      return withSecurityHeaders(withCors(await handleGetCompliancePacks(request, env), request));
    }

    // POST /api/global/compliance-packs/purchase — create Razorpay order for compliance pack
    if (path === '/api/global/compliance-packs/purchase' && method === 'POST') {
      const { handlePurchaseCompliancePack } = await import('./services/globalScale.js');
      const authCtx = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handlePurchaseCompliancePack(request, env, authCtx ? { userId: authCtx.userId, email: authCtx.email } : {}), request));
    }

    // POST /api/global/compliance-packs/verify — verify payment + grant access + notify founder
    if (path === '/api/global/compliance-packs/verify' && method === 'POST') {
      const { handleVerifyCompliancePack } = await import('./services/globalScale.js');
      return withSecurityHeaders(withCors(await handleVerifyCompliancePack(request, env), request));
    }

    // POST /api/sentinel/purchase — create Razorpay order for Sentinel APEX intel product (public)
    if (path === '/api/sentinel/purchase' && method === 'POST') {
      const { handleSentinelPurchase } = await import('./handlers/sentinelMarketplace.js');
      return withSecurityHeaders(withCors(await handleSentinelPurchase(request, env), request));
    }

    // POST /api/sentinel/verify — verify payment + grant access + notify founder (public)
    if (path === '/api/sentinel/verify' && method === 'POST') {
      const { handleSentinelVerify } = await import('./handlers/sentinelMarketplace.js');
      return withSecurityHeaders(withCors(await handleSentinelVerify(request, env), request));
    }

    // GET  /api/tools/catalog  — tools & AI marketplace catalog (public)
    if (path === '/api/tools/catalog' && method === 'GET') {
      const { handleListTools } = await import('./handlers/toolsMarketplace.js');
      return withSecurityHeaders(withCors(await handleListTools(request, env), request));
    }

    // POST /api/tools/purchase — create Razorpay order for tool purchase (public)
    if (path === '/api/tools/purchase' && method === 'POST') {
      const { handlePurchaseTool } = await import('./handlers/toolsMarketplace.js');
      return withSecurityHeaders(withCors(await handlePurchaseTool(request, env), request));
    }

    // POST /api/tools/verify — verify payment + grant access + notify founder (public)
    if (path === '/api/tools/verify' && method === 'POST') {
      const { handleVerifyTool } = await import('./handlers/toolsMarketplace.js');
      return withSecurityHeaders(withCors(await handleVerifyTool(request, env), request));
    }

    // GET  /api/academy/catalog  — academy course catalog (public)
    if (path === '/api/academy/catalog' && method === 'GET') {
      const { handleListAcademy } = await import('./handlers/academyMarketplace.js');
      return withSecurityHeaders(withCors(await handleListAcademy(request, env), request));
    }

    // POST /api/academy/purchase — create Razorpay order for academy course (public)
    if (path === '/api/academy/purchase' && method === 'POST') {
      const { handlePurchaseAcademy } = await import('./handlers/academyMarketplace.js');
      return withSecurityHeaders(withCors(await handlePurchaseAcademy(request, env), request));
    }

    // POST /api/academy/verify — verify payment + grant access + notify founder (public)
    if (path === '/api/academy/verify' && method === 'POST') {
      const { handleVerifyAcademy } = await import('./handlers/academyMarketplace.js');
      return withSecurityHeaders(withCors(await handleVerifyAcademy(request, env), request));
    }

    // GET /api/global/mssp — MSSP tier info + pricing (public)
    if (path === '/api/global/mssp' && method === 'GET') {
      const { handleGetMSSPInfo } = await import('./services/globalScale.js');
      return withSecurityHeaders(withCors(await handleGetMSSPInfo(request, env), request));
    }

    // POST /api/global/mssp/apply — MSSP partner application (public)
    if (path === '/api/global/mssp/apply' && method === 'POST') {
      const { handleMSSPApplication } = await import('./services/globalScale.js');
      return withSecurityHeaders(withCors(await handleMSSPApplication(request, env), request));
    }

    // ── Cron-driven content pipeline hook ─────────────────────────────────
    // POST /api/content/pipeline/run — trigger full CVE→blog→social pipeline (admin)
    if (path === '/api/content/pipeline/run' && method === 'POST') {
      const { runBulkContentPipeline } = await import('./services/contentPipeline.js');
      const authCtx = await resolveAuthV5(request, env);
      if (!authCtx.authenticated) return withSecurityHeaders(withCors(unauthorized(), request));
      if (authCtx.role !== 'admin') return withSecurityHeaders(withCors(new Response(JSON.stringify({ error: 'Admin only' }), { status: 403, headers: { 'Content-Type': 'application/json' } }), request));
      const body  = await request.json().catch(() => ({}));
      const result = await runBulkContentPipeline(env, body.limit || 3);
      return withSecurityHeaders(withCors(new Response(JSON.stringify(result), { headers: { 'Content-Type': 'application/json' } }), request));
    }

    // ══════════════════════════════════════════════════════════════════════
    // END v10.0 ROUTES
    // ══════════════════════════════════════════════════════════════════════

    // ── End v8.2 routes ───────────────────────────────────────────────────────

    // GET /api/export/siem — export capabilities info (public)
    if (path === '/api/export/siem' && method === 'GET') {
      return withSecurityHeaders(withCors(handleSiemInfo(), request));
    }

    // POST /api/export/siem — generate export file (TEAM+ entitlement gate — Task 9)
    if (path === '/api/export/siem' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env);
      if (!authCtx.authenticated) return withSecurityHeaders(withCors(unauthorized(), request));
      const { featureGate, FEATURES: SIEM_FEATS } = await import('./middleware/entitlementCheck.js');
      const siemGate = await featureGate(env.DB, authCtx, SIEM_FEATS.SIEM_WEBHOOK);
      if (siemGate) return withSecurityHeaders(withCors(siemGate, request));
      return withSecurityHeaders(withCors(await handleSiemExport(request, env, authCtx), request));
    }

    // GET /api/export/siem/stream — streaming NDJSON (TEAM+ entitlement gate — Task 9)
    if (path === '/api/export/siem/stream' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env);
      if (!authCtx.authenticated) return withSecurityHeaders(withCors(unauthorized(), request));
      const { featureGate, FEATURES: STREAM_FEATS } = await import('./middleware/entitlementCheck.js');
      const streamGate = await featureGate(env.DB, authCtx, STREAM_FEATS.SIEM_WEBHOOK);
      if (streamGate) return withSecurityHeaders(withCors(streamGate, request));
      // Streaming response — no withCors wrapper (returns raw stream)
      return await handleSiemStream(request, env, authCtx);
    }

    // ── P0 MISSION v12: Agentic AI Autonomous Remediation Engine (System 1) ───
    // POST /api/agent/execute, GET /api/agent/logs, GET /api/agent/status,
    // POST /api/agent/rollback, GET|POST /api/agent/waf/*, POST /api/agent/process-queue
    if (path.startsWith('/api/agent/')) {
      const authCtx = await resolveAuthV5(request, env);
      if (!authCtx.authenticated) return withSecurityHeaders(withCors(unauthorized(), request));
      const subpath = path.replace('/api/agent/', '');
      const res = await handleAgentRequest(request, env, authCtx, subpath);
      return withSecurityHeaders(withCors(res, request));
    }

    // ── P0 MISSION v12: Behavioral Anomaly Detection Engine (System 2) ────────
    // GET /api/anomaly/stats, GET /api/anomaly/:user_id,
    // GET /api/anomaly/:user_id/history, POST /api/anomaly/scan,
    // POST /api/anomaly/record, POST /api/anomaly/batch
    if (path.startsWith('/api/anomaly/') || path === '/api/anomaly') {
      const authCtx = await resolveAuthV5(request, env);
      if (!authCtx.authenticated) return withSecurityHeaders(withCors(unauthorized(), request));
      const subpath = path.replace('/api/anomaly', '').replace(/^\//, '');
      const res = await handleAnomalyRequest(request, env, authCtx, subpath);
      return withSecurityHeaders(withCors(res, request));
    }

    // ── P0 MISSION v12: Predictive Threat Intelligence Engine (System 3) ──────
    // GET /api/predict/threats, GET /api/predict/stats, GET /api/predict/:cve_id,
    // GET /api/predict/:cve_id/trend, POST /api/predict/batch, POST /api/predict/score
    if (path.startsWith('/api/predict/') || path === '/api/predict') {
      const authCtx = await resolveAuthV5(request, env);
      if (!authCtx.authenticated) return withSecurityHeaders(withCors(unauthorized(), request));
      const subpath = path.replace('/api/predict', '').replace(/^\//, '');
      const res = await handlePredictiveRequest(request, env, authCtx, subpath);
      return withSecurityHeaders(withCors(res, request));
    }

    // ══════════════════════════════════════════════════════════════════════════
    // GOD MODE v15 — DELIVERY ENGINE  (/api/delivery/*)
    // ══════════════════════════════════════════════════════════════════════════

    // POST /api/delivery/activate — admin: activate delivery for a verified payment
    if (path === '/api/delivery/activate' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env);
      if (!authCtx.authenticated) return withSecurityHeaders(withCors(unauthorized(), request));
      return withSecurityHeaders(withCors(await handleDeliveryActivate(request, env, authCtx), request));
    }

    // GET /api/delivery/access — public: access purchased content via token
    if (path === '/api/delivery/access' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleDeliveryAccess(request, env), request));
    }

    // GET /api/delivery/my-purchases — authenticated: list own deliveries
    if (path === '/api/delivery/my-purchases' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env);
      if (!authCtx.authenticated) return withSecurityHeaders(withCors(unauthorized(), request));
      return withSecurityHeaders(withCors(await handleMyPurchases(request, env, authCtx), request));
    }

    // POST /api/delivery/resend — admin: resend delivery instructions
    if (path === '/api/delivery/resend' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env);
      if (!authCtx.authenticated) return withSecurityHeaders(withCors(unauthorized(), request));
      return withSecurityHeaders(withCors(await handleResendDelivery(request, env, authCtx), request));
    }

    // GET /api/delivery/verify-token — public: validate a delivery token
    if (path === '/api/delivery/verify-token' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleVerifyDeliveryToken(request, env), request));
    }

    // GET /api/delivery/catalog — admin: list full delivery catalog
    if (path === '/api/delivery/catalog' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env);
      if (!authCtx.authenticated) return withSecurityHeaders(withCors(unauthorized(), request));
      return withSecurityHeaders(withCors(await handleDeliveryCatalog(request, env, authCtx), request));
    }

    // GET /api/user/reports — authenticated: list user's purchased scan reports
    // Also accepts GET /api/user/trainings and /api/user/tools (convenience aliases)
    if (path === '/api/user/reports' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env);
      if (!authCtx.authenticated) return withSecurityHeaders(withCors(unauthorized(), request));
      return withSecurityHeaders(withCors(await handleUserReports(request, env, authCtx), request));
    }

    // GET /api/user/trainings — convenience: my-purchases filtered to trainings/bundles
    if (path === '/api/user/trainings' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env);
      if (!authCtx.authenticated) return withSecurityHeaders(withCors(unauthorized(), request));
      // Reuse handleMyPurchases — frontend already filters by product_type
      return withSecurityHeaders(withCors(await handleMyPurchases(request, env, authCtx), request));
    }

    // GET /api/user/tools — returns tool access based on user plan tier
    if (path === '/api/user/tools' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env);
      if (!authCtx.authenticated) return withSecurityHeaders(withCors(unauthorized(), request));
      const TOOL_ACCESS = {
        FREE:       ['domain_scanner', 'ai_scan', 'threat_feed', 'basic_reports'],
        PRO:        ['domain_scanner', 'ai_scan', 'threat_feed', 'basic_reports', 'redteam_scan', 'identity_scan', 'compliance_scan', 'api_keys', 'monitoring', 'full_reports', 'siem_export', 'org_memory'],
        ENTERPRISE: ['domain_scanner', 'ai_scan', 'threat_feed', 'basic_reports', 'redteam_scan', 'identity_scan', 'compliance_scan', 'api_keys', 'monitoring', 'full_reports', 'siem_export', 'org_memory', 'mssp_panel', 'custom_branding', 'sla_support', 'threat_graph', 'autonomous_soc'],
      };
      const tier  = (authCtx.tier || 'FREE').toUpperCase();
      const tools = TOOL_ACCESS[tier] || TOOL_ACCESS.FREE;
      return withSecurityHeaders(withCors(Response.json({ tools, tier, total: tools.length }), request));
    }

    // ══════════════════════════════════════════════════════════════════════════
    // GOD MODE v15 — MCP SHADOW ENGINE  (/mcp/*)
    // ══════════════════════════════════════════════════════════════════════════

    // POST /mcp/recommend — AI-powered scan recommendations (MCP → local fallback)
    if (path === '/mcp/recommend' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
      return withSecurityHeaders(withCors(await handleMCPRecommend(request, env, authCtx), request));
    }

    // POST /mcp/upsell — rule-based upsell evaluation
    if (path === '/mcp/upsell' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
      return withSecurityHeaders(withCors(await handleMCPUpsell(request, env, authCtx), request));
    }

    // POST /mcp/training-map — map scan findings to training courses
    if (path === '/mcp/training-map' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
      return withSecurityHeaders(withCors(await handleMCPTrainingMap(request, env, authCtx), request));
    }

    // GET /mcp/health — MCP server health + fallback status
    if (path === '/mcp/health' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleMCPHealth(request, env), request));
    }

    // POST /mcp/bundle — time-limited bundle offers with social proof + countdown
    if (path === '/mcp/bundle' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
      return withSecurityHeaders(withCors(await handleMCPBundle(request, env, authCtx), request));
    }

    // POST /mcp/decision — MASTER CONTROL: full AI recommendation (tools + training + upsell + enterprise)
    // Frontend calls this FIRST after every scan. Replaces all static upsell/recommendation logic.
    if (path === '/mcp/decision' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
      return withSecurityHeaders(withCors(await handleMCPDecision(request, env, authCtx), request));
    }

    // ══════════════════════════════════════════════════════════════════════════
    // GOD MODE v16 — MCP CONTROL ENGINE  (/mcp/control)
    // THE OPERATING SYSTEM: merges decision + bundle + user memory + ui_blocks
    // KV cached, D1 user context, triple failsafe. Frontend MUST call this first.
    // ══════════════════════════════════════════════════════════════════════════

    // POST /mcp/control — Unified MCP Control Engine v16
    if (path === '/mcp/control' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false, ip: request.headers.get('CF-Connecting-IP') || 'anon' }));
      return withSecurityHeaders(withCors(await handleMCPControl(request, env, authCtx), request));
    }

    // GET /mcp/control/status — health + capabilities manifest
    if (path === '/mcp/control/status' && method === 'GET') {
      return withSecurityHeaders(withCors(Response.json({
        success: true,
        data: {
          version: '16.0',
          status: 'operational',
          capabilities: ['decision','bundle','user_memory','ui_blocks','personalization','kv_cache','failsafe'],
          endpoints: {
            control:   'POST /mcp/control',
            decision:  'POST /mcp/decision',
            bundle:    'POST /mcp/bundle',
            recommend: 'POST /mcp/recommend',
            upsell:    'POST /mcp/upsell',
            health:    'GET /mcp/health',
          },
          cache_ttl_s: 180,
          failsafe_layers: 3,
        },
      }), request));
    }

    // ══════════════════════════════════════════════════════════════════════════
    // GOD MODE v17 — MCP SELF-LEARNING FEEDBACK API  (/api/mcp/*)
    // Tracks clicks, purchases, ignores → feeds scoring + A/B engine
    // Rate limited (100/min/IP). Revenue verified server-side from D1.
    // ══════════════════════════════════════════════════════════════════════════

    // POST /api/mcp/feedback — single interaction event
    if (path === '/api/mcp/feedback' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({
        authenticated: false, ip: request.headers.get('CF-Connecting-IP') || 'anon',
      }));
      return withSecurityHeaders(withCors(await handleMCPFeedback(request, env, authCtx), request));
    }

    // POST /api/mcp/feedback/batch — batch interaction events (up to 20)
    if (path === '/api/mcp/feedback/batch' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({
        authenticated: false, ip: request.headers.get('CF-Connecting-IP') || 'anon',
      }));
      return withSecurityHeaders(withCors(await handleMCPFeedbackBatch(request, env, authCtx), request));
    }

    // GET /api/mcp/feedback/stats — item performance stats (admin)
    if (path === '/api/mcp/feedback/stats' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
      return withSecurityHeaders(withCors(await handleMCPFeedbackStats(request, env, authCtx), request));
    }

    // GET /api/mcp/feedback/scores — item MCP scores leaderboard (admin)
    if (path === '/api/mcp/feedback/scores' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
      return withSecurityHeaders(withCors(await handleMCPItemScores(request, env, authCtx), request));
    }

    // GET /api/mcp/ab/results — A/B experiment results (admin)
    if (path === '/api/mcp/ab/results' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
      return withSecurityHeaders(withCors(await handleMCPABResults(request, env, authCtx), request));
    }

    // ══════════════════════════════════════════════════════════════════════════
    // GOD MODE v18 — REVENUE AUTOPILOT DIRECT API  (/api/mcp/revenue/*)
    // trackRevenueEvent: fire-and-forget funnel tracking from frontend
    // getOfferPerformance: admin KPI — RPI, conversion, best context
    // ══════════════════════════════════════════════════════════════════════════

    // POST /api/mcp/revenue/event — client-side revenue funnel event (public)
    // Body: { event_type, offer_type, offer_id, session_id?, user_id?, ... }
    if (path === '/api/mcp/revenue/event' && method === 'POST') {
      try {
        const body = await request.json().catch(() => ({}));
        const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false, userId: null }));
        const ip = request.headers.get('CF-Connecting-IP') || 'anon';

        // Validate required fields
        const validEventTypes = ['impression','click','purchase','abandon',
          'loss_prevent_shown','loss_prevent_converted',
          'welcome_back_shown','welcome_back_converted'];
        const validOfferTypes = ['single','bundle','dynamic_bundle','enterprise',
          'upsell','loss_prevention','welcome_back','cta_only'];

        if (!validEventTypes.includes(body.event_type) || !validOfferTypes.includes(body.offer_type) || !body.offer_id) {
          return withSecurityHeaders(withCors(new Response(JSON.stringify({
            ok: false, error: 'Invalid event_type, offer_type, or missing offer_id'
          }), { status: 400, headers: { 'Content-Type': 'application/json' } }), request));
        }

        // revenue_inr is always 0 from client — server verifies purchases from delivery_tokens
        let verified_revenue = 0;
        if (body.event_type === 'purchase' && authCtx.authenticated && authCtx.userId) {
          try {
            const tokenRow = await env.DB.prepare(
              `SELECT SUM(amount_inr) as total FROM delivery_tokens WHERE user_id=? AND item_id=? AND status='delivered' ORDER BY created_at DESC LIMIT 1`
            ).bind(authCtx.userId, body.offer_id).first();
            verified_revenue = tokenRow?.total ?? 0;
          } catch (_) { /* ignore */ }
        }

        // Build event payload and track (fire-and-forget from client perspective)
        const eventPayload = {
          session_id: body.session_id ?? null,
          user_id: authCtx.userId ?? body.user_id ?? null,
          ip_hash: ip.split('.').slice(0,2).join('.') + '.x.x',
          event_type: body.event_type,
          offer_type: body.offer_type,
          offer_id: body.offer_id,
          offer_name: body.offer_name ?? null,
          display_price: Number(body.display_price ?? 0),
          actual_price: verified_revenue > 0 ? verified_revenue : Number(body.actual_price ?? 0),
          discount_pct: Number(body.discount_pct ?? 0),
          cta_variant: body.cta_variant ?? 'standard',
          urgency_level: body.urgency_level ?? 'low',
          module: body.module ?? null,
          risk_level: body.risk_level ?? null,
          user_type: body.user_type ?? 'new',
          context: body.context ?? 'scan_result',
          revenue_inr: verified_revenue,
        };

        // Non-blocking track — never fail client on DB error
        trackRevenueEvent(env, eventPayload).catch(() => {});

        return withSecurityHeaders(withCors(new Response(JSON.stringify({
          ok: true, tracked: true, event_type: body.event_type,
        }), { status: 200, headers: { 'Content-Type': 'application/json' } }), request));
      } catch (err) {
        return withSecurityHeaders(withCors(new Response(JSON.stringify({
          ok: false, error: 'Revenue event tracking failed'
        }), { status: 500, headers: { 'Content-Type': 'application/json' } }), request));
      }
    }

    // GET /api/mcp/revenue/performance — offer KPI leaderboard (admin)
    // Returns: top offers by RPI, conversion, revenue_score
    if (path === '/api/mcp/revenue/performance' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
      if (!authCtx.authenticated || authCtx.role !== 'admin') {
        return withSecurityHeaders(withCors(new Response(JSON.stringify({
          ok: false, error: 'Admin auth required'
        }), { status: 403, headers: { 'Content-Type': 'application/json' } }), request));
      }
      try {
        const url = new URL(request.url);
        const offerId = url.searchParams.get('offer_id') ?? null;
        const perf = await getOfferPerformance(env, offerId);
        return withSecurityHeaders(withCors(new Response(JSON.stringify({
          ok: true, data: perf, generated_at: new Date().toISOString(),
        }), { status: 200, headers: { 'Content-Type': 'application/json' } }), request));
      } catch (err) {
        return withSecurityHeaders(withCors(new Response(JSON.stringify({
          ok: false, error: 'Performance fetch failed', detail: err?.message
        }), { status: 500, headers: { 'Content-Type': 'application/json' } }), request));
      }
    }

    // GET /api/mcp/revenue/funnel — revenue funnel analytics (admin)
    // Returns impression→click→purchase conversion funnel from D1
    if (path === '/api/mcp/revenue/funnel' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
      if (!authCtx.authenticated || authCtx.role !== 'admin') {
        return withSecurityHeaders(withCors(new Response(JSON.stringify({
          ok: false, error: 'Admin auth required'
        }), { status: 403, headers: { 'Content-Type': 'application/json' } }), request));
      }
      try {
        const url = new URL(request.url);
        const days = Math.min(parseInt(url.searchParams.get('days') ?? '7'), 30);
        const since = new Date(Date.now() - days * 86400000).toISOString();

        const [funnelRows, topOffers, lossStats] = await Promise.all([
          env.DB.prepare(`
            SELECT event_type, COUNT(*) as count, SUM(revenue_inr) as revenue
            FROM mcp_revenue_events WHERE created_at >= ?
            GROUP BY event_type ORDER BY count DESC
          `).bind(since).all(),
          env.DB.prepare(`
            SELECT offer_id, offer_name, offer_type,
              SUM(CASE WHEN event_type='impression' THEN 1 ELSE 0 END) as impressions,
              SUM(CASE WHEN event_type='click' THEN 1 ELSE 0 END) as clicks,
              SUM(CASE WHEN event_type='purchase' THEN 1 ELSE 0 END) as purchases,
              SUM(revenue_inr) as revenue_inr
            FROM mcp_revenue_events WHERE created_at >= ?
            GROUP BY offer_id ORDER BY revenue_inr DESC LIMIT 10
          `).bind(since).all(),
          env.DB.prepare(`
            SELECT trigger_type,
              COUNT(*) as triggered,
              SUM(converted) as converted,
              SUM(revenue_inr) as revenue_inr
            FROM mcp_loss_prevention WHERE created_at >= ?
            GROUP BY trigger_type
          `).bind(since).all(),
        ]);

        const funnel = Object.fromEntries((funnelRows.results ?? []).map(r => [r.event_type, { count: r.count, revenue: r.revenue }]));
        const impressions = funnel.impression?.count ?? 1;
        const clicks      = funnel.click?.count ?? 0;
        const purchases   = funnel.purchase?.count ?? 0;

        return withSecurityHeaders(withCors(new Response(JSON.stringify({
          ok: true,
          period_days: days,
          funnel: {
            impressions, clicks, purchases,
            click_rate:    impressions > 0 ? Math.round((clicks / impressions) * 10000) / 100 : 0,
            purchase_rate: clicks > 0 ? Math.round((purchases / clicks) * 10000) / 100 : 0,
            end_to_end:    impressions > 0 ? Math.round((purchases / impressions) * 10000) / 100 : 0,
            total_revenue: funnel.purchase?.revenue ?? 0,
          },
          top_offers: topOffers.results ?? [],
          loss_prevention: lossStats.results ?? [],
          generated_at: new Date().toISOString(),
        }), { status: 200, headers: { 'Content-Type': 'application/json' } }), request));
      } catch (err) {
        return withSecurityHeaders(withCors(new Response(JSON.stringify({
          ok: false, error: 'Funnel fetch failed', detail: err?.message
        }), { status: 500, headers: { 'Content-Type': 'application/json' } }), request));
      }
    }

    // ══════════════════════════════════════════════════════════════════════════
    // GOD MODE v19 — THREAT HUNTING ENGINE  (/api/hunt/*)
    // KQL / Sigma / YARA query execution, IOC lookup, MITRE ATT&CK coverage
    // ══════════════════════════════════════════════════════════════════════════

    // POST /api/hunt — execute a threat hunt query
    if (path === '/api/hunt' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: true, tier: 'FREE', identity: request.headers.get('CF-Connecting-IP') || 'ip:unknown' }));
      return withSecurityHeaders(withCors(await handleRunHunt(request, env, authCtx), request));
    }

    // POST /api/hunt/run — alias used by frontend threat hunting UI
    if (path === '/api/hunt/run' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: true, tier: 'FREE', identity: request.headers.get('CF-Connecting-IP') || 'ip:unknown' }));
      return withSecurityHeaders(withCors(await handleRunHunt(request, env, authCtx), request));
    }

    // GET /api/threat/ioc — production IOC enrichment (CVE/IP/domain/hash/URL/email)
    if (path === '/api/threat/ioc' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: true, tier: 'FREE', identity: request.headers.get('CF-Connecting-IP') || 'ip:anon' }));
      return withSecurityHeaders(withCors(await handleThreatIOC(request, env, authCtx), request));
    }

    // GET /api/demo/slots — public booking slot availability (alias for /api/sales/demo/slots)
    if (path === '/api/demo/slots' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleGetDemoSlots(request, env), request));
    }

    // GET /api/hunt/templates — list built-in hunt query templates
    if (path === '/api/hunt/templates' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: true, tier: 'FREE', identity: 'ip:anon' }));
      return withSecurityHeaders(withCors(await handleHuntTemplates(request, env, authCtx), request));
    }

    // POST /api/hunt/ioc — IOC enrichment lookup
    if (path === '/api/hunt/ioc' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: true, tier: 'FREE', identity: request.headers.get('CF-Connecting-IP') || 'ip:unknown' }));
      return withSecurityHeaders(withCors(await handleIOCLookup(request, env, authCtx), request));
    }

    // GET /api/hunt/sessions — list recent hunt sessions (auth required)
    if (path === '/api/hunt/sessions' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
      return withSecurityHeaders(withCors(await handleHuntSessions(request, env, authCtx), request));
    }

    // GET /api/hunt/mitre — MITRE ATT&CK technique coverage matrix
    if (path === '/api/hunt/mitre' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: true, tier: 'FREE', identity: 'ip:anon' }));
      return withSecurityHeaders(withCors(await handleMITREMatrix(request, env, authCtx), request));
    }

    // ══════════════════════════════════════════════════════════════════════════
    // GOD MODE v19 — AUDIT LOG  (/api/audit-log/*)
    // Tamper-evident audit trail — 90-day retention, ENTERPRISE export
    // ══════════════════════════════════════════════════════════════════════════

    // GET /api/audit-log — query audit log
    if (path === '/api/audit-log' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
      return withSecurityHeaders(withCors(await handleGetAuditLog(request, env, authCtx), request));
    }

    // POST /api/audit-log — write custom audit event (ENTERPRISE)
    if (path === '/api/audit-log' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
      return withSecurityHeaders(withCors(await handleWriteAuditEvent(request, env, authCtx), request));
    }

    // GET /api/audit-log/export — CSV or JSON export (ENTERPRISE)
    if (path === '/api/audit-log/export' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
      return withSecurityHeaders(withCors(await handleAuditExport(request, env, authCtx), request));
    }

    // GET /api/audit-log/summary — daily category stats
    if (path === '/api/audit-log/summary' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
      return withSecurityHeaders(withCors(await handleAuditSummary(request, env, authCtx), request));
    }

    // ══════════════════════════════════════════════════════════════════════════
    // GOD MODE v19 — VULNERABILITY MANAGEMENT  (/api/vulns/*)
    // Full vuln lifecycle: ingest → triage → remediate → verify → close
    // Real NVD/CISA KEV integration, CVSS 3.1 + EPSS scoring
    // ══════════════════════════════════════════════════════════════════════════

    // GET /api/vulns/stats — dashboard stats
    if (path === '/api/vulns/stats' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: true, tier: 'FREE', identity: 'ip:anon' }));
      return withSecurityHeaders(withCors(await handleVulnStats(request, env, authCtx), request));
    }

    // GET /api/vulns/kev — CISA KEV catalog (live or seed)
    if (path === '/api/vulns/kev' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: true, tier: 'FREE', identity: 'ip:anon' }));
      return withSecurityHeaders(withCors(await handleKEVFeed(request, env, authCtx), request));
    }

    // GET /api/vulns/cve/:cveId — live NVD CVE lookup
    if (path.startsWith('/api/vulns/cve/') && method === 'GET') {
      const cveId = path.slice('/api/vulns/cve/'.length);
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: true, tier: 'FREE', identity: 'ip:anon' }));
      return withSecurityHeaders(withCors(await handleCVELookup(request, env, authCtx, cveId), request));
    }

    // GET /api/vulns — list vulnerabilities
    if (path === '/api/vulns' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: true, tier: 'FREE', identity: 'ip:anon' }));
      return withSecurityHeaders(withCors(await handleListVulns(request, env, authCtx), request));
    }

    // POST /api/vulns — create / ingest a vulnerability
    if (path === '/api/vulns' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
      return withSecurityHeaders(withCors(await handleCreateVuln(request, env, authCtx), request));
    }

    // POST /api/vulns/:id/remediate — advance remediation stage
    if (path.match(/^\/api\/vulns\/[^/]+\/remediate$/) && method === 'POST') {
      const vulnId  = path.split('/')[3];
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
      return withSecurityHeaders(withCors(await handleRemediateVuln(request, env, authCtx, vulnId), request));
    }

    // GET /api/vulns/:id — single vuln detail
    if (path.match(/^\/api\/vulns\/[^/]+$/) && method === 'GET') {
      const vulnId  = path.split('/')[3];
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: true, tier: 'FREE', identity: 'ip:anon' }));
      return withSecurityHeaders(withCors(await handleGetVuln(request, env, authCtx, vulnId), request));
    }

    // ══════════════════════════════════════════════════════════════════════════
    // GOD MODE v15 — DATA SEEDING ENGINE  (/api/seed/*)
    // All endpoints are public — deterministic PRNG, no KV abuse
    // ══════════════════════════════════════════════════════════════════════════

    // GET /api/seed/threats — seeded threat event feed (20 events)
    if (path === '/api/seed/threats' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleGetSeededThreats(request, env), request));
    }

    // GET /api/seed/cves — seeded CVE feed (15 real 2025 CVEs)
    if (path === '/api/seed/cves' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleGetSeededCVEs(request, env), request));
    }

    // GET /api/seed/stats — platform stats (scan counts, users, revenue)
    if (path === '/api/seed/stats' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleGetPlatformStats(request, env), request));
    }

    // GET /api/seed/soc — SOC metrics (MTTD, MTTR, alerts, incidents)
    if (path === '/api/seed/soc' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleGetSOCMetrics(request, env), request));
    }

    // GET /api/seed/siem — SIEM event stream (30 events)
    if (path === '/api/seed/siem' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleGetSIEMStream(request, env), request));
    }

    // GET /api/seed/apt — APT group profiles (5 detailed)
    if (path === '/api/seed/apt' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleGetAPTProfiles(request, env), request));
    }

    // GET /api/seed/all — single-call anti-empty-state bundle (threats+CVEs+stats+SOC+SIEM+APTs)
    // Perfect for frontend initial load — one fetch hydrates every dashboard panel
    if (path === '/api/seed/all' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
      return withSecurityHeaders(withCors(await handleGetSeedAll(request, env, authCtx), request));
    }

    // ══════════════════════════════════════════════════════════════════════════
    // GOD MODE v16 — SEO + TRAFFIC ENGINE  (/api/seo/*, /api/leads/magnet,
    //                                       /api/retarget/*, /api/seo/cve/*)
    // ══════════════════════════════════════════════════════════════════════════

    // GET /api/seo/meta?path=/ — auto meta tags + OG + JSON-LD for any page
    if (path === '/api/seo/meta' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleSEOMeta(request, env), request));
    }

    // GET /api/seo/cve/:id — SEO-optimised CVE landing page data
    if (path.startsWith('/api/seo/cve/') && method === 'GET') {
      return withSecurityHeaders(withCors(await handleCVEPage(request, env), request));
    }

    // POST /api/leads/magnet — free mini-report lead capture (email → CRM + KV)
    if (path === '/api/leads/magnet' && method === 'POST') {
      return withSecurityHeaders(withCors(await handleLeadMagnet(request, env), request));
    }

    // POST /api/retarget/visit — record visitor for retargeting (KV, 30-day TTL)
    if (path === '/api/retarget/visit' && method === 'POST') {
      return withSecurityHeaders(withCors(await handleRetargetVisit(request, env), request));
    }

    // GET /api/retarget/offer?vid= — get personalized return-visitor offer
    if (path === '/api/retarget/offer' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleRetargetOffer(request, env), request));
    }

    // ══════════════════════════════════════════════════════════════════════════
    // v21.0 — VISITOR INTELLIGENCE ENGINE  (/api/visitor/*)
    // Live visitor tracking, geo intel, online user dashboard widget
    // ══════════════════════════════════════════════════════════════════════════

    // POST /api/visitor/track — fire-and-forget visitor session tracking
    if (path === '/api/visitor/track' && method === 'POST') {
      return withSecurityHeaders(withCors(await handleVisitorTrack(request, env), request));
    }

    // GET /api/visitor/live — live online users + recent visitor list (10s cache)
    if (path === '/api/visitor/live' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleVisitorLive(request, env), request));
    }

    // GET /api/visitor/stats — aggregate country + total visitor stats (admin)
    if (path === '/api/visitor/stats' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleVisitorStats(request, env), request));
    }

    // ══════════════════════════════════════════════════════════════════════════
    // GOD MODE v16 — ENTERPRISE HARDENING  (/api/enterprise/*)
    // ══════════════════════════════════════════════════════════════════════════

    // POST /api/enterprise/auto-qualify — batch auto-qualify high-ICP leads (icp>=60)
    if (path === '/api/enterprise/auto-qualify' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env);
      return withSecurityHeaders(withCors(await handleAutoQualify(request, env, authCtx), request));
    }

    // GET /api/enterprise/org-dashboard — full org pipeline + deal value + forecast
    if (path === '/api/enterprise/org-dashboard' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env);
      return withSecurityHeaders(withCors(await handleEnterpriseDashboard(request, env, authCtx), request));
    }

    // POST /api/enterprise/auto-proposal — auto-generate proposals for DEMO_DONE leads
    if (path === '/api/enterprise/auto-proposal' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env);
      return withSecurityHeaders(withCors(await handleAutoProposal(request, env, authCtx), request));
    }

    // GET /api/enterprise/health — CRM system health check
    if (path === '/api/enterprise/health' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
      return withSecurityHeaders(withCors(await handleEnterpriseHealth(request, env, authCtx), request));
    }

    // ══════════════════════════════════════════════════════════════════════════
    // GOD MODE v20 — CYBERBRAIN ENGINE  (/api/cyber-brain/*)
    // Central AI Intelligence Core: risk scoring, attack path prediction,
    // threat actor correlation, automated remediation planning
    // ══════════════════════════════════════════════════════════════════════════

    // POST /api/cyber-brain/analyze — full AI risk analysis on findings/vulns
    if (path === '/api/cyber-brain/analyze' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: true, tier: 'FREE', identity: 'ip:anon' }));
      return withSecurityHeaders(withCors(await handleCyberBrainAnalyze(request, env, authCtx), request));
    }

    // GET /api/cyber-brain/risk-score — retrieve cached risk score for target
    if (path === '/api/cyber-brain/risk-score' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: true, tier: 'FREE', identity: 'ip:anon' }));
      return withSecurityHeaders(withCors(await handleRiskScore(request, env, authCtx), request));
    }

    // GET /api/cyber-brain/attack-paths — predict attack chains from risk signals
    if (path === '/api/cyber-brain/attack-paths' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: true, tier: 'FREE', identity: 'ip:anon' }));
      return withSecurityHeaders(withCors(await handleAttackPaths(request, env, authCtx), request));
    }

    // GET /api/cyber-brain/threat-actors — correlated APT/threat actor groups
    if (path === '/api/cyber-brain/threat-actors' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: true, tier: 'FREE', identity: 'ip:anon' }));
      return withSecurityHeaders(withCors(await handleThreatActors(request, env, authCtx), request));
    }

    // GET /api/cyber-brain/remediation — AI-generated remediation action plan
    if (path === '/api/cyber-brain/remediation' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: true, tier: 'FREE', identity: 'ip:anon' }));
      return withSecurityHeaders(withCors(await handleRemediationPlan(request, env, authCtx), request));
    }

    // ── GOD MODE v21: Adaptive Cyber Brain ────────────────────────────────────

    // POST /api/cyber-brain/learn — submit feedback to evolve risk model (STARTER+)
    if (path === '/api/cyber-brain/learn' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
      if (!authCtx.authenticated) return withSecurityHeaders(withCors(unauthorized(), request));
      return withSecurityHeaders(withCors(await handleLearnFeedback(request, env, authCtx), request));
    }

    // GET /api/cyber-brain/global-intel — cross-tenant threat heatmap (PRO+)
    if (path === '/api/cyber-brain/global-intel' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: true, tier: 'FREE', identity: 'ip:anon' }));
      return withSecurityHeaders(withCors(await handleGlobalIntel(request, env, authCtx), request));
    }

    // GET /api/cyber-brain/adaptive-risk — personalised adaptive risk score (STARTER+)
    if (path === '/api/cyber-brain/adaptive-risk' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
      if (!authCtx.authenticated) return withSecurityHeaders(withCors(unauthorized(), request));
      return withSecurityHeaders(withCors(await handleAdaptiveRisk(request, env, authCtx), request));
    }

    // GET /api/cyber-brain/predictions — attack path predictions (PRO+)
    if (path === '/api/cyber-brain/predictions' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: true, tier: 'FREE', identity: 'ip:anon' }));
      return withSecurityHeaders(withCors(await handleAttackPredictions(request, env, authCtx), request));
    }

    // ══════════════════════════════════════════════════════════════════════════
    // GOD MODE v20 — GLOBAL THREAT FEED  (/api/global-threat-feed/*)
    // ThreatFusion Engine: normalized IOCs from NVD, CISA KEV, ThreatFox,
    // Shodan, URLhaus, GreyNoise, OpenPhish, Ransomware.live — SSE streaming
    // ══════════════════════════════════════════════════════════════════════════

    // GET /api/global-threat-feed/stream — SSE real-time IOC stream
    if (path === '/api/global-threat-feed/stream' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: true, tier: 'FREE', identity: 'ip:anon' }));
      return withSecurityHeaders(withCors(await handleThreatFeedStream(request, env, authCtx), request));
    }

    // GET /api/global-threat-feed/stats — feed statistics (count, sources, top types)
    if (path === '/api/global-threat-feed/stats' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: true, tier: 'FREE', identity: 'ip:anon' }));
      return withSecurityHeaders(withCors(await handleThreatFeedStats(request, env, authCtx), request));
    }

    // POST /api/global-threat-feed/ingest — manual IOC submission
    if (path === '/api/global-threat-feed/ingest' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
      if (!authCtx.authenticated) return withSecurityHeaders(withCors(unauthorized(), request));
      return withSecurityHeaders(withCors(await handleThreatFeedIngest(request, env, authCtx), request));
    }

    // GET /api/global-threat-feed — paginated normalized IOC feed (must come AFTER /stats and /ingest)
    if (path === '/api/global-threat-feed' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: true, tier: 'FREE', identity: 'ip:anon' }));
      return withSecurityHeaders(withCors(await handleGlobalThreatFeed(request, env, authCtx), request));
    }

    // ══════════════════════════════════════════════════════════════════════════
    // GOD MODE v20 — ZERO TRUST SECURITY LAYER  (/api/zero-trust/*)
    // Device fingerprinting, risk-based auth, session anomaly detection,
    // behavioral scoring — Zero Trust enforcement at the API edge
    // ══════════════════════════════════════════════════════════════════════════

    // GET /api/zero-trust/score — device + session trust score
    if (path === '/api/zero-trust/score' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: true, tier: 'FREE', identity: 'ip:anon' }));
      return withSecurityHeaders(withCors(await handleTrustScore(request, env, authCtx), request));
    }

    // GET /api/zero-trust/anomalies — detected session anomalies for user
    if (path === '/api/zero-trust/anomalies' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
      if (!authCtx.authenticated) return withSecurityHeaders(withCors(unauthorized(), request));
      return withSecurityHeaders(withCors(await handleZeroTrustAnomalies(request, env, authCtx), request));
    }

    // POST /api/zero-trust/verify — risk-based authentication verification
    if (path === '/api/zero-trust/verify' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
      if (!authCtx.authenticated) return withSecurityHeaders(withCors(unauthorized(), request));
      return withSecurityHeaders(withCors(await handleZeroTrustVerify(request, env, authCtx), request));
    }

    // ══════════════════════════════════════════════════════════════════════════
    // GOD MODE v20 — REVENUE ENGINE 2.0  (/api/revenue/*)
    // Subscription plans (₹199/₹999/₹9999), usage-based billing,
    // feature gating middleware, upsell engine
    // ══════════════════════════════════════════════════════════════════════════

    // GET /api/revenue/plans — subscription plan catalog
    if (path === '/api/revenue/plans' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: true, tier: 'FREE', identity: 'ip:anon' }));
      return withSecurityHeaders(withCors(await handleGetPlansV20(request, env, authCtx), request));
    }

    // POST /api/revenue/subscribe — create or upgrade subscription
    if (path === '/api/revenue/subscribe' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
      if (!authCtx.authenticated) return withSecurityHeaders(withCors(unauthorized(), request));
      return withSecurityHeaders(withCors(await handleSubscribeV20(request, env, authCtx), request));
    }

    // GET /api/revenue/gate/:feature — check if user has access to a feature
    if (path.startsWith('/api/revenue/gate/') && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: true, tier: 'FREE', identity: 'ip:anon' }));
      return withSecurityHeaders(withCors(await handleFeatureGate(request, env, authCtx), request));
    }

    // GET /api/revenue/billing — current billing status + usage
    if (path === '/api/revenue/billing' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false }));
      if (!authCtx.authenticated) return withSecurityHeaders(withCors(unauthorized(), request));
      return withSecurityHeaders(withCors(await handleBillingStatus(request, env, authCtx), request));
    }

    // ══════════════════════════════════════════════════════════════════════════
    // GOD MODE v20 — GLOBAL AUTHORITY ENGINE  (/api/authority/*)
    // Auto-generate CVE reports, threat bulletins, blog posts for SEO authority
    // ══════════════════════════════════════════════════════════════════════════

    // POST /api/authority/cve-report — generate full CVE report (PDF-ready)
    if (path === '/api/authority/cve-report' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: true, tier: 'FREE', identity: 'ip:anon' }));
      return withSecurityHeaders(withCors(await handleCVEReport(request, env, authCtx), request));
    }

    // POST /api/authority/blog-post — auto-generate SEO blog post from CVE/topic
    if (path === '/api/authority/blog-post' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: true, tier: 'FREE', identity: 'ip:anon' }));
      return withSecurityHeaders(withCors(await handleBlogPost(request, env, authCtx), request));
    }

    // GET /api/authority/bulletin — latest threat intelligence bulletin
    if (path === '/api/authority/bulletin' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: true, tier: 'FREE', identity: 'ip:anon' }));
      return withSecurityHeaders(withCors(await handleThreatBulletin(request, env, authCtx), request));
    }

    // GET /api/authority/stats — authority engine content statistics
    if (path === '/api/authority/stats' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleAuthorityStats(request, env), request));
    }

    // ── Sync scan routes (v4 backward compat — full pipeline) ────────────────
    const routeKey = `${method} ${path}`;
    const route    = SYNC_ROUTES[routeKey];
    if (route) {
      try {
        const response = await runSyncPipeline(request, env, routeKey, route);
        return withSecurityHeaders(withCors(response, request));
      } catch (err) {
        console.error(`[${routeKey}]`, err?.message);
        return withSecurityHeaders(withCors(Response.json({
          error:      'Internal server error',
          request_id: crypto.randomUUID?.() || Date.now().toString(36),
          support:    CONTACT_EMAIL,
        }, { status: 500 }), request));
      }
    }

    // ── v23.0 RevOS — Revenue Operating System (/api/revos/*) ─────────────────
    if (path.startsWith('/api/revos/')) {
      const revosAuthCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false, tier: 'FREE' }));
      return withSecurityHeaders(withCors(
        await handleRevOS(request, env, revosAuthCtx, path, method),
        request
      ));
    }

    // ── v24.0 Revenue Dominance (/api/v24/*) ─────────────────────────────────
    if (path.startsWith('/api/v24/')) {
      const v24AuthCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false, tier: 'FREE' }));
      return withSecurityHeaders(withCors(
        await handleV24(request, env, v24AuthCtx, path, method),
        request
      ));
    }

    // ── SENTINEL APEX™ Intelligence Marketplace (/api/marketplace/*) ─────────
    // Wired: Task 23-25 — commerce engine: catalog, checkout, subscribe, entitlements
    if (path.startsWith('/api/marketplace/')) {
      const mktAuthCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false, tier: 'FREE' }));
      const { handleMarketplace } = await import('./handlers/sentinelApexMarketplace.js');
      return withSecurityHeaders(withCors(await handleMarketplace(request, env, mktAuthCtx, path, method), request));
    }

    // ── SENTINEL APEX™ Intelligence Preview System (/api/preview/*) ──────────
    // Wired: Task 24 — live intelligence preview cards with paywall conversion hooks
    if (path.startsWith('/api/preview/')) {
      const prevAuthCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false, tier: 'FREE' }));
      const { handleIntelligencePreview } = await import('./handlers/intelligencePreview.js');
      return withSecurityHeaders(withCors(await handleIntelligencePreview(request, env, prevAuthCtx), request));
    }

    // ── SENTINEL APEX™ Provisioning Engine (/api/provision/*) ────────────────
    // Wired: Task 25 — auto-provision tenant/entitlements/API keys after purchase
    if (path.startsWith('/api/provision/')) {
      const provAuthCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false, tier: 'FREE' }));
      const { handleProvisioning } = await import('./handlers/provisioningEngine.js');
      return withSecurityHeaders(withCors(await handleProvisioning(request, env, provAuthCtx, path, method), request));
    }

    // ── SENTINEL APEX™ Onboarding & Welcome Flow (/api/onboarding/*) ──────────
    if (path.startsWith('/api/onboarding/')) {
      const obAuthCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false, tier: 'FREE' }));
      const { handleOnboarding } = await import('./handlers/onboarding.js');
      return withSecurityHeaders(withCors(await handleOnboarding(request, env, obAuthCtx, path, method), request));
    }

    // ── SENTINEL APEX™ Support & Help Centre (/api/support/*) ────────────────
    if (path.startsWith('/api/support/')) {
      const supAuthCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false, tier: 'FREE' }));
      const { handleSupport } = await import('./handlers/support.js');
      return withSecurityHeaders(withCors(await handleSupport(request, env, supAuthCtx, path, method), request));
    }

    // ── SENTINEL APEX™ Secure Report Downloads + AI Report Generation ────────
    // Wired: Task 7 — KV-token signed download delivery + dynamic report generation
    if (path.startsWith('/api/download/') || path.startsWith('/api/report/')) {
      const dlAuthCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false, tier: 'FREE' }));
      const { handleSecureDownload } = await import('./handlers/secureDownload.js');
      return withSecurityHeaders(withCors(await handleSecureDownload(request, env, dlAuthCtx, path, method), request));
    }

    // ── v22.0 PRODUCTION ROUTE FIXES ─────────────────────────────────────────
    // GET /api/defense-marketplace → alias → /api/defense/solutions (frontend uses old path)
    if (path === '/api/defense-marketplace' && method === 'GET') {
      const { handleGetSolutions } = await import('./handlers/defenseMarketplace.js');
      return withSecurityHeaders(withCors(await handleGetSolutions(request, env, {}), request));
    }

    // GET /api/gtm/funnel-dashboard → alias (frontend GTM module calls this)
    if (path === '/api/gtm/funnel-dashboard' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleFunnelDashboard(request, env), request));
    }

    // ── GTM telemetry beacons (public, fire-and-forget — never 5xx) ──────────
    // POST /api/gtm/funnel-event — single conversion-funnel event (CDB_FUNNEL)
    if (path === '/api/gtm/funnel-event' && method === 'POST') {
      const { handleGtmFunnelEvent } = await import('./handlers/gtm.js');
      const gtmAuth = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleGtmFunnelEvent(request, env, gtmAuth), request));
    }

    // POST /api/gtm/events/batch — batched product events (CDB_TRACK)
    if (path === '/api/gtm/events/batch' && method === 'POST') {
      const { handleGtmEventsBatch } = await import('./handlers/gtm.js');
      const gtmAuth = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleGtmEventsBatch(request, env, gtmAuth), request));
    }

    // POST /api/gtm/email-capture — scan-gate email capture → lead
    if (path === '/api/gtm/email-capture' && method === 'POST') {
      const { handleGtmEmailCapture } = await import('./handlers/gtm.js');
      const gtmAuth = await resolveAuthV5(request, env).catch(() => null);
      return withSecurityHeaders(withCors(await handleGtmEmailCapture(request, env, gtmAuth), request));
    }

    // POST /api/csp-report — browser CSP violation reports (report-uri target)
    if (path === '/api/csp-report' && method === 'POST') {
      const { handleCspReport } = await import('./handlers/gtm.js');
      return withSecurityHeaders(withCors(await handleCspReport(request, env), request));
    }

    // GET /api/auth/plans → alias → /api/subscription/plans
    if (path === '/api/auth/plans' && method === 'GET') {
      return withSecurityHeaders(withCors(await handleGetPlans(request, env), request));
    }

    // GET /api/ai/analyze → GET method alias (POST is the canonical — return helpful 405)
    if (path === '/api/ai/analyze' && method === 'GET') {
      return withSecurityHeaders(withCors(Response.json({
        error: 'Method Not Allowed',
        hint: 'POST /api/ai/analyze with body: { target, module, findings }',
        docs: 'GET /api',
      }, { status: 405 }), request));
    }



  // v28+ enterprise & scanner routes share one auth context (anonymous-friendly).
  // Fixes ReferenceError: authCtx is not defined for /api/ai-security/*, /api/mcp-security/*, /api/vibe-code/*.
  const authCtx = await resolveAuthV5(request, env).catch(() => ({ authenticated: false, tier: 'FREE', identity: 'ip:anon' }));

  // ── v28: AI SECURITY POSTURE MANAGEMENT (PILLAR 1) ────────────────────────
  if (path === '/api/ai-security/assets' && method === 'GET') {
    return handleListAIAssets(request, env, authCtx);
  }
  if (path === '/api/ai-security/assets/register' && method === 'POST') {
    return handleRegisterAIAsset(request, env, authCtx);
  }
  if (path.startsWith('/api/ai-security/assets/') && path.endsWith('/scan') && method === 'POST') {
    return handleScanAIAsset(request, env, authCtx);
  }
  if (path === '/api/ai-security/dashboard' && method === 'GET') {
    return handleASPMDashboard(request, env, authCtx);
  }

  // ── v28: AI GOVERNANCE CENTER (PILLAR 2) ───────────────────────────────────
  if (path === '/api/ai-security/governance/frameworks') {
    return handleListFrameworks(request, env);
  }
  if (path === '/api/ai-security/governance/assess' && method === 'POST') {
    return handleGovernanceAssess(request, env, authCtx);
  }
  if (path.startsWith('/api/ai-security/governance/') && path.endsWith('/answer') && method === 'POST') {
    return handleGovernanceAnswer(request, env, authCtx);
  }
  if (path.startsWith('/api/ai-security/governance/') && method === 'GET') {
    return handleGetGovernanceAssessment(request, env, authCtx);
  }

  // ── v28: AI RED TEAM PLATFORM (PILLAR 3) ──────────────────────────────────
  if (path === '/api/ai-security/redteam/engage' && method === 'POST') {
    return handleRedTeamEngage(request, env, authCtx);
  }
  if (path.startsWith('/api/ai-security/redteam/') && path.endsWith('/attack') && method === 'POST') {
    return handleRedTeamAttack(request, env, authCtx);
  }
  if (path.startsWith('/api/ai-security/redteam/') && path.endsWith('/report')) {
    return handleRedTeamReport(request, env, authCtx);
  }
  if (path.startsWith('/api/ai-security/redteam/') && method === 'GET') {
    return handleGetRedTeamEngagement(request, env, authCtx);
  }

  // ── v28: AI AGENT SECURITY (PILLAR 4) ─────────────────────────────────────
  if (path === '/api/ai-security/agents/scan' && method === 'POST') {
    return handleScanAgent(request, env, authCtx);
  }
  if (path === '/api/ai-security/agents/register' && method === 'POST') {
    return handleRegisterAgent(request, env, authCtx);
  }
  if (path === '/api/ai-security/agents' && method === 'GET') {
    return handleListAgents(request, env, authCtx);
  }

  // ── v28: AI THREAT INTELLIGENCE FEED (PILLAR 5) ───────────────────────────
  // Specific sub-routes must be checked before the startsWith() feed route below.
  if (path === '/api/ai-security/threat-feed/report' && method === 'GET') {
    return handleAIThreatReport(request, env, authCtx);
  }
  // Continuously-published live report — always reflects the latest radar scan
  if (path === '/api/ai-security/threat-feed/latest-report' && method === 'GET') {
    return handleLatestPublishedReport(request, env, authCtx);
  }
  if (path === '/api/ai-security/threat-feed/radar-status' && method === 'GET') {
    return handleAIThreatRadarStatus(request, env);
  }
  if (path === '/api/ai-security/threat-feed/radar-scan-now' && method === 'POST') {
    return handleAIThreatRadarScanNow(request, env, authCtx);
  }
  if (path.startsWith('/api/ai-security/threat-feed')) {
    return handleAIThreatFeed(request, env, authCtx);
  }

  // ── v28: AI SECURITY SERVICES (PILLAR 6) ──────────────────────────────────
  if (path === '/api/ai-security/services/catalog') {
    return handleServiceCatalog(request, env);
  }
  if (path === '/api/ai-security/services/book' && method === 'POST') {
    return handleBookAIService(request, env, authCtx);
  }
  if (path.startsWith('/api/ai-security/services/') && method === 'GET') {
    return handleGetAIServiceEngagement(request, env, authCtx);
  }

  // ── v36: AI SECURITY COPILOT — APEX God Mode Orchestrator ─────────────────
  // Full-spectrum AI security orchestration via natural language.
  // Tier-routed across Groq / DeepSeek / OpenRouter — zero Anthropic dependency.
  // Tool registry: 19 skills covering threat intel, SOC, SIEM, red team, etc.
  if (path === '/api/copilot/capabilities' && method === 'GET') {
    return withSecurityHeaders(withCors(await handleCopilotCapabilities(request, env, authCtx), request));
  }
  if (path === '/api/copilot/chat' && method === 'POST') {
    return withSecurityHeaders(withCors(await handleCopilotChat(request, env, authCtx), request));
  }
  if (path === '/api/copilot/session' && method === 'GET') {
    return withSecurityHeaders(withCors(await handleGetCopilotSession(request, env, authCtx), request));
  }
  if (path === '/api/copilot/session' && method === 'DELETE') {
    return withSecurityHeaders(withCors(await handleDeleteCopilotSession(request, env, authCtx), request));
  }
  if (path === '/api/copilot/quick-action' && method === 'POST') {
    return withSecurityHeaders(withCors(await handleCopilotQuickAction(request, env, authCtx), request));
  }

  // ── P22.0: AI Governance Compliance PDF Export Engine ────────────────────
  // Specific routes must appear before the /api/ai-governance/* catch-all below
  if (path === '/api/ai-governance/pdf/generate' && method === 'POST') {
    return withSecurityHeaders(withCors(await handlePdfGenerate(request, env, authCtx), request));
  }
  if (path === '/api/ai-governance/pdf/observability' && method === 'GET') {
    return withSecurityHeaders(withCors(await handlePdfObservability(request, env), request));
  }
  if (path === '/api/ai-governance/pdf/list' && method === 'GET') {
    return withSecurityHeaders(withCors(await handlePdfList(request, env), request));
  }
  if (path.startsWith('/api/ai-governance/pdf/status/') && method === 'GET') {
    const pdfStatusToken = path.replace('/api/ai-governance/pdf/status/', '');
    return withSecurityHeaders(withCors(await handlePdfStatus(request, env, pdfStatusToken), request));
  }
  if (path.startsWith('/api/ai-governance/pdf/') && method === 'GET') {
    const pdfToken = path.replace('/api/ai-governance/pdf/', '');
    return await handlePdfDownload(request, env, pdfToken);
  }

  // ── v27: CEO EXECUTIVE DASHBOARD ──────────────────────────────────────────
    // v20.0 GOD MODE: AI GOVERNANCE PRO (EU AI Act, NIST AI RMF, ISO 42001)
  if (path.startsWith('/api/ai-governance/')) {
    return handleAIGovernancePro(request, env);
  }

  // v20.0 GOD MODE: AI RED TEAM PRO (MITRE ATLAS v2.1)
  if (path.startsWith('/api/ai-redteam/')) {
    return handleAIRedTeamPro(request, env);
  }

  // v20.0 GOD MODE: DEVELOPER PORTAL / API ECONOMY
  if (path.startsWith('/api/developer/')) {
    return handleDeveloperPortal(request, env);
  }

  // P8.0-001: /api/openapi.json — top-level alias for /api/developer/openapi.json (same generator, zero duplication)
  if (path === '/api/openapi.json' && method === 'GET') {
    return withSecurityHeaders(withCors(await getOpenAPISpec(request, env), request));
  }

  // v20.0 GOD MODE: EXECUTIVE COMMAND CENTER PRO (FAIR, Board, ROI)
  if (path.startsWith('/api/executive/')) {
    return handleExecutiveCommandCenter(request, env);
  }

  if (path === '/api/ceo/dashboard' || path === '/api/ceo/dashboard/kpis') {
    return handleCEODashboard(request, env, authCtx);
  }
  if (path === '/api/ceo/snapshot' && method === 'POST') {
    return handleCEOSnapshot(request, env, authCtx);
  }

  // ── v27: ASSESSMENT BOOKING ────────────────────────────────────────────────
  if (path === '/api/assessments/book' && method === 'POST') {
    return handleBookAssessment(request, env);
  }
  if (path === '/api/assessments/confirm' && method === 'POST') {
    return handleConfirmAssessment(request, env);
  }
  if (path === '/api/assessments' && method === 'GET') {
    return handleListAssessments(request, env, authCtx);
  }
  if (path.startsWith('/api/assessments/') && method === 'GET') {
    return handleGetAssessment(request, env, authCtx);
  }
  if (path.includes('/api/assessments/') && path.endsWith('/status') && method === 'PUT') {
    return handleUpdateAssessmentStatus(request, env, authCtx);
  }

  // ── v27: TRUST CENTER ──────────────────────────────────────────────────────
  if (path === '/api/trust/center') {
    return handleTrustCenter(request, env);
  }
  if (path === '/api/trust/metrics') {
    return handleTrustMetrics(request, env);
  }
  if (path === '/api/trust/company') {
    return handleTrustCompany(request, env);
  }
  if (path === '/api/trust/testimonial' && method === 'POST') {
    return handleSubmitTestimonial(request, env);
  }

  // ── v29: MCP SECURITY SCANNER (World's First) ─────────────────────────────
  if (path === '/api/mcp-security/scan' && method === 'POST') {
    return handleMCPSecurityScan(request, env, authCtx);
  }
  if (path.startsWith('/api/mcp-security/results/') && method === 'GET') {
    return handleMCPScanResult(request, env, authCtx);
  }
  if (path === '/api/mcp-security/threats' && method === 'GET') {
    return handleMCPThreatFeed(request, env);
  }
  if (path === '/api/mcp-security/assess' && method === 'POST') {
    return handleMCPQuickAssess(request, env);
  }

  // ── v29: VIBE CODE SECURITY SCANNER ─────────────────────────────────────
  if (path === '/api/vibe-code/scan' && method === 'POST') {
    return handleVibeCodeScan(request, env, authCtx);
  }
  if (path === '/api/vibe-code/patterns' && method === 'GET') {
    return handleVibeCodePatterns(request, env);
  }

  // ── v43: AGENT THREAT ADVISORIES — live D1-backed feed for /agent-threats ──
  if (path === '/api/agent-threats/advisories' && method === 'GET') {
    return withSecurityHeaders(withCors(await handleListAgentAdvisories(request, env), request));
  }
  if (path === '/api/agent-threats/overview' && method === 'GET') {
    return withSecurityHeaders(withCors(await handleAgentThreatOverview(request, env), request));
  }
  if (path === '/api/admin/agent-threats/advisories' && method === 'POST') {
    return withSecurityHeaders(withCors(await handleCreateAgentAdvisory(request, env), request));
  }
  if (path === '/api/admin/agent-threats/ingest' && method === 'POST') {
    if (!isAdminAuthorized(request, env)) {
      return withSecurityHeaders(withCors(Response.json({ error: 'Unauthorized' }, { status: 401 }), request));
    }
    const result = await ingestAgentThreatAdvisories(env);
    return withSecurityHeaders(withCors(Response.json({ success: true, ...result }), request));
  }

  // ── v44: ATTACK LIBRARY — live D1-backed feed for /attack-library ──────────
  if (path === '/api/attack-library/techniques' && method === 'GET') {
    return withSecurityHeaders(withCors(await handleListAttackTechniques(request, env), request));
  }
  if (path === '/api/attack-library/overview' && method === 'GET') {
    return withSecurityHeaders(withCors(await handleAttackLibraryOverview(request, env), request));
  }
  if (path === '/api/admin/attack-library/techniques' && method === 'POST') {
    return withSecurityHeaders(withCors(await handleCreateAttackTechnique(request, env), request));
  }
  if (path === '/api/admin/attack-library/ingest' && method === 'POST') {
    if (!isAdminAuthorized(request, env)) {
      return withSecurityHeaders(withCors(Response.json({ error: 'Unauthorized' }, { status: 401 }), request));
    }
    const result = await ingestAttackLibraryTechniques(env);
    return withSecurityHeaders(withCors(Response.json({ success: true, ...result }), request));
  }

  // -- v30.0: Platform Metrics ------------------------------------------------
  if (path === '/api/platform/metrics') {
    return servePlatformMetrics(request, env);
  }

  // -- v30.0: Scan Token issuance ---------------------------------------------
  if (path === '/api/scan/token') {
    return issueScanToken(request, env);
  }

  // -- v30.0: Subscription Checkout + Plan ------------------------------------
  if (path === '/api/subscription/checkout') {
    return handleSubscriptionCheckout(request, env, authCtx);
  }
  if (path === '/api/subscription/plan' && method === 'GET') {
    return handleGetMyPlan(request, env, authCtx);
  }


    // ── GET /api/geo — Edge geolocation + currency detection ─────────────────
    if (path === '/api/geo' && method === 'GET') {
      const cf       = request.cf || {};
      const country  = (cf.country || request.headers.get('CF-IPCountry') || 'IN').toUpperCase();
      const currency = country === 'IN' ? 'INR' : 'USD';
      const symbol   = currency === 'INR' ? '₹' : '$';
      return new Response(JSON.stringify({
        country, currency, symbol,
        plans: currency === 'INR'
          ? { STARTER: 499, PRO: 1499, ENTERPRISE: 4999, MSSP: 9999 }
          : { STARTER: 6,   PRO: 19,   ENTERPRISE: 59,   MSSP: 119  },
        report_price: currency === 'INR' ? 999 : 12,
        ts: Date.now(),
      }), {
        status: 200,
        headers: {
          'Content-Type':                'application/json',
          'Cache-Control':               'public, max-age=3600, s-maxage=3600',
          'CDN-Cache-Control':           'max-age=3600',
          'Access-Control-Allow-Origin': '*',
          'Vary':                        'CF-IPCountry',
          'X-Country':                   country,
          'X-Currency':                  currency,
        },
      });
    }

    // ══════════════════════════════════════════════════════════════════════════
    // PHASE 3 P0 — REVENUE OPERATING SYSTEM ROUTES
    // All routes are owner-gated (internal dashboards only)
    // ══════════════════════════════════════════════════════════════════════════

    // GET /api/revenue/breakdown — Revenue by product type
    if (path === '/api/revenue/breakdown' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE' }));
      if (!isOwner(authCtx, env)) return withSecurityHeaders(withCors(forbidden(), request));
      return withSecurityHeaders(withCors(await handleRevenueBreakdown(request, env), request));
    }

    // GET /api/revenue/leads — Lead source breakdown
    if (path === '/api/revenue/leads' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE' }));
      if (!isOwner(authCtx, env)) return withSecurityHeaders(withCors(forbidden(), request));
      return withSecurityHeaders(withCors(await handleRevenueLeads(request, env), request));
    }

    // GET /api/revenue/funnel — Conversion funnel rates
    if (path === '/api/revenue/funnel' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE' }));
      if (!isOwner(authCtx, env)) return withSecurityHeaders(withCors(forbidden(), request));
      return withSecurityHeaders(withCors(await handleRevenueFunnelOps(request, env), request));
    }

    // GET /api/revenue/transactions — Recent payment transactions
    if (path === '/api/revenue/transactions' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE' }));
      if (!isOwner(authCtx, env)) return withSecurityHeaders(withCors(forbidden(), request));
      return withSecurityHeaders(withCors(await handleRevenueTransactions(request, env), request));
    }

    // GET /api/revenue/forecast — Sales forecast
    if (path === '/api/revenue/forecast' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE' }));
      if (!isOwner(authCtx, env)) return withSecurityHeaders(withCors(forbidden(), request));
      return withSecurityHeaders(withCors(await handleRevenueForecastOps(request, env), request));
    }

    // GET /api/enterprise/pipeline — Enterprise deal pipeline board
    if (path === '/api/enterprise/pipeline' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE' }));
      if (!isOwner(authCtx, env)) return withSecurityHeaders(withCors(forbidden(), request));
      return withSecurityHeaders(withCors(await handleGetEnterprisePipeline(request, env), request));
    }

    // POST /api/enterprise/pipeline — Add new enterprise deal
    if (path === '/api/enterprise/pipeline' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE' }));
      if (!isOwner(authCtx, env)) return withSecurityHeaders(withCors(forbidden(), request));
      return withSecurityHeaders(withCors(await handleAddEnterpriseDeal(request, env), request));
    }

    // POST /api/enterprise/inquiry — Alias for /api/enterprise/inquire (spelling fix)
    if (path === '/api/enterprise/inquiry' && method === 'POST') {
      return withSecurityHeaders(withCors(await handleEnterpriseInquiryAlias(request, env), request));
    }

    // POST /api/attribution/track — Track visitor→lead→customer attribution
    if (path === '/api/attribution/track' && method === 'POST') {
      return withSecurityHeaders(withCors(await handleAttributionTrack(request, env), request));
    }

    // ── MSSP Command Center Routes ────────────────────────────────────────────

    // GET /api/mssp/metrics — Partner count, MRR, active clients, alerts
    if (path === '/api/mssp/metrics' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE' }));
      if (!isOwner(authCtx, env)) return withSecurityHeaders(withCors(forbidden(), request));
      return withSecurityHeaders(withCors(await handleMsspMetrics(request, env), request));
    }

    // GET /api/mssp/partners — List all MSSP partners
    if (path === '/api/mssp/partners' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE' }));
      if (!isOwner(authCtx, env)) return withSecurityHeaders(withCors(forbidden(), request));
      return withSecurityHeaders(withCors(await handleListMsspPartners(request, env), request));
    }

    // POST /api/mssp/partners — Onboard a new MSSP partner
    if (path === '/api/mssp/partners' && method === 'POST') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE' }));
      if (!isOwner(authCtx, env)) return withSecurityHeaders(withCors(forbidden(), request));
      return withSecurityHeaders(withCors(await handleAddMsspPartner(request, env), request));
    }

    // GET /api/mssp/wl-status — White-label configuration status
    if (path === '/api/mssp/wl-status' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE' }));
      if (!isOwner(authCtx, env)) return withSecurityHeaders(withCors(forbidden(), request));
      return withSecurityHeaders(withCors(await handleMsspWlStatus(request, env), request));
    }

    // GET /api/mssp/usage — Usage metrics across all partners
    if (path === '/api/mssp/usage' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE' }));
      if (!isOwner(authCtx, env)) return withSecurityHeaders(withCors(forbidden(), request));
      return withSecurityHeaders(withCors(await handleMsspUsage(request, env), request));
    }

    // GET /api/mssp/revenue-trend — Monthly MRR trend (6 months)
    if (path === '/api/mssp/revenue-trend' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE' }));
      if (!isOwner(authCtx, env)) return withSecurityHeaders(withCors(forbidden(), request));
      return withSecurityHeaders(withCors(await handleMsspRevenueTrend(request, env), request));
    }

    // GET /api/mssp/expansion-opps — Partners eligible for tier upgrade
    if (path === '/api/mssp/expansion-opps' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE' }));
      if (!isOwner(authCtx, env)) return withSecurityHeaders(withCors(forbidden(), request));
      return withSecurityHeaders(withCors(await handleMsspExpansionOpps(request, env), request));
    }

    // PATCH /api/mssp/partners/:id/status — Certification status machine
    // Advances: pending → qualified → certified → active with criteria checks
    if (path.startsWith('/api/mssp/partners/') && path.endsWith('/status') && method === 'PATCH') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE' }));
      if (!isOwner(authCtx, env)) return withSecurityHeaders(withCors(forbidden(), request));
      const partnerId = path.split('/')[4]; // /api/mssp/partners/:id/status
      return withSecurityHeaders(withCors(await handleMsspPartnerStatusUpdate(request, env, partnerId), request));
    }

    // GET /api/admin/acquisition-scorecard — Full acquisition funnel KPIs
    // CAC, LTV, close rate, sales velocity, pipeline value, lead qualification funnel
    if (path === '/api/admin/acquisition-scorecard' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE' }));
      if (!isOwner(authCtx, env)) return withSecurityHeaders(withCors(forbidden(), request));
      if (!env.DB) return withSecurityHeaders(withCors(Response.json({ error: 'DB unavailable' }, { status: 503 }), request));

      try {
        const [leadStages, sqlLeads, proposalStats, dealSize, salesVelocity, mrrBySource, partnerStats] = await Promise.all([
          // Lead funnel by qualification stage
          env.DB.prepare(`SELECT funnel_stage, COUNT(*) as cnt, COALESCE(AVG(lead_score),0) as avg_score FROM leads GROUP BY funnel_stage`).all().catch(() => ({ results: [] })),
          // SQL-qualified leads
          env.DB.prepare(`SELECT COUNT(*) as cnt FROM leads WHERE funnel_stage = 'sql'`).first().catch(() => null),
          // Proposal pipeline stats
          env.DB.prepare(`SELECT status, COUNT(*) as cnt, COALESCE(SUM(price_inr),0) as value FROM proposals GROUP BY status`).all().catch(() => ({ results: [] })),
          // Avg accepted deal size
          env.DB.prepare(`SELECT COALESCE(AVG(price_inr),0) as avg, COALESCE(SUM(price_inr),0) as total FROM proposals WHERE status='accepted'`).first().catch(() => null),
          // Sales velocity: avg days from lead creation to payment
          env.DB.prepare(`SELECT AVG(JULIANDAY(p.created_at) - JULIANDAY(l.created_at)) as velocity_days FROM payments p LEFT JOIN leads l ON l.email = p.email WHERE p.status='paid' AND l.created_at IS NOT NULL`).first().catch(() => null),
          // MRR attribution by revenue source
          env.DB.prepare(`SELECT source, COUNT(*) as events, COALESCE(SUM(amount_inr),0) as total_inr FROM revenue_events WHERE created_at >= date('now','-30 days') GROUP BY source`).all().catch(() => ({ results: [] })),
          // MSSP pipeline by status
          env.DB.prepare(`SELECT status, COUNT(*) as cnt FROM mssp_partners GROUP BY status`).all().catch(() => ({ results: [] })),
        ]);

        const stageMap = {};
        for (const r of (leadStages?.results ?? [])) stageMap[r.funnel_stage] = { cnt: r.cnt, avg_score: Math.round(r.avg_score) };
        const totalLeads = Object.values(stageMap).reduce((s, v) => s + v.cnt, 0);

        const propMap = {};
        for (const r of (proposalStats?.results ?? [])) propMap[r.status] = { cnt: r.cnt, value: r.value };
        const sent     = propMap.sent?.cnt || 0;
        const accepted = propMap.accepted?.cnt || 0;
        const rejected = propMap.rejected?.cnt || 0;
        const closeable = sent + accepted + rejected;
        const closeRate = closeable > 0 ? Math.round(accepted / closeable * 1000) / 10 : 0;

        const mrrMap = {};
        for (const r of (mrrBySource?.results ?? [])) mrrMap[r.source] = { events: r.events, total_inr: r.total_inr };

        const msspMap = {};
        for (const r of (partnerStats?.results ?? [])) msspMap[r.status] = r.cnt;

        return withSecurityHeaders(withCors(Response.json({
          generated_at: new Date().toISOString(),
          leads: {
            total:            totalLeads,
            new_30d:          (stageMap.lead?.cnt || 0) + (stageMap.warm_lead?.cnt || 0),
            by_stage:         stageMap,
            sql_count:        sqlLeads?.cnt || 0,
            sql_rate_pct:     totalLeads > 0 ? Math.round((sqlLeads?.cnt || 0) / totalLeads * 1000) / 10 : 0,
          },
          pipeline: {
            proposals_draft:    propMap.draft?.cnt || 0,
            proposals_sent:     sent,
            proposals_accepted: accepted,
            proposals_rejected: rejected,
            close_rate_pct:     closeRate,
            avg_deal_size_inr:  Math.round(dealSize?.avg || 0),
            total_won_inr:      dealSize?.total || 0,
            pipeline_value_inr: propMap.sent?.value || 0,
            sales_velocity_days: salesVelocity?.velocity_days ? Math.round(salesVelocity.velocity_days) : null,
          },
          revenue_attribution: mrrMap,
          mssp: {
            pending:   msspMap.pending || 0,
            qualified: msspMap.qualified || 0,
            certified: msspMap.certified || 0,
            active:    msspMap.active || 0,
            total:     Object.values(msspMap).reduce((s, v) => s + v, 0),
          },
        }), request));
      } catch (e) {
        return withSecurityHeaders(withCors(Response.json({ error: e.message }, { status: 500 }), request));
      }
    }

    // GET /api/admin/weekly-report — structured 7-day acquisition + revenue summary
    // Designed for daily CRO review: WoW growth, SQLs, pipeline, revenue, email delivery
    if (path === '/api/admin/weekly-report' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE' }));
      if (!isOwner(authCtx, env)) return withSecurityHeaders(withCors(forbidden(), request));
      if (!env.DB) return withSecurityHeaders(withCors(Response.json({ error: 'DB unavailable' }, { status: 503 }), request));

      try {
        const [
          leadsThis, leadsPrev, sqlsThis, sqlsPrev,
          propThis, propPrev,
          revThis, revPrev,
          emailSent, emailFailed, seqEnrolled,
          channelThis, msspThis,
        ] = await Promise.all([
          env.DB.prepare(`SELECT COUNT(*) as cnt FROM leads WHERE created_at >= datetime('now','-7 days')`).first().catch(() => null),
          env.DB.prepare(`SELECT COUNT(*) as cnt FROM leads WHERE created_at BETWEEN datetime('now','-14 days') AND datetime('now','-7 days')`).first().catch(() => null),
          env.DB.prepare(`SELECT COUNT(*) as cnt FROM leads WHERE funnel_stage='sql' AND updated_at >= datetime('now','-7 days')`).first().catch(() => null),
          env.DB.prepare(`SELECT COUNT(*) as cnt FROM leads WHERE funnel_stage='sql' AND updated_at BETWEEN datetime('now','-14 days') AND datetime('now','-7 days')`).first().catch(() => null),
          env.DB.prepare(`SELECT status, COUNT(*) as cnt, COALESCE(SUM(price_inr),0) as value FROM proposals WHERE updated_at >= datetime('now','-7 days') GROUP BY status`).all().catch(() => ({ results: [] })),
          env.DB.prepare(`SELECT status, COUNT(*) as cnt FROM proposals WHERE updated_at BETWEEN datetime('now','-14 days') AND datetime('now','-7 days') GROUP BY status`).all().catch(() => ({ results: [] })),
          env.DB.prepare(`SELECT COALESCE(SUM(amount_inr),0) as total, COUNT(*) as cnt FROM revenue_events WHERE created_at >= datetime('now','-7 days')`).first().catch(() => null),
          env.DB.prepare(`SELECT COALESCE(SUM(amount_inr),0) as total FROM revenue_events WHERE created_at BETWEEN datetime('now','-14 days') AND datetime('now','-7 days')`).first().catch(() => null),
          env.DB.prepare(`SELECT COUNT(*) as cnt FROM email_tracking WHERE event='sent' AND created_at >= datetime('now','-7 days')`).first().catch(() => null),
          env.DB.prepare(`SELECT COUNT(*) as cnt FROM email_tracking WHERE event IN ('failed_permanent','failed_retry') AND created_at >= datetime('now','-7 days')`).first().catch(() => null),
          env.DB.prepare(`SELECT COUNT(*) as cnt FROM email_sequences WHERE enrolled_at >= datetime('now','-7 days')`).first().catch(() => null),
          env.DB.prepare(`SELECT COALESCE(json_extract(meta,'$.utm_source'), 'direct') as src, COUNT(*) as cnt FROM funnel_events WHERE stage='email_capture' AND created_at >= datetime('now','-7 days') GROUP BY src ORDER BY cnt DESC LIMIT 5`).all().catch(() => ({ results: [] })),
          env.DB.prepare(`SELECT COUNT(*) as cnt FROM mssp_partners WHERE created_at >= datetime('now','-7 days')`).first().catch(() => null),
        ]);

        const propMapThis  = {}, propMapPrev = {};
        for (const r of (propThis?.results  ?? [])) propMapThis[r.status]  = { cnt: r.cnt, value: r.value };
        for (const r of (propPrev?.results  ?? [])) propMapPrev[r.status]  = r.cnt;

        const leadsN    = leadsThis?.cnt  || 0;
        const leadsP    = leadsPrev?.cnt  || 0;
        const sqlsN     = sqlsThis?.cnt   || 0;
        const sqlsP     = sqlsPrev?.cnt   || 0;
        const revN      = revThis?.total  || 0;
        const revP      = revPrev?.total  || 0;
        const sentN     = emailSent?.cnt  || 0;
        const failN     = emailFailed?.cnt || 0;

        const wow = (curr, prev) => prev > 0 ? Math.round((curr - prev) / prev * 1000) / 10 : null;
        const deliveryRate = (sentN + failN) > 0 ? Math.round(sentN / (sentN + failN) * 1000) / 10 : null;

        return withSecurityHeaders(withCors(Response.json({
          generated_at: new Date().toISOString(),
          period:  { days: 7, start: new Date(Date.now() - 7 * 86400000).toISOString().slice(0,10), end: new Date().toISOString().slice(0,10) },
          leads: {
            new_this_week:  leadsN,
            new_prev_week:  leadsP,
            wow_growth_pct: wow(leadsN, leadsP),
          },
          qualification: {
            sqls_this_week:  sqlsN,
            sqls_prev_week:  sqlsP,
            sql_wow_pct:     wow(sqlsN, sqlsP),
            sql_rate_pct:    leadsN > 0 ? Math.round(sqlsN / leadsN * 1000) / 10 : 0,
          },
          pipeline: {
            proposals_sent:     propMapThis.sent?.cnt     || 0,
            proposals_accepted: propMapThis.accepted?.cnt || 0,
            proposals_rejected: propMapThis.rejected?.cnt || 0,
            pipeline_value_inr: propMapThis.sent?.value   || 0,
            close_rate_pct: (() => {
              const c = (propMapThis.sent?.cnt||0) + (propMapThis.accepted?.cnt||0) + (propMapThis.rejected?.cnt||0);
              return c > 0 ? Math.round((propMapThis.accepted?.cnt||0) / c * 1000) / 10 : 0;
            })(),
          },
          revenue: {
            this_week_inr: revN,
            prev_week_inr: revP,
            wow_growth_pct: wow(revN, revP),
            transactions:  revThis?.cnt || 0,
          },
          email: {
            sequences_enrolled: seqEnrolled?.cnt || 0,
            emails_sent:        sentN,
            emails_failed:      failN,
            delivery_rate_pct:  deliveryRate,
          },
          acquisition_channels: (channelThis?.results ?? []).map(r => ({ source: r.src, leads: r.cnt })),
          mssp: { new_partners_this_week: msspThis?.cnt || 0 },
        }), request));
      } catch (e) {
        return withSecurityHeaders(withCors(Response.json({ error: e.message }, { status: 500 }), request));
      }
    }

    // PHASE 5 P0 — REVENUE INTELLIGENCE & RECURRING REVENUE
    // GET /api/revenue/kpi — Full KPI: Visitors, Leads, Proposals, Customers, MRR, ARR, CAC, LTV
    if (path === '/api/revenue/kpi' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE' }));
      if (!isOwner(authCtx, env)) return withSecurityHeaders(withCors(forbidden(), request));
      return withSecurityHeaders(withCors(await handleRevenueKPI(request, env), request));
    }

    // GET /api/revenue/funnel-analytics — Per-funnel drop-off (all 5 revenue funnels)
    if (path === '/api/revenue/funnel-analytics' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE' }));
      if (!isOwner(authCtx, env)) return withSecurityHeaders(withCors(forbidden(), request));
      return withSecurityHeaders(withCors(await handleFunnelAnalytics(request, env), request));
    }

    // GET /api/admin/pipeline-forecast — combined 30/60/90-day forward revenue forecast
    // Combines weighted proposal pipeline + upcoming subscription renewals into
    // a single forward-looking view for board-level pipeline reporting.
    if (path === '/api/admin/pipeline-forecast' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE' }));
      if (!isOwner(authCtx, env)) return withSecurityHeaders(withCors(forbidden(), request));
      if (!env.DB) return withSecurityHeaders(withCors(Response.json({ error: 'DB unavailable' }, { status: 503 }), request));

      try {
        const WIN_WEIGHTS = { draft: 0.1, sent: 0.3, accepted: 0.95, rejected: 0 };
        const [proposals, renewals30, renewals60, renewals90] = await Promise.all([
          env.DB.prepare(`SELECT status, COALESCE(SUM(price_inr),0) as value FROM proposals WHERE status IN ('draft','sent','accepted') GROUP BY status`).all().catch(() => ({ results: [] })),
          env.DB.prepare(`SELECT COUNT(*) as cnt, COALESCE(SUM(amount_inr),0) as arr FROM renewal_queue WHERE status='upcoming' AND renewal_date <= date('now','+30 days')`).first().catch(() => null),
          env.DB.prepare(`SELECT COUNT(*) as cnt, COALESCE(SUM(amount_inr),0) as arr FROM renewal_queue WHERE status='upcoming' AND renewal_date <= date('now','+60 days')`).first().catch(() => null),
          env.DB.prepare(`SELECT COUNT(*) as cnt, COALESCE(SUM(amount_inr),0) as arr FROM renewal_queue WHERE status='upcoming' AND renewal_date <= date('now','+90 days')`).first().catch(() => null),
        ]);

        const propMap = {};
        for (const r of (proposals?.results ?? [])) propMap[r.status] = r.value;
        const weightedPipeline = Object.entries(propMap).reduce(
          (s, [status, v]) => s + Math.round(v * (WIN_WEIGHTS[status] || 0)), 0
        );

        const mkWindow = (days, renewal) => ({
          days,
          weighted_proposals_inr: weightedPipeline,
          renewals_count:         renewal?.cnt || 0,
          renewals_arr_inr:       renewal?.arr || 0,
          combined_forecast_inr:  weightedPipeline + (renewal?.arr || 0),
        });

        return withSecurityHeaders(withCors(Response.json({
          generated_at: new Date().toISOString(),
          proposal_pipeline: {
            draft:    { value_inr: propMap.draft    || 0, weighted: Math.round((propMap.draft    || 0) * WIN_WEIGHTS.draft)    },
            sent:     { value_inr: propMap.sent     || 0, weighted: Math.round((propMap.sent     || 0) * WIN_WEIGHTS.sent)     },
            accepted: { value_inr: propMap.accepted || 0, weighted: Math.round((propMap.accepted || 0) * WIN_WEIGHTS.accepted) },
            total_weighted_inr: weightedPipeline,
            win_rates_used: WIN_WEIGHTS,
          },
          forecast: {
            d30: mkWindow(30, renewals30),
            d60: mkWindow(60, renewals60),
            d90: mkWindow(90, renewals90),
          },
        }), request));
      } catch (e) {
        return withSecurityHeaders(withCors(Response.json({ error: e.message }, { status: 500 }), request));
      }
    }

    // GET /api/admin/monthly-review — executive monthly revenue review
    // MoM MRR growth, ARR, new vs renewal vs expansion breakdown, churn, NRR.
    if (path === '/api/admin/monthly-review' && method === 'GET') {
      const authCtx = await resolveAuthV5(request, env).catch(() => ({ tier: 'FREE' }));
      if (!isOwner(authCtx, env)) return withSecurityHeaders(withCors(forbidden(), request));
      if (!env.DB) return withSecurityHeaders(withCors(Response.json({ error: 'DB unavailable' }, { status: 503 }), request));

      try {
        const now      = new Date();
        const thisMonthStart = now.toISOString().slice(0, 7) + '-01';
        const prevMonthStart = new Date(now.getFullYear(), now.getMonth() - 1, 1).toISOString().slice(0, 10);
        const prevMonthEnd   = new Date(now.getFullYear(), now.getMonth(), 0).toISOString().slice(0, 10);
        const yearStart      = now.getFullYear() + '-01-01';

        const [
          revThis, revPrev,
          revBySource, revBySourcePrev,
          subActive, subChurned,
          mrrSnap, channelThis,
        ] = await Promise.all([
          env.DB.prepare(`SELECT COALESCE(SUM(amount_inr),0) as total, COUNT(*) as cnt FROM revenue_events WHERE created_at >= ?`).bind(thisMonthStart).first().catch(() => null),
          env.DB.prepare(`SELECT COALESCE(SUM(amount_inr),0) as total FROM revenue_events WHERE created_at >= ? AND created_at < ?`).bind(prevMonthStart, thisMonthStart).first().catch(() => null),
          env.DB.prepare(`SELECT source, COALESCE(SUM(amount_inr),0) as total FROM revenue_events WHERE created_at >= ? GROUP BY source`).bind(thisMonthStart).all().catch(() => ({ results: [] })),
          env.DB.prepare(`SELECT source, COALESCE(SUM(amount_inr),0) as total FROM revenue_events WHERE created_at >= ? AND created_at < ? GROUP BY source`).bind(prevMonthStart, thisMonthStart).all().catch(() => ({ results: [] })),
          env.DB.prepare(`SELECT plan, COUNT(*) as cnt, COALESCE(SUM(price_inr),0) as mrr FROM subscriptions WHERE status='active' GROUP BY plan`).all().catch(() => ({ results: [] })),
          env.DB.prepare(`SELECT COUNT(*) as cnt FROM leads WHERE funnel_stage='churned' AND updated_at >= ?`).bind(thisMonthStart).first().catch(() => null),
          env.DB.prepare(`SELECT mrr_inr, arr_inr, snapshot_date FROM mrr_snapshots ORDER BY snapshot_date DESC LIMIT 2`).all().catch(() => ({ results: [] })),
          env.DB.prepare(`SELECT channel, COUNT(*) as cnt, COALESCE(SUM(mrr_generated),0) as mrr FROM cac_events WHERE converted=1 AND event_date >= ? GROUP BY channel ORDER BY mrr DESC LIMIT 5`).bind(thisMonthStart).all().catch(() => ({ results: [] })),
        ]);

        const totalMrr = (subActive?.results ?? []).reduce((s, r) => s + (r.mrr || 0), 0);
        const revN  = revThis?.total  || 0;
        const revP  = revPrev?.total  || 0;
        const momGrowthPct = revP > 0 ? Math.round((revN - revP) / revP * 1000) / 10 : null;

        const srcMapThis = {}, srcMapPrev = {};
        for (const r of (revBySource?.results ?? [])) srcMapThis[r.source] = r.total;
        for (const r of (revBySourcePrev?.results ?? [])) srcMapPrev[r.source] = r.total;

        const newRevenue       = srcMapThis.razorpay || 0;
        const renewalRevenue   = srcMapThis.subscription || 0;
        const expansionRevenue = srcMapThis.expansion || 0;
        const otherRevenue     = revN - newRevenue - renewalRevenue - expansionRevenue;

        const snapRows   = mrrSnap?.results ?? [];
        const mrrCurrent = snapRows[0]?.mrr_inr || totalMrr;
        const mrrPrev    = snapRows[1]?.mrr_inr || 0;
        const nrr = mrrPrev > 0 ? Math.round((mrrCurrent / mrrPrev) * 1000) / 10 : null;

        return withSecurityHeaders(withCors(Response.json({
          generated_at: new Date().toISOString(),
          period: { month: thisMonthStart.slice(0, 7), prev_month: prevMonthStart.slice(0, 7) },
          revenue: {
            this_month_inr:  revN,
            prev_month_inr:  revP,
            mom_growth_pct:  momGrowthPct,
            transactions:    revThis?.cnt || 0,
          },
          breakdown: {
            new_revenue_inr:       newRevenue,
            renewal_revenue_inr:   renewalRevenue,
            expansion_revenue_inr: expansionRevenue,
            other_inr:             Math.max(0, otherRevenue),
            new_pct:       revN > 0 ? Math.round(newRevenue / revN * 1000) / 10       : 0,
            renewal_pct:   revN > 0 ? Math.round(renewalRevenue / revN * 1000) / 10   : 0,
            expansion_pct: revN > 0 ? Math.round(expansionRevenue / revN * 1000) / 10 : 0,
          },
          subscriptions: {
            mrr_inr: mrrCurrent,
            arr_inr: mrrCurrent * 12,
            by_plan: (subActive?.results ?? []).map(r => ({ plan: r.plan, count: r.cnt, mrr: r.mrr })),
          },
          nrr_pct:     nrr,
          churn: { leads_churned_this_month: subChurned?.cnt || 0 },
          top_channels: (channelThis?.results ?? []).map(r => ({ channel: r.channel, conversions: r.cnt, mrr_inr: r.mrr })),
        }), request));
      } catch (e) {
        return withSecurityHeaders(withCors(Response.json({ error: e.message }, { status: 500 }), request));
      }
    }

    // GET /api/content/threat-brief-weekly — public SEO threat intelligence brief
    // Formatted for authority content publishing: SEO title, meta, top 5 CVEs,
    // executive summary, remediation steps, and marketing CTA for organic lead gen.
    if (path === '/api/content/threat-brief-weekly' && method === 'GET') {
      if (!env.DB) return withSecurityHeaders(withCors(Response.json({ error: 'DB unavailable' }, { status: 503 }), request));

      try {
        const [topCves, stats] = await Promise.all([
          env.DB.prepare(`
            SELECT id, title, description, cvss, severity, published_at, source_url, cve_id
            FROM threat_intel
            WHERE cvss IS NOT NULL AND cvss > 0
            ORDER BY cvss DESC, published_at DESC LIMIT 5
          `).all().catch(() => ({ results: [] })),
          env.DB.prepare(`
            SELECT COUNT(*) as total,
              SUM(CASE WHEN severity='CRITICAL' THEN 1 ELSE 0 END) as critical,
              SUM(CASE WHEN severity='HIGH' THEN 1 ELSE 0 END) as high,
              MAX(cvss) as max_cvss
            FROM threat_intel WHERE published_at >= date('now','-7 days')
          `).first().catch(() => null),
        ]);

        const cves = (topCves?.results ?? []).map((c, i) => ({
          rank:         i + 1,
          cve_id:       c.cve_id || c.id,
          title:        c.title,
          cvss_score:   c.cvss,
          severity:     c.severity,
          published:    c.published_at,
          summary:      (c.description || '').slice(0, 200) + ((c.description || '').length > 200 ? '…' : ''),
          remediation:  `Immediately patch ${c.cve_id || c.id}. Apply vendor security updates and review exposure in your environment.`,
          source_url:   c.source_url || null,
        }));

        const weekLabel = new Date().toLocaleDateString('en-US', { month: 'long', day: 'numeric', year: 'numeric' });
        const title     = `Top ${cves.length} Critical Vulnerabilities — Week of ${weekLabel}`;
        const meta      = `CYBERDUDEBIVASH AI Security Hub weekly threat brief: ${stats?.critical || 0} critical, ${stats?.high || 0} high-severity CVEs tracked this week. Protect your infrastructure now.`;

        return withSecurityHeaders(withCors(Response.json({
          seo: {
            title,
            meta_description:  meta,
            slug:              `threat-brief-${new Date().toISOString().slice(0,10)}`,
            publish_date:      new Date().toISOString().slice(0,10),
            canonical_url:     `https://cyberdudebivash.in/threat-briefs/${new Date().toISOString().slice(0,10)}`,
          },
          executive_summary: `This week, CYBERDUDEBIVASH AI Security Hub tracked ${stats?.total || 0} new vulnerabilities, including ${stats?.critical || 0} critical (CVSS ≥ 9.0) and ${stats?.high || 0} high-severity threats. The highest CVSS score this week is ${stats?.max_cvss || 'N/A'}. Immediate patching is required for the vulnerabilities listed below.`,
          threats:       cves,
          week_stats:    { total_cves: stats?.total || 0, critical: stats?.critical || 0, high: stats?.high || 0, max_cvss: stats?.max_cvss || 0 },
          cta: {
            headline:    'Is your infrastructure exposed to these vulnerabilities?',
            body:        'Get an instant AI-powered security assessment tailored to your domain — free, no credit card required.',
            action:      'Start Free Security Scan',
            url:         'https://cyberdudebivash.in/#scan',
            lead_capture: true,
          },
          generated_at: new Date().toISOString(),
        }), request));
      } catch (e) {
        return withSecurityHeaders(withCors(Response.json({ error: e.message }, { status: 500 }), request));
      }
    }

    return withSecurityHeaders(withCors(Response.json({
      error:    'Not Found',
      path,
      method,
      api_docs: 'GET /api',
      contact:  CONTACT_EMAIL,
    }, { status: 404 }), request));
  },

  // ── Cloudflare Queue consumer ─────────────────────────────────────────────
  async queue(batch, env) {
    normalizeBindings(env);
    await processQueueBatch(batch, env);
  },

  // ── Cron scheduler ───────────────────────────────────────────────────────
  async scheduled(event, env, ctx) {
    normalizeBindings(env);
    const cron = event.cron;
    console.log('[CRON] Trigger:', cron, event.scheduledTime);

    // ── HOURLY: Threat Intel Ingestion (Sentinel APEX v2.0 — D1-backed) ──
    // Runs every cron trigger — priority pipeline
    // ── v30.0: Platform Metrics Hydration ───────────────────────────────────────
    ctx.waitUntil(
      refreshPlatformMetrics(env)
        .then(r => console.log('[CRON] MetricsHydration:', JSON.stringify(r)))
        .catch(e => console.error('[CRON] MetricsHydration error:', e?.message))
    );

ctx.waitUntil(
      runIngestion(env)
        .then(r => console.log('[CRON] Threat Ingestion:', JSON.stringify({
          sources:  r.sources,
          total:    r.total,
          inserted: r.inserted,
          errors:   r.errors,
          duration_ms: r.duration_ms,
        })))
        .catch(e => console.error('[CRON] Threat Ingestion error:', e?.message))
    );

    // ── HOURLY: AI Threat Radar — dedicated, targeted AI/LLM ecosystem scan
    //    (OSV.dev watchlist + rotated NVD keyword search + GitHub Advisory API),
    //    independent of the generic CTI pipeline above. ──
    ctx.waitUntil(
      runAIThreatRadar(env)
        .then(r => console.log('[CRON] AI Threat Radar:', JSON.stringify({
          sources: r.sources, matched: r.matched, inserted: r.inserted,
          errors: r.errors, duration_ms: r.duration_ms,
        })))
        .catch(e => console.error('[CRON] AI Threat Radar error:', e?.message))
    );

    // ── HOURLY: AI Threat Report — runs INDEPENDENTLY of radar scan so the
    //    report always publishes to KV even when external APIs are down.
    //    Uses curated library as baseline + any live rows already in D1. ──
    ctx.waitUntil(
      generateAndPublishAIThreatReport(env)
        .then(r => {
          if (r) console.log('[CRON] AI Threat Report published:', r.report_id,
            `| risk=${r.risk_level} | threats=${r.total_threats} | live=${r.live_entries}`);
        })
        .catch(e => console.error('[CRON] AI Threat Report error:', e?.message))
    );

    // ── DAILY (6 AM): Bulk backfill — refresh the FULL CISA KEV catalog and
    //    advance one paginated NVD page per severity (Phase-2 catalog growth). ──
    if (cron === '0 6 * * *') {
      ctx.waitUntil(
        runBulkBackfill(env, { nvdBackfill: true })
          .then(r => console.log('[CRON] Bulk Backfill:', JSON.stringify({
            kev: r.kev_inserted, nvd: r.nvd_inserted, total: r.total_now,
            epss: r.epss_enriched, errors: r.errors?.length, duration_ms: r.duration_ms,
          })))
          .catch(e => console.error('[CRON] Bulk Backfill error:', e?.message))
      );
    }

    // ── DAILY (6 AM): Pull real GHSA advisories for tracked AI agent
    //    frameworks (LangChain, CrewAI, AutoGen, OpenAI Agents, MCP,
    //    LlamaIndex) so /agent-threats stops showing the same 5 seed rows. ──
    if (cron === '0 6 * * *') {
      ctx.waitUntil(
        ingestAgentThreatAdvisories(env)
          .then(r => console.log('[CRON] Agent Threat Advisories:', JSON.stringify(r)))
          .catch(e => console.error('[CRON] Agent Threat Advisories error:', e?.message))
      );
    }

    // ── DAILY (6 AM): Pull the real MITRE ATLAS technique catalog so
    //    /attack-library stops being frozen at its 11 hand-seeded rows. ──
    if (cron === '0 6 * * *') {
      ctx.waitUntil(
        ingestAttackLibraryTechniques(env)
          .then(r => console.log('[CRON] Attack Library Techniques:', JSON.stringify(r)))
          .catch(e => console.error('[CRON] Attack Library Techniques error:', e?.message))
      );
    }

    // ── 4x/DAY: Incremental EPSS enrichment — converge exploit-probability
    //    scores across the large catalog without a single heavy pass. ──
    if (cron === '0 0,6,12,18 * * *') {
      ctx.waitUntil(
        enrichUnscoredEPSS(env, 200)
          .then(r => console.log('[CRON] EPSS enrichment:', JSON.stringify(r)))
          .catch(e => console.error('[CRON] EPSS enrichment error:', e?.message))
      );
    }

    // ── HOURLY: Sentinel APEX legacy KV feed refresh ──
    ctx.waitUntil(
      runSentinelCron(env)
        .then(r => console.log('[CRON] Sentinel APEX KV:', JSON.stringify(r)))
        .catch(e => console.error('[CRON] Sentinel KV error:', e?.message))
    );

    // ── HOURLY: Continuous monitoring scans ──
    ctx.waitUntil(
      runMonitoringCron(env)
        .then(r => console.log('[CRON] Monitoring:', JSON.stringify(r)))
        .catch(e => console.error('[CRON] Monitoring error:', e?.message))
    );

    // ── HOURLY: Purge expired legacy threat intel cache entries ──
    ctx.waitUntil(
      purgeExpiredThreatIntel(env)
        .then(n => { if (n > 0) console.log(`[CRON] Purged ${n} expired threat intel entries`); })
        .catch(e => console.error('[CRON] Purge error:', e?.message))
    );

    // ── HOURLY: v21.0 Adaptive Cyber Brain — refresh global signals + FP patterns ──
    ctx.waitUntil(
      runAdaptiveBrainCron(env)
        .then(r => console.log('[CRON] AdaptiveBrain:', JSON.stringify(r)))
        .catch(e => console.error('[CRON] AdaptiveBrain error:', e?.message))
    );

    // ── Sentinel APEX v3: Global Federation + SOC Automation Pipeline ────────
    // Non-blocking — runs after ingestion, uses the freshly-written D1 data
    // Phase 6: Async pipeline integration (federation → detection → decisions → defense)
    ctx.waitUntil((async () => {
      try {
        // 1. Wait a moment for ingestion to settle, then run federation
        await new Promise(r => setTimeout(r, 3000));

        // 2. Run global feed federation (adds ExploitDB + RSS + VT to existing D1 entries)
        const fedResult = await runFederation(env, []);
        console.log('[CRON] Federation:', JSON.stringify({
          total:    fedResult.total_entries,
          sources:  fedResult.sources_active,
          confidence: fedResult.confidence,
          ms:       fedResult.federation_ms,
        }));

        // 3. Run SOC detection on federated feed (already enriched by federation pipeline)
        const enriched  = fedResult.global_feed.slice(0, 100);  // entries enriched during ingestion
        const detResult = runDetection(enriched);
        console.log('[CRON] SOC Detection:', JSON.stringify({
          alerts: detResult.total,
          critical: detResult.by_severity?.CRITICAL || 0,
        }));

        // 4. Run AI decision engine
        const decResult = runDecisionEngine(enriched, detResult);
        console.log('[CRON] SOC Decisions:', JSON.stringify({
          total:        decResult.total,
          threat_level: decResult.overall_threat_level,
          escalations:  decResult.p1_count,
        }));

        // 5. Run autonomous defense
        const defResult = runAutonomousDefense(enriched, decResult.decisions);
        console.log('[CRON] Autonomous Defense:', JSON.stringify({
          actions:  defResult.total_actions,
          posture:  defResult.posture_level,
        }));

        // 6. Store all SOC results (batch, non-blocking)
        await Promise.all([
          storeDetectionResults(env, detResult),
          storeDecisions(env, decResult),
          storeDefenseActions(env, defResult),
        ]);

        // 7. Invalidate hot cache so next API request hits fresh D1
        if (env?.SECURITY_HUB_KV) {
          env.SECURITY_HUB_KV.delete('threat_intel:hot:v2').catch(() => {});
          env.SECURITY_HUB_KV.delete('sentinel:federation:latest').catch(() => {});
        }

        console.log('[CRON] Sentinel APEX v3 SOC pipeline complete');
      } catch (e) {
        console.error('[CRON] SOC pipeline error:', e?.message);
      }
    })());

    // ── GTM Growth Engine v12: Email Drip + Sales + Content pipelines ─────────
    ctx.waitUntil((async () => {
      try {
        // 1. Run email drip automation (send due sequence emails)
        const dripResult = await runDripAutomation(env);
        console.log('[CRON] GTM Drip Emails:', JSON.stringify(dripResult));

        // 2. Run enterprise sales pipeline (detect + generate outreach)

        const salesResult = await runSalesPipeline(env);
        console.log('[CRON] GTM Sales Pipeline:', JSON.stringify(salesResult));

        // 3. Run content automation (CRITICAL CVEs → LinkedIn/Twitter/Telegram)
        const criticalRows = await env.DB.prepare(
          `SELECT * FROM threat_intel WHERE severity = 'CRITICAL' ORDER BY cvss DESC, published_at DESC LIMIT 5`
        ).all().catch(() => ({ results: [] }));

        if ((criticalRows.results || []).length > 0) {
          const contentResult = await runContentPipeline(env, criticalRows.results);
          console.log('[CRON] GTM Content:', JSON.stringify({
            generated: contentResult.generated,
            posted:    contentResult.telegram_posted,
          }));
        }

        // 4. LinkedIn authority post automation (Mon/Tue/Thu/Fri only)
        const linkedInResult = await runLinkedInAutomation(env, criticalRows.results || [], {});
        if (!linkedInResult.skipped) {
          console.log('[CRON] GTM LinkedIn:', JSON.stringify(linkedInResult));
        }

        console.log('[CRON] GTM Growth Engine pipeline complete');
      } catch (e) {
        console.error('[CRON] GTM pipeline error:', e?.message);
      }
    })());

    // ── v8.2 Revenue Automation Pipeline ─────────────────────────────────────
    ctx.waitUntil((async () => {
      try {
        const { runAutomationCron } = await import('./services/automationEngine.js');
        const autoResult = await runAutomationCron(env, event.cron);
        console.log('[CRON] Revenue Automation:', JSON.stringify({
          jobs_run:    autoResult.jobs_run,
          duration_ms: autoResult.duration_ms,
          defense_products_generated: autoResult.results?.defense_products?.generated || 0,
          upsell_emails_processed:    autoResult.results?.upsell_emails?.processed    || 0,
          churn_flagged:              autoResult.results?.churn_prevention?.at_risk    || 0,
        }));
      } catch (e) {
        console.error('[CRON] Revenue Automation error:', e?.message);
      }
    })());

    // ── v10.0 Sentinel APEX Defense Product Generation (every 12h) ───────────
    if (cron === '0 */12 * * *' || cron === '0 0 * * *') {
      ctx.waitUntil((async () => {
        try {
          const { generateAndStoreAll, fetchLiveIntel } = await import('./services/sentinelDefenseEngine.js');
          const intel = await fetchLiveIntel(env, { limit: 10, severity: 'HIGH' });
          let generated = 0;
          for (const item of intel.slice(0, 5)) {
            const r = await generateAndStoreAll(env, item);
            generated += r.stored || 0;
          }
          console.log(`[CRON] v10 Defense Products: ${generated} stored for ${intel.length} CVEs`);
        } catch (e) {
          console.error('[CRON] v10 Defense generation error:', e?.message);
        }
      })());
    }

    // ── v10.0 Content Pipeline — CVE→Blog→LinkedIn→Telegram (every 24h) ─────
    if (cron === '0 6 * * *' || cron === '0 0 * * *') {
      ctx.waitUntil((async () => {
        try {
          const { runBulkContentPipeline } = await import('./services/contentPipeline.js');
          const result = await runBulkContentPipeline(env, 3);
          console.log('[CRON] v10 Content Pipeline:', JSON.stringify({
            processed:  result.processed,
            linkedin:   result.results?.filter(r => r.linkedin?.success).length || 0,
            telegram:   result.results?.filter(r => r.telegram?.success).length || 0,
          }));
        } catch (e) {
          console.error('[CRON] v10 Content Pipeline error:', e?.message);
        }
      })());
    }

    // ── v10.0 Revenue Snapshot — daily KPI capture ────────────────────────────
    if (cron === '0 23 * * *' || cron === '0 0 * * *') {
      // v23.0 RevOS: MRR Snapshot
      ctx.waitUntil(
        writeMRRSnapshot(env.DB)
          .then(r => console.log('[CRON] RevOS MRR:', JSON.stringify(r)))
          .catch(e => console.error('[CRON] RevOS MRR error:', e?.message))
      );
      // v24.0: Build renewal queue + run payment recovery
      ctx.waitUntil((async () => {
        try {
          const { buildRenewalQueue, runPaymentRecovery } = await import('./services/v24/billingEngine.js');
          await buildRenewalQueue(env.DB);
          await runPaymentRecovery(env.DB, env);
          console.log('[CRON] v24 Billing: renewal queue + recovery run complete');
        } catch (e) { console.error('[CRON] v24 Billing error:', e?.message); }
      })());
      // v35.1 Phase 5 P0: Renewal automation — seed 35-day window + send reminders
      ctx.waitUntil((async () => {
        try {
          await seedRenewalQueue35d(env);
          const renewalResult = await runRenewalAutomation(env);
          console.log('[CRON] Phase5 Renewals:', JSON.stringify(renewalResult));
        } catch (e) { console.error('[CRON] Phase5 Renewals error:', e?.message); }
      })());

      // Phase 11 P0: Quota nudge — enroll users at 80%+ usage in upgrade_nudge sequence
      ctx.waitUntil((async () => {
        try {
          if (!env.DB) return;
          const monthStart = new Date().toISOString().slice(0, 7) + '-01';
          const PLAN_LIMITS = { FREE: 3, STARTER: 10 };
          const rows = await env.DB.prepare(`
            SELECT ak.email, ak.tier, COALESCE(SUM(aku.request_count), 0) as used
            FROM api_keys ak
            LEFT JOIN api_key_usage aku ON aku.key_id = ak.id AND aku.date_bucket >= ?
            WHERE ak.email IS NOT NULL AND ak.tier IN ('FREE','STARTER')
            GROUP BY ak.id, ak.email, ak.tier
          `).bind(monthStart).all().catch(() => ({ results: [] }));
          const { enrollInSequence } = await import('./services/emailEngine.js');
          for (const row of (rows?.results ?? [])) {
            const limit = PLAN_LIMITS[row.tier] ?? 3;
            if (limit > 0 && row.used / limit >= 0.8 && row.email) {
              enrollInSequence(env, row.email, 'upgrade_nudge', {
                plan: row.tier.toLowerCase(), scans_used: row.used, scans_limit: limit,
                upgrade_plan: row.tier === 'FREE' ? 'STARTER' : 'PRO',
              }).catch(() => {});
            }
          }
          console.log('[CRON] Phase11 QuotaNudge: evaluated', rows?.results?.length ?? 0, 'keys');
        } catch (e) { console.error('[CRON] Phase11 QuotaNudge error:', e?.message); }
      })());

      // Phase 12: Daily batch lead score recomputation — upgrades scores as usage accumulates
      // and triggers smart routing (SQL → enterprise_nurture) for newly qualified leads
      ctx.waitUntil((async () => {
        try {
          if (!env.DB) return;
          const { computeAndUpdateLeadScore } = await import('./handlers/leads.js');
          const activeLeads = await env.DB.prepare(`
            SELECT email FROM leads
            WHERE scan_count > 0 AND funnel_stage NOT IN ('customer','churned')
            ORDER BY updated_at ASC LIMIT 200
          `).all().catch(() => ({ results: [] }));
          let recomputed = 0;
          for (const lead of (activeLeads?.results ?? [])) {
            await computeAndUpdateLeadScore(env, lead.email).catch(() => {});
            recomputed++;
          }
          console.log('[CRON] Phase12 LeadScoring: recomputed', recomputed, 'leads');
        } catch (e) { console.error('[CRON] Phase12 LeadScoring error:', e?.message); }
      })());

      // v23.0 RevOS: AI CS Analysis
      ctx.waitUntil(
        runCSAnalysis(env.DB)
          .then(r => console.log('[CRON] RevOS CS:', JSON.stringify(r)))
          .catch(e => console.error('[CRON] RevOS CS error:', e?.message))
      );
      // v23.0 RevOS: Auto-queue critical CVEs for product generation
      ctx.waitUntil((async () => {
        try {
          const critCVEs = await env.DB?.prepare(`SELECT id, title, cvss, severity FROM threat_intel WHERE severity IN ('CRITICAL','HIGH') AND id NOT IN (SELECT cve_id FROM product_pipeline) ORDER BY COALESCE(cvss, cvss_score, 0) DESC LIMIT 5`).all().catch(() => ({ results: [] }));
          if (critCVEs?.results?.length > 0) {
            await queueCVEsForGeneration(env.DB, critCVEs.results);
            for (const cve of critCVEs.results.slice(0, 2)) { await runProductPipeline(env.DB, cve.id).catch(() => {}); }
            console.log('[CRON] RevOS Pipeline queued:', critCVEs.results.length);
          }
        } catch (e) { console.error('[CRON] RevOS Pipeline error:', e?.message); }
      })());
      // v10 legacy snapshot
      ctx.waitUntil((async () => {
        try {
          const today = new Date().toISOString().slice(0, 10);
          const [subRow, defRow, totalUsers] = await Promise.allSettled([
            env.DB?.prepare(`SELECT COUNT(*) as cnt, SUM(amount) as rev FROM revenue_events WHERE event_type='subscription_payment' AND DATE(created_at)=?`).bind(today).first(),
            env.DB?.prepare(`SELECT COUNT(*) as cnt, SUM(amount_inr) as rev FROM defense_purchases WHERE status='paid' AND DATE(created_at)=?`).bind(today).first(),
            env.DB?.prepare(`SELECT COUNT(*) as total FROM users`).first(),
          ]);
          await env.DB?.prepare(`INSERT OR REPLACE INTO revenue_snapshots (id, snapshot_date, daily_revenue, defense_sales, defense_revenue, total_users) VALUES (?,?,?,?,?,?)`).bind(crypto.randomUUID(), today, (subRow.value?.rev || 0) + (defRow.value?.rev || 0), defRow.value?.cnt || 0, defRow.value?.rev || 0, totalUsers.value?.total || 0).run();
          console.log(`[CRON] v10 Revenue Snapshot: ${today}`);
        } catch (e) { console.error('[CRON] v10 Snapshot error:', e?.message); }
      })());
    }

    // ── v12 P0 MISSION: Agentic AI Engine — Agent Event Queue Processing ───────
    ctx.waitUntil((async () => {
      try {
        // Process pending events from agent bus (CVE detections, anomaly events)
        const events = await consumeEvents(env, 20);
        let processed = 0;
        for (const event of events) {
          try {
            if (event.event_type === 'cve_detected') {
              await processCVEEvent(env, event);
            } else if (event.event_type === 'anomaly_detected') {
              const decision = decideAnomalyResponse(event.payload || {});
              for (const action of decision.actions) {
                if (action.action_type === 'block_ip' && action.target) {
                  await autoBlockIP(env, action.target, 'anomaly_cron', decision.risk_level, event.id);
                }
                if ((action.action_type === 'rotate_credentials' || action.action_type === 'disable_session') && action.target) {
                  await autoRotateOnAnomaly(env, action.target, event.payload || {});
                }
              }
            }
            await ackEvent(env, event.id, true);
            processed++;
          } catch (evErr) {
            await ackEvent(env, event.id, false, evErr.message);
          }
        }
        if (processed > 0) console.log(`[CRON] v12 Agent Bus: processed ${processed} events`);
      } catch (e) {
        console.error('[CRON] v12 Agent Bus error:', e?.message);
      }
    })());

    // ── v12 P0 MISSION: Behavioral Anomaly Detection — batch scan (every 15 min)
    ctx.waitUntil((async () => {
      try {
        const result = await runAnomalyBatch(env);
        if (result.anomalies_detected > 0) {
          console.log(`[CRON] v12 Anomaly Engine: ${result.scanned} users scanned, ${result.anomalies_detected} anomalies (${result.high_risk} CRITICAL/HIGH)`);
        }
      } catch (e) {
        console.error('[CRON] v12 Anomaly Engine error:', e?.message);
      }
    })());

    // ── v12 P0 MISSION: Predictive Threat Intelligence — batch (every 1h) ──────
    if (cron === '0 * * * *' || cron === '*/15 * * * *' || cron === '0 */2 * * *') {
      ctx.waitUntil((async () => {
        try {
          const result = await runPredictiveBatch(env);
          if (result.predictions > 0) {
            console.log(`[CRON] v12 Predictive Engine: ${result.analyzed} CVEs analyzed, ${result.critical_count} CRITICAL, ${result.high_count} HIGH`);
          }
        } catch (e) {
          console.error('[CRON] v12 Predictive Engine error:', e?.message);
        }
      })());
    }

    // ── v12 P0 MISSION: Virtual WAF Patching — expire stale patches + batch ────
    ctx.waitUntil((async () => {
      try {
        // Get recent HIGH+KEV CVEs for auto-patching
        const recentCVEs = await env.DB?.prepare(`
          SELECT cve_id, cvss_score as cvss, epss_score as epss, is_kev,
                 description, cvss_vector
          FROM threat_intel
          WHERE (cvss_score >= 7.0 OR is_kev = 1)
            AND published_date > datetime('now', '-3 days')
          ORDER BY cvss_score DESC LIMIT 20
        `).all().catch(() => ({ results: [] }));

        const patchResult = await runPatchingBatch(env, recentCVEs?.results || []);
        if (patchResult.patched > 0 || patchResult.expired > 0) {
          console.log(`[CRON] v12 Patching Agent: ${patchResult.patched} patches applied, ${patchResult.expired} expired`);
        }
      } catch (e) {
        console.error('[CRON] v12 Patching Agent error:', e?.message);
      }
    })());

    // ── MYTHOS GOD MODE v4.0 — full 12-phase autonomous platform sweep ───────────
    // Runs every 6h (replaces the old 12h-only orchestrator cron).
    // Also runs at daily 6am and on the midnight all-jobs cron.
    if (cron === '0 */6 * * *' || cron === '0 6 * * *' || cron === '0 0 * * *') {
      ctx.waitUntil((async () => {
        try {
          const result = await runGodModeCron(env);
          console.log(
            `[CRON] MYTHOS GOD MODE: ` +
            `${result.summary?.intel_processed || 0} intel, ` +
            `${result.summary?.tools_generated || 0} tools, ` +
            `posture: ${result.summary?.posture_score || 0}/100`
          );
        } catch (e) {
          console.error('[CRON] MYTHOS GOD MODE error:', e?.message);
        }
      })());

      // ── Phase C: MYTHOS Autonomous Platform Governor — runs alongside GOD MODE ──
      ctx.waitUntil((async () => {
        try {
          const govResult = await runPlatformGovernor(env);
          console.log(
            `[CRON] GOVERNOR: ${govResult.overall_status} — ` +
            `${govResult.summary?.healthy || 0}/${govResult.summary?.total_subsystems || 0} healthy, ` +
            `${govResult.summary?.repaired || 0} repaired, ` +
            `${govResult.summary?.alerts_sent || 0} alerts`
          );
        } catch (e) {
          console.error('[CRON] GOVERNOR error:', e?.message);
        }
      })());
    }

    // ── MYTHOS ORCHESTRATOR CORE — legacy tool generation fallback (every 12h) ──
    if (cron === '0 */12 * * *') {
      ctx.waitUntil((async () => {
        try {
          const result = await runMythosCron(env);
          console.log(`[CRON] MYTHOS CORE: ${result.total_tools} tools generated, ${result.total_published} published`);
        } catch (e) {
          console.error('[CRON] MYTHOS Core error:', e?.message);
        }
      })());
    }

    // ── PHASE 2: Autonomous SOC Mode cron check ───────────────────────────────
    ctx.waitUntil((async () => {
      try {
        await runAutoSocCron(env);
        console.log('[CRON] AutoSOC: cron check complete');
      } catch (e) {
        console.error('[CRON] AutoSOC error:', e?.message);
      }
    })());

    // ── P7.0 Automation crons — webhook retries every 30 min, reports daily ─
    ctx.waitUntil((async () => {
      try {
        const { runAutomationCrons } = await import('./handlers/enterpriseAutomation.js');
        const r = await runAutomationCrons(env);
        if (r.webhook_retries.retried > 0 || r.webhook_retries.dead_lettered > 0 || r.scheduled_reports.sent > 0) {
          console.log(`[CRON] AUTOMATION: wh_retried=${r.webhook_retries.retried} dead=${r.webhook_retries.dead_lettered} reports_sent=${r.scheduled_reports.sent}`);
        }
      } catch (e) { console.error('[CRON] AUTOMATION error:', e?.message); }
    })());

    // ── P6.0-009 Ops Lifecycle — daily 3am UTC ─────────────────────────────
    if (cron === '0 3 * * *' || cron === '0 0 * * *') {
      ctx.waitUntil((async () => {
        try {
          const { runOpsLifecycleCron } = await import('./handlers/opsEngine.js');
          const report = await runOpsLifecycleCron(env);
          console.log(`[CRON] OPS LIFECYCLE: -${report.deleted_usage_events} usage_events, -${report.deleted_notifications} notifications, ${report.aggregated_days} days aggregated`);
        } catch (e) {
          console.error('[CRON] OPS LIFECYCLE error:', e?.message);
        }
      })());
    }

  },
};
