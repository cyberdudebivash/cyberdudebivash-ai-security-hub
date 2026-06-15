"""
CYBERDUDEBIVASH(R) MACOS - Agents Package
Exports all 50+ specialist agents across all domains.
"""
# Core
from .core.base_agent import BaseAgent, AgentLayer, AgentCapability
from .core.orchestrator import MasterOrchestrator
from .core.agent_registry import AgentRegistry

# SOC
from .soc import (
    SOCTier1Agent, SOCTier2Agent, SOCTier3Agent,
    IncidentResponseAgent, ThreatHuntingAgent,
    DetectionEngineeringAgent, ForensicsAgent,
    PhishingAnalysisAgent, SIEMCorrelationAgent, RansomwareResponseAgent,
)

# Threat Intelligence
from .threat_intel import (
    IOCIntelligenceAgent, CVEIntelligenceAgent,
    MalwareIntelligenceAgent, ThreatActorAgent,
    EnrichmentAgent, CampaignIntelligenceAgent,
    DarkWebMonitoringAgent, OSINTAgent, ZeroDayResearchAgent,
)

# AI Security
from .ai_security import (
    PromptInjectionAgent, AIGovernanceAgent,
    AIRedTeamAgent, AIRuntimeSecurityAgent, AIRiskAgent,
)

# Security Engineering (includes ComplianceAgent)
from .security_engineering import (
    ComplianceAgent, SecurityArchitectureAgent, CloudSecurityAgent,
    DevSecOpsAgent, VulnerabilityAgent, PenetrationTestingAgent, RedTeamAgent,
    APISecurityAgent, ContainerSecurityAgent, IdentitySecurityAgent,
    NetworkSecurityAgent, EndpointSecurityAgent, SupplyChainSecurityAgent,
    DataLossPreventionAgent, ThreatModelingAgent, EmailSecurityAgent,
    WebApplicationSecurityAgent, IoTSecurityAgent, BlockchainSecurityAgent,
    PrivilegedAccessAgent, RegulatoryReportingAgent,
)

# Executive
from .executive import CEOAgent, CISOAgent, CROAgent, CTOAgent

# Research
from .research import ThreatResearchAgent

# Revenue
from .revenue import SubscriptionAgent, BillingAgent, OnboardingAgent, RenewalAgent

# Content
from .content import ResearchAgent, BlogAgent, WhitepaperAgent, ContentIntelligenceAgent

# Customer
from .customer import CustomerSuccessAgent, MSSPAgent, VendorRiskAgent, CyberInsuranceAgent

__all__ = [
    # Core
    "BaseAgent", "AgentLayer", "AgentCapability", "MasterOrchestrator", "AgentRegistry",
    # SOC
    "SOCTier1Agent", "SOCTier2Agent", "SOCTier3Agent",
    "IncidentResponseAgent", "ThreatHuntingAgent",
    "DetectionEngineeringAgent", "ForensicsAgent",
    "PhishingAnalysisAgent", "SIEMCorrelationAgent", "RansomwareResponseAgent",
    # Threat Intel
    "IOCIntelligenceAgent", "CVEIntelligenceAgent",
    "MalwareIntelligenceAgent", "ThreatActorAgent",
    "EnrichmentAgent", "CampaignIntelligenceAgent",
    "DarkWebMonitoringAgent", "OSINTAgent", "ZeroDayResearchAgent",
    # AI Security
    "PromptInjectionAgent", "AIGovernanceAgent",
    "AIRedTeamAgent", "AIRuntimeSecurityAgent", "AIRiskAgent",
    # Security Engineering
    "ComplianceAgent",
    "SecurityArchitectureAgent", "CloudSecurityAgent", "DevSecOpsAgent",
    "VulnerabilityAgent", "PenetrationTestingAgent", "RedTeamAgent",
    "APISecurityAgent", "ContainerSecurityAgent", "IdentitySecurityAgent",
    "NetworkSecurityAgent", "EndpointSecurityAgent", "SupplyChainSecurityAgent",
    "DataLossPreventionAgent", "ThreatModelingAgent", "EmailSecurityAgent",
    "WebApplicationSecurityAgent", "IoTSecurityAgent", "BlockchainSecurityAgent",
    "PrivilegedAccessAgent", "RegulatoryReportingAgent",
    # Executive
    "CEOAgent", "CISOAgent", "CROAgent", "CTOAgent",
    # Research
    "ThreatResearchAgent",
    # Revenue
    "SubscriptionAgent", "BillingAgent", "OnboardingAgent", "RenewalAgent",
    # Content
    "ResearchAgent", "BlogAgent", "WhitepaperAgent", "ContentIntelligenceAgent",
    # Customer
    "CustomerSuccessAgent", "MSSPAgent", "VendorRiskAgent", "CyberInsuranceAgent",
]
