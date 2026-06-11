"""
RAG Retriever — Retrieval-Augmented Generation for all agents.
Attaches relevant knowledge context to agent prompts automatically.
"""
from __future__ import annotations
from typing import Any, Dict, List, Optional
from .knowledge_base import KnowledgeBase, KnowledgeSource

try:
    import structlog
    logger = structlog.get_logger(__name__)
except ImportError:
    import logging
    logger = logging.getLogger(__name__)

INTENT_KNOWLEDGE_MAP: Dict[str, List[KnowledgeSource]] = {
    "analyze_ioc":           [KnowledgeSource.MITRE_ATTACK, KnowledgeSource.IOC_FEEDS],
    "lookup_cve":            [KnowledgeSource.CVE_DATABASE, KnowledgeSource.NIST_800_53],
    "analyze_malware":       [KnowledgeSource.MITRE_ATTACK, KnowledgeSource.IOC_FEEDS],
    "get_threat_actor":      [KnowledgeSource.MITRE_ATTACK, KnowledgeSource.THREAT_REPORTS],
    "compliance_check":      [KnowledgeSource.NIST_CSF, KnowledgeSource.NIST_800_53],
    "assess_prompt_injection":[KnowledgeSource.OWASP_LLM, KnowledgeSource.MITRE_ATLAS],
    "ai_governance_check":   [KnowledgeSource.NIST_AI_RMF, KnowledgeSource.OWASP_LLM],
    "incident_response":     [KnowledgeSource.PLAYBOOKS, KnowledgeSource.MITRE_ATTACK],
    "threat_hunt":           [KnowledgeSource.MITRE_ATTACK, KnowledgeSource.IOC_FEEDS],
    "ciso_briefing":         [KnowledgeSource.THREAT_REPORTS, KnowledgeSource.NIST_CSF],
}

class RAGRetriever:
    def __init__(self, knowledge_base: KnowledgeBase):
        self.kb = knowledge_base

    async def enrich_prompt(self, intent: str, query: str, top_k: int = 3) -> str:
        """
        Retrieve relevant knowledge and return formatted context string
        to prepend to AI provider prompts. Reduces hallucination.
        """
        sources = INTENT_KNOWLEDGE_MAP.get(intent)
        try:
            results = await self.kb.search(query, sources=sources, top_k=top_k, min_score=0.55)
        except Exception:
            return ""

        if not results:
            return ""

        context_parts = ["=== RETRIEVED KNOWLEDGE CONTEXT ==="]
        for r in results:
            context_parts.append(
                f"[{r['source'].upper()} | Trust: {r['trust_score']:.1f} | Score: {r['score']:.2f}]\n"
                f"Title: {r['title']}\n"
                f"Content: {r['content'][:400]}\n"
            )
        context_parts.append("=== END CONTEXT ===\n")
        return "\n".join(context_parts)

    async def get_sources(self, intent: str, query: str, top_k: int = 5) -> List[Dict[str, Any]]:
        """Return source citations for response attribution."""
        sources = INTENT_KNOWLEDGE_MAP.get(intent)
        try:
            results = await self.kb.search(query, sources=sources, top_k=top_k)
            return [
                {
                    "title":  r["title"],
                    "source": r["source"],
                    "score":  round(r["score"], 3),
                    "url":    r["metadata"].get("url", ""),
                }
                for r in results
            ]
        except Exception:
            return []
