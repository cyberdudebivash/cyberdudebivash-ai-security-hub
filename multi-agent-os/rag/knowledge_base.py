"""
CYBERDUDEBIVASH® Multi-Agent Cybersecurity OS
Unified RAG Knowledge System — MITRE, OWASP, NIST, CVE, IOC, Playbooks.
Qdrant-backed vector search + PostgreSQL metadata store.
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

import structlog

logger = structlog.get_logger(__name__)

class KnowledgeSource(str, Enum):
    MITRE_ATTACK   = "mitre_attack"
    MITRE_ATLAS    = "mitre_atlas"    # AI/ML threat matrix
    OWASP_LLM      = "owasp_llm"
    OWASP_TOP10    = "owasp_top10"
    NIST_CSF       = "nist_csf"
    NIST_AI_RMF    = "nist_ai_rmf"
    NIST_800_53    = "nist_800_53"
    CVE_DATABASE   = "cve_database"
    IOC_FEEDS      = "ioc_feeds"
    PLAYBOOKS      = "playbooks"
    THREAT_REPORTS = "threat_reports"
    INTERNAL       = "internal"

@dataclass
class KnowledgeDocument:
    doc_id:      str
    source:      KnowledgeSource
    title:       str
    content:     str
    metadata:    Dict[str, Any] = field(default_factory=dict)
    embedding:   Optional[List[float]] = None
    trust_score: float = 0.9       # 0-1
    freshness:   float = 1.0       # 1.0 = current, decays over time
    created_at:  float = field(default_factory=time.time)
    updated_at:  float = field(default_factory=time.time)

    def __post_init__(self):
        if not self.doc_id:
            self.doc_id = hashlib.sha256(
                f"{self.source}:{self.title}:{self.content[:100]}".encode()
            ).hexdigest()[:16]

    @property
    def relevance_weight(self) -> float:
        return self.trust_score * self.freshness

class KnowledgeBase:
    """
    Manages the unified cybersecurity knowledge corpus.
    All agent queries go through this class for consistent, attributed retrieval.
    """

    QDRANT_COLLECTION = "cdb_knowledge"
    EMBEDDING_DIM     = 1536  # OpenAI/CF ada-002 compatible

    def __init__(
        self,
        qdrant_client:   Any = None,
        pg_pool:         Any = None,
        embedding_model: Any = None,
    ):
        self.qdrant    = qdrant_client
        self.db        = pg_pool
        self.embedder  = embedding_model
        self._local_cache: Dict[str, KnowledgeDocument] = {}

    async def initialize(self) -> None:
        """Create Qdrant collection and seed initial knowledge if empty."""
        if not self.qdrant:
            logger.warning("knowledge_base.qdrant_unavailable")
            return

        try:
            from qdrant_client.models import Distance, VectorParams
            collections = await self.qdrant.get_collections()
            names = [c.name for c in collections.collections]
            if self.QDRANT_COLLECTION not in names:
                await self.qdrant.create_collection(
                    collection_name=self.QDRANT_COLLECTION,
                    vectors_config=VectorParams(size=self.EMBEDDING_DIM, distance=Distance.COSINE),
                )
                logger.info("knowledge_base.collection_created", name=self.QDRANT_COLLECTION)
                await self._seed_static_knowledge()
        except Exception as e:
            logger.error("knowledge_base.init_error", error=str(e))

    async def search(
        self,
        query:       str,
        sources:     Optional[List[KnowledgeSource]] = None,
        top_k:       int = 5,
        min_score:   float = 0.6,
    ) -> List[Dict[str, Any]]:
        """
        Semantic search across the knowledge base.
        Returns ranked results with source attribution and trust/freshness scores.
        """
        if not self.qdrant or not self.embedder:
            return self._local_search(query, sources, top_k)

        try:
            embedding = await self._embed(query)
            filter_   = self._build_filter(sources) if sources else None

            results = await self.qdrant.search(
                collection_name=self.QDRANT_COLLECTION,
                query_vector=embedding,
                query_filter=filter_,
                limit=top_k,
                score_threshold=min_score,
                with_payload=True,
            )

            return [
                {
                    "doc_id":      r.id,
                    "title":       r.payload.get("title", ""),
                    "content":     r.payload.get("content", ""),
                    "source":      r.payload.get("source", ""),
                    "score":       r.score,
                    "trust_score": r.payload.get("trust_score", 0.9),
                    "freshness":   r.payload.get("freshness", 1.0),
                    "metadata":    r.payload.get("metadata", {}),
                    "relevance":   r.score * r.payload.get("trust_score", 0.9),
                }
                for r in results
            ]
        except Exception as e:
            logger.error("knowledge_base.search_error", error=str(e))
            return self._local_search(query, sources, top_k)

    async def add_document(self, doc: KnowledgeDocument) -> bool:
        """Add or update a document in the knowledge base."""
        self._local_cache[doc.doc_id] = doc

        if not self.qdrant or not self.embedder:
            return True

        try:
            embedding = await self._embed(doc.content[:4000])  # Truncate for embedding
            from qdrant_client.models import PointStruct
            await self.qdrant.upsert(
                collection_name=self.QDRANT_COLLECTION,
                points=[PointStruct(
                    id=int(hashlib.sha256(doc.doc_id.encode()).hexdigest()[:8], 16),
                    vector=embedding,
                    payload={
                        "doc_id":      doc.doc_id,
                        "title":       doc.title,
                        "content":     doc.content[:8000],
                        "source":      doc.source.value,
                        "trust_score": doc.trust_score,
                        "freshness":   doc.freshness,
                        "metadata":    doc.metadata,
                        "updated_at":  doc.updated_at,
                    }
                )]
            )
            return True
        except Exception as e:
            logger.error("knowledge_base.add_document_error", error=str(e))
            return False

    async def _embed(self, text: str) -> List[float]:
        """Generate embedding using configured embedding model."""
        if self.embedder:
            return await self.embedder.embed(text)
        # Fallback: zero vector (will still work, just no semantic search)
        return [0.0] * self.EMBEDDING_DIM

    def _local_search(
        self, query: str, sources: Optional[List[KnowledgeSource]], top_k: int
    ) -> List[Dict[str, Any]]:
        """Simple keyword search over local cache when Qdrant unavailable."""
        query_lower = query.lower()
        results = []
        for doc in self._local_cache.values():
            if sources and doc.source not in sources:
                continue
            if (query_lower in doc.content.lower() or
                    query_lower in doc.title.lower()):
                results.append({
                    "doc_id": doc.doc_id, "title": doc.title,
                    "content": doc.content[:500], "source": doc.source.value,
                    "score": 0.7, "trust_score": doc.trust_score, "freshness": doc.freshness,
                    "metadata": doc.metadata, "relevance": 0.7 * doc.trust_score,
                })
        return sorted(results, key=lambda x: x["relevance"], reverse=True)[:top_k]

    def _build_filter(self, sources: List[KnowledgeSource]) -> Dict:
        from qdrant_client.models import Filter, FieldCondition, MatchAny
        return Filter(must=[
            FieldCondition(key="source", match=MatchAny(any=[s.value for s in sources]))
        ])

    async def _seed_static_knowledge(self) -> None:
        """Seed initial static knowledge entries."""
        static_docs = [
            KnowledgeDocument(
                doc_id="mitre-ta0001", source=KnowledgeSource.MITRE_ATTACK,
                title="MITRE ATT&CK: Initial Access (TA0001)",
                content="Initial Access consists of techniques that use various entry vectors to gain their initial foothold within a network. Techniques used to gain a foothold include targeted spearphishing and exploiting weaknesses on public-facing web servers. Key techniques: T1566 Phishing, T1078 Valid Accounts, T1190 Exploit Public-Facing Application, T1195 Supply Chain Compromise.",
                metadata={"tactic": "TA0001", "framework": "ATT&CK v14"},
                trust_score=1.0,
            ),
            KnowledgeDocument(
                doc_id="owasp-llm01", source=KnowledgeSource.OWASP_LLM,
                title="OWASP LLM01: Prompt Injection",
                content="Prompt Injection occurs when an attacker manipulates a large language model (LLM) through crafted inputs, causing the LLM to unknowingly execute the attacker's intentions. This can be done directly by 'jailbreaking' the system prompt or indirectly via manipulated external content. Mitigations: privilege control, human oversight, input/output filtering.",
                metadata={"category": "LLM01", "framework": "OWASP LLM Top 10"},
                trust_score=1.0,
            ),
            KnowledgeDocument(
                doc_id="nist-csf-pr", source=KnowledgeSource.NIST_CSF,
                title="NIST CSF 2.0: Protect Function",
                content="The Protect function supports the ability to limit or contain the impact of a cybersecurity event. Categories: Identity Management, Authentication, Access Control; Awareness and Training; Data Security; Platform Security; Technology Infrastructure Resilience.",
                metadata={"function": "Protect", "framework": "NIST CSF 2.0"},
                trust_score=1.0,
            ),
        ]
        for doc in static_docs:
            await self.add_document(doc)
        logger.info("knowledge_base.seeded", count=len(static_docs))
