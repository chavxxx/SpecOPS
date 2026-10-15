"""
Reputation Status and Explainable Scoring Engine
WISP Network & Data Solutions (WISPnet)
"""
from typing import List, Tuple, Dict, Any
from app.models.ip_intel_schemas import (
    ProviderResult,
    ReputationStatus,
    ListingCategory,
    ScoreFactor
)

class ReputationScoringEngine:
    """Evaluates provider results to derive an explainable status classification and numerical score"""

    @classmethod
    def evaluate(
        cls,
        results: List[ProviderResult]
    ) -> Tuple[ReputationStatus, float, List[ScoreFactor], str]:
        """
        Evaluates a collection of ProviderResult items.
        Returns (overall_status, overall_score, score_factors, explanation).
        """
        if not results:
            return ReputationStatus.UNKNOWN, 0.0, [], "No reputation providers were queried."

        completed_results = [r for r in results if r.lookup_status == "completed"]
        failed_results = [r for r in results if r.lookup_status in ("failed", "timeout", "blocked")]
        unsupported_results = [r for r in results if r.lookup_status == "unsupported"]
        listed_results = [r for r in completed_results if r.is_listed]

        score_factors: List[ScoreFactor] = []
        raw_score = 0.0

        # Group listed results by independent evidence categories to avoid double-counting
        # E.g. Multiple DNSBLs (Spamhaus, SpamCop, Barracuda)
        dnsbl_listings = [r for r in listed_results if r.provider_type.value == "dnsbl"]
        abuse_listings = [r for r in listed_results if r.provider_type.value == "abuse_api"]
        threat_listings = [r for r in listed_results if r.provider_type.value == "threat_intel"]
        email_listings = [r for r in listed_results if r.provider_type.value == "email_reputation"]

        has_severe_finding = False

        # 1. DNSBL listings
        for r in dnsbl_listings:
            if r.listing_category == ListingCategory.BOTNET_C2:
                weight = 40.0
                has_severe_finding = True
            elif r.listing_category == ListingCategory.DELIVERABILITY:
                weight = 15.0
            else:
                weight = 25.0
            raw_score += weight
            score_factors.append(ScoreFactor(
                factor=f"{r.provider_name} Listing",
                weight=weight,
                evidence=r.evidence_summary
            ))

        # 2. Abuse API (AbuseIPDB)
        for r in abuse_listings:
            conf_score = r.source_score or 0.0
            weight = round(conf_score * 0.4, 1)  # Scale up to 40 max
            if conf_score >= 80:
                has_severe_finding = True
            if weight > 0:
                raw_score += weight
                score_factors.append(ScoreFactor(
                    factor=f"{r.provider_name} Abuse Confidence ({conf_score}%)",
                    weight=weight,
                    evidence=r.evidence_summary
                ))

        # 3. Threat Intel (VirusTotal / GreyNoise)
        for r in threat_listings:
            vt_score = r.source_score or 0.0
            if r.risk_status == ReputationStatus.HIGH_RISK:
                has_severe_finding = True
                weight = 35.0
            elif r.risk_status == ReputationStatus.SUSPICIOUS:
                weight = 20.0
            else:
                weight = 0.0
            if weight > 0:
                raw_score += weight
                score_factors.append(ScoreFactor(
                    factor=f"{r.provider_name} Threat Telemetry",
                    weight=weight,
                    evidence=r.evidence_summary
                ))

        # 4. Email Deliverability (Missing PTR / FCrDNS)
        for r in email_listings:
            if r.is_listed:
                weight = 15.0
                raw_score += weight
                score_factors.append(ScoreFactor(
                    factor=f"{r.provider_name} Deliverability Defect",
                    weight=weight,
                    evidence=r.evidence_summary
                ))

        # Clamp numerical score to [0.0, 100.0]
        final_score = min(max(round(raw_score, 1), 0.0), 100.0)

        # 5. Status Classification Logic
        # Case A: Severe findings or multiple independent high listings -> HIGH_RISK
        if has_severe_finding or len(dnsbl_listings) >= 2 or final_score >= 70.0:
            status = ReputationStatus.HIGH_RISK
            explanation = f"High Risk: Detected severe threat indicators or multiple verified listings ({len(listed_results)} active findings)."
            if failed_results:
                explanation += f" (Note: {len(failed_results)} checks could not be completed)."
            return status, final_score, score_factors, explanation

        # Case B: At least one verified active listing -> LISTED
        if listed_results:
            status = ReputationStatus.LISTED
            explanation = f"Listed: Verified active listing detected across {len(listed_results)} source(s)."
            if failed_results:
                explanation += f" (Note: {len(failed_results)} checks could not be completed)."
            return status, final_score, score_factors, explanation

        # Case C: Suspicious score or deliverability warning without hard listing -> SUSPICIOUS
        if final_score >= 25.0:
            status = ReputationStatus.SUSPICIOUS
            explanation = f"Suspicious: Elevated risk signals observed (Score: {final_score}/100)."
            return status, final_score, score_factors, explanation

        # Case D: Failed checks without any positive findings -> INCOMPLETE
        if failed_results:
            status = ReputationStatus.INCOMPLETE
            explanation = f"Incomplete: {len(failed_results)} required provider checks failed or timed out. Completed checks ({len(completed_results)}) showed no active listings."
            return status, final_score, score_factors, explanation

        # Case E: Only unsupported / unconfigured providers -> UNKNOWN
        if not completed_results:
            status = ReputationStatus.UNKNOWN
            explanation = "Unknown: Insufficient evidence available. Configured providers require valid API credentials."
            return status, 0.0, score_factors, explanation

        # Case F: All completed checks clean with zero listings -> CLEAN
        status = ReputationStatus.CLEAN
        explanation = f"Clean: All {len(completed_results)} configured checks completed successfully with zero active listings or threat indicators."
        return status, 0.0, score_factors, explanation
