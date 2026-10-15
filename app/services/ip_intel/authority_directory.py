"""
Authoritative Global Blocklist & Anti-Cheat Directory
Contains official delisting portals, removal procedures, contact protocols,
and tailored appeal templates for major reputation authorities.
WISP Network & Data Solutions (WISPnet)
"""
from typing import Dict, Any, List, Optional
import urllib.parse

AUTHORITY_CATALOG: Dict[str, Dict[str, Any]] = {
    "spamhaus_zen": {
        "authority_id": "spamhaus_zen",
        "name": "The Spamhaus Project (ZEN / SBL / XBL / PBL)",
        "organization": "The Spamhaus Project",
        "category": "Global Email DNSBL Authority",
        "dns_zone": "zen.spamhaus.org",
        "impact": "Blocks outbound email to Gmail, Yahoo, Microsoft 365, and major corporate MTAs worldwide.",
        "portal_url": "https://check.spamhaus.org/query/ip/{ip}",
        "email_contact": "https://check.spamhaus.org/contact/",
        "removal_sla": "Automated self-service: 15–30 minutes after submission.",
        "requirements": [
            "Confirm that the abusive host or malware has been disconnected or secured.",
            "Verify that outbound SMTP (TCP port 25) from end-user dynamic ranges is filtered on ISP routers.",
            "For PBL (Policy Block List): ISP network operators must register dynamic IP ranges or verify static mail server allocation."
        ],
        "default_appeal": (
            "Dear Spamhaus Removals Team,\n\n"
            "We are writing on behalf of WISPnet Solutions (NOC / Network Operations) regarding public IP address {ip}.\n\n"
            "Action Taken:\n"
            "1. The subscriber connection associated with this IP has been quarantined and remediated.\n"
            "2. Outbound port 25 (SMTP) traffic from customer subnets has been strictly blocked on our core edge routers.\n"
            "3. Live traffic captures now confirm zero spam or malicious traffic originating from this host.\n\n"
            "We respectfully request the delisting of {ip} from your blocklist. Thank you for your assistance.\n\n"
            "Sincerely,\n"
            "WISPnet Network Operations Center (NOC)\n"
            "noc@wispnet.ph"
        )
    },
    "barracuda": {
        "authority_id": "barracuda",
        "name": "Barracuda Central (BRBL)",
        "organization": "Barracuda Networks",
        "category": "Corporate Email Security Authority",
        "dns_zone": "b.barracudacentral.org",
        "impact": "Causes email rejections at organizations and enterprises protected by Barracuda Spam Firewalls.",
        "portal_url": "https://www.barracudacentral.org/rbl/removal-request",
        "email_contact": "rbl@barracuda.com",
        "removal_sla": "Automated review queue: 12–24 hours.",
        "requirements": [
            "Provide a valid ISP contact email address.",
            "State that the cause of spam/abuse has been corrected and verified clean.",
            "Wait 24 hours after applying firewall filtering before submitting."
        ],
        "default_appeal": (
            "Dear Barracuda Central Removals,\n\n"
            "We are requesting the removal of IP address {ip} from the Barracuda Reputation Block List (BRBL).\n\n"
            "Root-Cause Resolution:\n"
            "- The customer premise equipment (CPE) has been sanitized and isolated.\n"
            "- Firewall egress filtering has been enforced at our ISP gateway.\n"
            "- Ongoing monitoring shows normal benign traffic with zero unauthorized relay.\n\n"
            "Please process the delisting of {ip}. Thank you.\n\n"
            "Network Operations Center\n"
            "WISPnet Solutions\n"
            "noc@wispnet.ph"
        )
    },
    "spamcop": {
        "authority_id": "spamcop",
        "name": "SpamCop Blocking List (SCBL)",
        "organization": "SpamCop / Cisco Systems",
        "category": "Real-Time Spam Trap Authority",
        "dns_zone": "bl.spamcop.net",
        "impact": "Triggers temporary 550 reject bounces on mail systems using SpamCop DNSBL feeds.",
        "portal_url": "https://www.spamcop.net/w3m?action=checkblock&ip={ip}",
        "email_contact": "deputies@admin.spamcop.net",
        "removal_sla": "Automatic self-decay: Automatically delisted 24–48 hours after abusive traffic ceases.",
        "requirements": [
            "SpamCop is fully automated; manual delisting requests are not processed.",
            "Stop all outgoing port 25 traffic from the IP; the listing will expire automatically within 24 to 48 hours."
        ],
        "default_appeal": (
            "SpamCop delisting is automated by Cisco SpamCop. Once outbound spam is blocked at the core router, "
            "the IP will automatically expire from the SCBL within 24–48 hours without requiring a manual ticket."
        )
    },
    "sorbs": {
        "authority_id": "sorbs",
        "name": "SORBS (Spam and Open Relay Blocking System)",
        "organization": "Proofpoint / SORBS",
        "category": "DNSBL & Dynamic Pool Authority",
        "dns_zone": "dnsbl.sorbs.net",
        "impact": "Blocks email delivery to networks utilizing Proofpoint/SORBS anti-spam databases.",
        "portal_url": "http://www.sorbs.net/delisting/overview.shtml",
        "email_contact": "support@sorbs.net",
        "removal_sla": "Web self-service: 24–48 hours.",
        "requirements": [
            "Login to SORBS ticketing portal (free account required).",
            "Verify whether the listing is in DUHL (Dynamic/Generic IP) or SPAM/HTTP.",
            "If DUHL, confirm that the host is a static mail server or update reverse DNS."
        ],
        "default_appeal": (
            "Dear SORBS Administration,\n\n"
            "We request the delisting of {ip} from your database. We have identified and halted the anomalous traffic. "
            "Our ISP core firewalls enforce strict egress filtering and no open relays exist on this allocation.\n\n"
            "WISPnet NOC\n"
            "noc@wispnet.ph"
        )
    },
    "uceprotect": {
        "authority_id": "uceprotect",
        "name": "UCEPROTECT Network (Level 1 / 2)",
        "organization": "UCEPROTECT-Network",
        "category": "Automated DNSBL Network",
        "dns_zone": "dnsbl-1.uceprotect.net",
        "impact": "Rejects email delivery at mail servers subscribed to UCEPROTECT feeds.",
        "portal_url": "http://www.uceprotect.net/en/rblcheck.php?ipr={ip}",
        "email_contact": "http://www.uceprotect.net/",
        "removal_sla": "Automated decay: 7 days after the last spam emission, or instant manual payment.",
        "requirements": [
            "UCEPROTECT Level 1 listings automatically expire 7 days after the last spam packet was detected.",
            "Verify zero outbound port 25 traffic so the 7-day automatic decay timer counts down undisturbed."
        ],
        "default_appeal": (
            "UCEPROTECT Level 1 delisting is automated upon zero spam emissions for 7 days. "
            "Ensure outbound port 25 drop is active on {ip} so the timer clears the IP automatically."
        )
    },
    "abuseipdb": {
        "authority_id": "abuseipdb",
        "name": "AbuseIPDB Community Blacklist",
        "organization": "AbuseIPDB Project",
        "category": "Crowdsourced Threat Intelligence",
        "dns_zone": None,
        "impact": "Affects web application firewalls (WAF), fail2ban, SSH/API logins, and hosting providers.",
        "portal_url": "https://www.abuseipdb.com/check/{ip}",
        "email_contact": "support@abuseipdb.com",
        "removal_sla": "Reports decay over 30–90 days; disputes reviewed within 24–48 hours.",
        "requirements": [
            "Log in to AbuseIPDB as the authoritative network administrator or WHOIS contact.",
            "Review reporter comment history to verify reported attack port (SSH, FTP, HTTP, etc.).",
            "File dispute for false-positive reports on shared CGNAT pool IPs."
        ],
        "default_appeal": (
            "Dear AbuseIPDB Support,\n\n"
            "We are filing a false-positive / remediation review for IP address {ip}.\n\n"
            "Context:\n"
            "- {ip} is part of a carrier-grade NAT (CGNAT) subscriber pool operated by WISPnet Solutions.\n"
            "- The offending internal host has been identified and isolated.\n"
            "- We request the historical report score be recalculated as the malicious traffic has been fully eradicated.\n\n"
            "Regards,\n"
            "WISPnet Security Team"
        )
    },
    "cisco_talos": {
        "authority_id": "cisco_talos",
        "name": "Cisco Talos Intelligence Group",
        "organization": "Cisco Systems",
        "category": "Global Threat & Web Reputation Registry",
        "dns_zone": None,
        "impact": "Affects Cisco Secure Email (ESA), Cisco Umbrella, and corporate firewall reputations.",
        "portal_url": "https://talosintelligence.com/reputation_center/lookup?search={ip}",
        "email_contact": "https://talosintelligence.com/tickets",
        "removal_sla": "Ticket review: 1 to 3 business days.",
        "requirements": [
            "Submit an official reputation adjustment ticket on Cisco Talos portal.",
            "Provide evidence of FCrDNS (Forward-Confirmed Reverse DNS) and ISP ownership."
        ],
        "default_appeal": (
            "Dear Cisco Talos Reputation Team,\n\n"
            "We are requesting a reputation re-evaluation for IP address {ip}.\n"
            "The IP is an ISP-managed public address with verified forward and reverse DNS. "
            "Any historical volume anomalies have been investigated and closed. We request the IP reputation "
            "status be restored to 'Neutral' or 'Good'.\n\n"
            "WISPnet NOC\n"
            "noc@wispnet.ph"
        )
    },
    "microsoft_snds": {
        "authority_id": "microsoft_snds",
        "name": "Microsoft SmartScreen & SNDS (Outlook.com / Hotmail)",
        "organization": "Microsoft Corporation",
        "category": "Consumer Webmail Authority",
        "dns_zone": None,
        "impact": "Blocks all outgoing email to Outlook.com, Hotmail.com, Live.com, and MSN email addresses.",
        "portal_url": "https://olcsupport.office.com/",
        "email_contact": "https://olcsupport.office.com/",
        "removal_sla": "Sender Support ticket: 24–48 hours.",
        "requirements": [
            "Submit the official Sender Information for Outlook.com Delivery ticket.",
            "Require valid Reverse DNS (PTR) record matching the sending domain.",
            "Must have SPF and DKIM configured if sending email."
        ],
        "default_appeal": (
            "Dear Microsoft Outlook Sender Support,\n\n"
            "We are requesting deliverability mitigation for our ISP public IP: {ip}.\n"
            "This IP has verified reverse DNS and complies with RFC 8805. All outbound SMTP from non-mail servers "
            "is blocked on our edge routers. Please reset the SmartScreen filter for this IP.\n\n"
            "Thank you,\n"
            "WISPnet Postmaster Team"
        )
    },
    "google_safebrowsing": {
        "authority_id": "google_safebrowsing",
        "name": "Google Safe Browsing & Web Risk",
        "organization": "Google LLC",
        "category": "Browser & Endpoint Malware Protection",
        "dns_zone": None,
        "impact": "Displays red 'Deceptive site ahead' or malware warning in Google Chrome, Android, and Firefox.",
        "portal_url": "https://safebrowsing.google.com/safebrowsing/report_error/?hl=en",
        "email_contact": "https://search.google.com/search-console",
        "removal_sla": "Automated security review: 24–72 hours.",
        "requirements": [
            "Confirm that malware/phishing files or open redirects have been completely removed.",
            "Submit error report or verify ownership in Google Search Console."
        ],
        "default_appeal": (
            "Dear Google Safe Browsing Team,\n\n"
            "We are submitting a false positive / clean review request for {ip}.\n"
            "Our security team has thoroughly inspected all hosts on this IP. All malicious content "
            "and compromised scripts have been eradicated. The IP is safe for web visitors.\n\n"
            "WISPnet Solutions Security Team"
        )
    },
    "gaming_codm_garena": {
        "authority_id": "gaming_codm_garena",
        "name": "Garena Security & Anti-Cheat (CODM Garena SEA)",
        "organization": "Garena International",
        "category": "Online Gaming & Anti-Cheat Authority",
        "dns_zone": None,
        "impact": "Causes 'Connecting to server...' timeout, login failure, or false anti-cheat blocks in Call of Duty: Mobile.",
        "portal_url": "https://help.garena.sg/",
        "email_contact": "help@garena.sg",
        "removal_sla": "ISP Ticket Review: 1–3 business days.",
        "requirements": [
            "Provide evidence that the IP is an ISP residential subscriber subnet located in the Philippines/Southeast Asia.",
            "Publish RFC 8805 compliant Geofeed entry showing country code PH and city.",
            "Ensure Reverse DNS (PTR) record resolves to an ISP domain (not generic datacenter/VPN)."
        ],
        "default_appeal": (
            "Dear Garena Security & Technical Operations,\n\n"
            "We are writing on behalf of WISPnet Solutions, an authorized Wireless Internet Service Provider in the Philippines.\n\n"
            "We have observed that our subscriber pool IP {ip} is experiencing connection blocks or anti-cheat flags when accessing Garena Call of Duty: Mobile game servers.\n\n"
            "ISP Verification Details:\n"
            "- ISP Name: WISPnet Solutions\n"
            "- Country: Philippines (PH)\n"
            "- Subnet Classification: Fixed Wireless Residential / Subscriber CGNAT\n"
            "- RFC 8805 Geofeed: {ip}/32,PH,PH-00,Manila,WISPnet Solutions,Wireless ISP\n"
            "- Reverse DNS: dynamic-{ip_dash}.wispnet.ph\n\n"
            "This IP is used exclusively by genuine residential gamers and is not a commercial VPN or proxy service. "
            "We kindly request your security team to whitelist or update the reputation of this IP for Garena game services.\n\n"
            "Best regards,\n"
            "WISPnet Network Operations & Gaming Support\n"
            "noc@wispnet.ph"
        )
    },
    "gaming_codm_activision": {
        "authority_id": "gaming_codm_activision",
        "name": "Activision Security & Enforcement / Demonware (COD Global)",
        "organization": "Activision Publishing / Demonware",
        "category": "Online Gaming & Anti-Cheat Authority",
        "dns_zone": None,
        "impact": "Triggers 'Under Review' (Shadowban), 350ms ping matchmaking loops, or Activision anti-cheat IP blocks.",
        "portal_url": "https://support.activision.com/ban-appeal",
        "email_contact": "privacy@activision.com",
        "removal_sla": "Security review: 24–48 hours.",
        "requirements": [
            "Must be classified as residential or commercial ISP, not datacenter or anonymizing proxy.",
            "Must have valid Reverse DNS (PTR) record conforming to ISP residential naming.",
            "Ensure zero high-frequency credential stuffing or bot traffic from the IP."
        ],
        "default_appeal": (
            "Dear Activision Security & Enforcement Team,\n\n"
            "We are requesting a reputation check and IP unblock for {ip} regarding Call of Duty online multiplayer matchmaking.\n\n"
            "Network Attribution:\n"
            "- Provider: WISPnet Solutions (Philippines)\n"
            "- Usage: End-user residential broadband connection\n"
            "- PTR Record: dynamic-{ip_dash}.wispnet.ph\n"
            "- Geolocation: Metro Manila / Philippines (PH)\n\n"
            "This IP is a legitimate ISP residential subscriber address. Please unflag this IP in your Demonware anti-fraud registry.\n\n"
            "WISPnet NOC\n"
            "noc@wispnet.ph"
        )
    },
    "gaming_riot_vanguard": {
        "authority_id": "gaming_riot_vanguard",
        "name": "Riot Games Vanguard Anti-Cheat (Valorant)",
        "organization": "Riot Games",
        "category": "Online Gaming & Anti-Cheat Authority",
        "dns_zone": None,
        "impact": "Causes VAN 152 / VAN 68 errors, routing delays, or match connection drops in Valorant.",
        "portal_url": "https://support-valorant.riotgames.com/hc/en-us/requests/new",
        "email_contact": "support@riotgames.com",
        "removal_sla": "Player Support Ticket: 24–48 hours.",
        "requirements": [
            "Verify IP is not listed in malicious botnet registries (Spamhaus XBL / AbuseIPDB).",
            "Verify non-commercial ISP geolocation attribution."
        ],
        "default_appeal": (
            "Dear Riot Games Technical Support,\n\n"
            "We are submitting an ISP network inquiry regarding connectivity to Riot Vanguard and Valorant game servers from IP {ip}.\n"
            "The IP is an authentic subscriber address within our Philippine ISP network. "
            "All security checks confirm the IP is clean and free of abusive automated traffic. We request your team to ensure "
            "no routing or anti-cheat restrictions are applied to this allocation.\n\n"
            "WISPnet Engineering Team\n"
            "noc@wispnet.ph"
        )
    }
}

def get_authority_dossier(authority_id: str, ip: str) -> Optional[Dict[str, Any]]:
    """Generates a complete, tailored delisting dossier for a specific authority and IP"""
    auth = AUTHORITY_CATALOG.get(authority_id)
    if not auth:
        return None

    clean_ip = ip.strip()
    dash_ip = clean_ip.replace(".", "-")
    portal_url = auth["portal_url"].format(ip=urllib.parse.quote(clean_ip))
    
    appeal_text = auth.get("default_appeal", "")
    appeal_text = appeal_text.format(ip=clean_ip, ip_dash=dash_ip)

    return {
        "authority_id": auth["authority_id"],
        "name": auth["name"],
        "organization": auth["organization"],
        "category": auth["category"],
        "dns_zone": auth.get("dns_zone"),
        "impact": auth["impact"],
        "portal_url": portal_url,
        "email_contact": auth.get("email_contact"),
        "removal_sla": auth["removal_sla"],
        "requirements": auth["requirements"],
        "appeal_letter": appeal_text
    }

def get_all_authorities_dossier(ip: str) -> List[Dict[str, Any]]:
    """Returns delisting dossiers for all recognized reputation authorities tailored for this IP"""
    return [get_authority_dossier(auth_id, ip) for auth_id in AUTHORITY_CATALOG]
