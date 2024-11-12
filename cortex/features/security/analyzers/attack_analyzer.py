"""Attack analyzer for security events."""

from typing import Dict, Any, Optional
from cortex.features.models.security import AttackCategory


class AttackAnalyzer:
    """Analyzes and categorizes security attacks."""

    @staticmethod
    def categorize_attack(event: Dict[str, Any]) -> Optional[str]:
        """Categorize the type of attack based on event characteristics."""
        # Extract signature and category with fallbacks
        signature = ""
        category = ""

        if "alert" in event:
            alert = event["alert"]
            signature = alert.get("signature", "").lower()
            category = alert.get("category", "").lower()
        else:
            # Try alternate fields for non-alert events
            signature = event.get("signature", "").lower()
            category = event.get("category", "").lower()
            if not signature and not category:
                signature = event.get("event_type", "").lower()

        # SQL Injection detection
        if any(x in signature for x in ["sql", "union", "select", "drop table"]):
            return AttackCategory.SQL_INJECTION

        # DDoS detection
        if "ddos" in signature or "dos" in category or "flood" in signature:
            return AttackCategory.DDOS

        # Port scan detection
        if "scan" in signature or "port scan" in category or "portscan" in signature:
            return AttackCategory.PORT_SCAN

        # Brute force detection
        if any(x in signature for x in ["brute force", "bruteforce", "authentication failure"]):
            return AttackCategory.BRUTE_FORCE

        # Protocol abuse detection
        if "protocol abuse" in signature or "protocol-command-decode" in category:
            return AttackCategory.PROTOCOL_ABUSE

        # Reconnaissance detection
        if "recon" in category or "attempted-recon" in category or "probe" in signature:
            return AttackCategory.RECONNAISSANCE

        # Malware detection
        if any(
            x in signature.lower() for x in ["malware", "trojan", "virus", "ransomware", "backdoor"]
        ):
            return AttackCategory.MALWARE

        return AttackCategory.UNKNOWN

    @staticmethod
    def extract_attack_details(event: Dict[str, Any]) -> Dict[str, Any]:
        """Extract detailed information about the attack."""
        details = {}

        # Extract alert details if present
        if "alert" in event:
            alert = event["alert"]
            details.update(
                {
                    "signature": alert.get("signature"),
                    "signature_id": alert.get("signature_id"),
                    "category": alert.get("category"),
                    "severity": alert.get("severity"),
                }
            )
        else:
            # Extract from top-level event for non-alert events
            details.update(
                {
                    "signature": event.get("signature"),
                    "category": event.get("category"),
                    "severity": event.get("severity"),
                }
            )

        # Extract authentication details
        if "auth" in event:
            auth = event["auth"]
            details.update(
                {
                    "auth_attempts": auth.get("attempts"),
                    "auth_service": auth.get("service"),
                    "auth_timeframe": auth.get("timeframe"),
                    "username_pattern": auth.get("username_pattern"),
                }
            )

        # Extract HTTP details
        if "http" in event:
            http = event["http"]
            details.update(
                {
                    "http_method": http.get("http_method"),
                    "url": http.get("url"),
                    "status": http.get("status"),
                }
            )

        # Extract port scan details
        if "port_scan" in event:
            port_scan = event["port_scan"]
            details.update(
                {
                    "scanned_ports": port_scan.get("ports"),
                    "scan_type": port_scan.get("scan_type"),
                }
            )

        # Extract protocol details
        if "protocol_info" in event:
            protocol = event["protocol_info"]
            details.update(
                {
                    "violation_type": protocol.get("violation_type"),
                    "packet_size": protocol.get("packet_size"),
                    "flags": protocol.get("flags"),
                }
            )

        # Extract geographic anomaly details
        if "geo_context" in event:
            geo = event["geo_context"]
            details.update(
                {
                    "unusual_route": geo.get("unusual_route"),
                    "risk_level": geo.get("risk_level"),
                    "region_risk_score": geo.get("region_risk_score"),
                }
            )

        # Extract anomaly details
        if "anomaly" in event:
            anomaly = event["anomaly"]
            details.update(
                {
                    "anomaly_type": anomaly.get("type"),
                    "baseline_value": anomaly.get("baseline_value"),
                    "current_value": anomaly.get("current_value"),
                    "deviation_factor": anomaly.get("deviation_factor"),
                }
            )

        # Add basic event details
        details.update(
            {
                "timestamp": event.get("timestamp"),
                "source_ip": event.get("source_ip"),
                "destination_ip": event.get("destination_ip"),
                "protocol": event.get("protocol"),
                "event_type": event.get("event_type"),
            }
        )

        # Remove None values
        return {k: v for k, v in details.items() if v is not None}

    @staticmethod
    def determine_tactics(category: str, details: Dict[str, Any]) -> list[str]:
        """Determine attack tactics based on category and details."""
        tactics = []

        if category == AttackCategory.SQL_INJECTION:
            tactics.extend(["Initial Access", "Credential Access", "Data Manipulation"])
        elif category == AttackCategory.DDOS:
            tactics.extend(["Impact", "Resource Exhaustion"])
        elif category == AttackCategory.PORT_SCAN:
            tactics.extend(["Discovery", "Reconnaissance"])
        elif category == AttackCategory.BRUTE_FORCE:
            tactics.extend(["Credential Access", "Initial Access"])
        elif category == AttackCategory.PROTOCOL_ABUSE:
            tactics.extend(["Defense Evasion", "Command and Control"])
        elif category == AttackCategory.MALWARE:
            tactics.extend(["Execution", "Persistence", "Defense Evasion"])

        return tactics

    @staticmethod
    def determine_techniques(category: str, details: Dict[str, Any]) -> list[str]:
        """Determine attack techniques based on category and details."""
        techniques = []

        signature = str(details.get("signature", ""))

        if category == AttackCategory.SQL_INJECTION:
            if "UNION" in signature:
                techniques.append("UNION-based Injection")
            elif "DROP" in signature:
                techniques.append("Schema Manipulation")
            else:
                techniques.append("SQL Injection")

        elif category == AttackCategory.PORT_SCAN:
            scan_type = details.get("scan_type", "").upper()
            if scan_type:
                techniques.append(f"{scan_type} Scan")
            else:
                techniques.append("Port Scanning")

        elif category == AttackCategory.BRUTE_FORCE:
            service = details.get("auth_service", "").upper()
            if service:
                techniques.append(f"{service} Brute Force")
            else:
                techniques.append("Password Brute Force")

        elif category == AttackCategory.PROTOCOL_ABUSE:
            violation = details.get("violation_type", "")
            if violation:
                techniques.append(f"Protocol {violation.replace('_', ' ').title()}")
            else:
                techniques.append("Protocol Abuse")

        elif category == AttackCategory.MALWARE:
            if "trojan" in signature.lower():
                techniques.append("Trojan")
            elif "ransomware" in signature.lower():
                techniques.append("Ransomware")
            elif "backdoor" in signature.lower():
                techniques.append("Backdoor")
            else:
                techniques.append("Malware")

        return techniques
