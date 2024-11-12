"""Rule generator for security tools.

This module generates actionable security rules based on analysis results:
- Suricata rules for network-based detection
- ClamAV signatures for malware detection
- iptables rules for network blocking
"""

from typing import Dict, Any, Set
from pathlib import Path
import json
import logging
from datetime import datetime

from ...features.models.models import SecurityReport, ConsolidatedReport

logger = logging.getLogger(__name__)


class RuleGenerator:
    """Generate security rules from analysis results."""

    def __init__(self, reports_dir: Path):
        """Initialize rule generator.

        Args:
            reports_dir: Path to directory for saving rules
        """
        self.reports_dir = reports_dir
        self.rules_dir = reports_dir / "rules"
        self.rules_dir.mkdir(exist_ok=True)

    def _extract_malware_info(self, anomaly: Dict[str, Any]) -> Dict[str, str]:
        """Extract malware information from anomaly details."""
        malware_info = {}
        if "raw_log" in anomaly:
            # Extract malware type from ClamAV log
            if "signature" in anomaly:
                malware_info["type"] = anomaly["signature"]
            # Extract source IP
            if "source_ip" in anomaly:
                malware_info["source_ip"] = anomaly["source_ip"]
            # Extract file type if present
            if "file_type" in anomaly:
                malware_info["file_type"] = anomaly["file_type"]
        return malware_info

    def _generate_suricata_rule(self, anomaly: Dict[str, Any], rule_id: int) -> str:
        """Generate a Suricata rule from detected malware."""
        malware_info = self._extract_malware_info(anomaly)
        if not malware_info:
            return ""

        # Create specific rule based on malware type and source
        rule = (
            f"alert {anomaly.get('protocol', 'tcp')} "
            f"{malware_info.get('source_ip', 'any')} "
            f"{anomaly.get('port', 'any')} -> $HOME_NET any "
            f'(msg:"ET MALWARE {malware_info.get("type", "Unknown")} Activity"; '
            f'flow:established,to_server; '
            f'classtype:trojan-activity; '
            f'threshold:type limit,track by_src,seconds 60,count 1; '
            f'sid:{rule_id}; rev:1;)'
        )
        return rule

    def _generate_clamav_signature(self, anomaly: Dict[str, Any]) -> str:
        """Generate a ClamAV signature from detected malware."""
        malware_info = self._extract_malware_info(anomaly)
        if not malware_info:
            return ""

        # Create specific signature based on malware type and file type
        malware_type = malware_info.get("type", "Unknown").replace(".", "_")
        file_type = malware_info.get("file_type", "*")

        # Format: SignatureName:TargetType:Offset:Signature
        sig_name = f"Cortex.Malware.{malware_type}"
        if file_type != "*":
            sig_name += f".{file_type}"

        # Add specific detection patterns based on malware type
        if "Phishing" in malware_type:
            return f"{sig_name}:0:*:HTML.Phishing.Page"
        elif "Trojan" in malware_type:
            return f"{sig_name}:1:*:MZ.{malware_type}.Payload"
        elif "Encrypted" in malware_type:
            return f"{sig_name}:0:*:Encrypted.Container"
        else:
            return f"{sig_name}:0:*:Malicious.Content"

    def _generate_iptables_rule(self, anomaly: Dict[str, Any]) -> str:
        """Generate an iptables rule from detected malware source."""
        malware_info = self._extract_malware_info(anomaly)
        if not malware_info or "source_ip" not in malware_info:
            return ""

        # Create specific rule based on severity and malware type
        source_ip = malware_info["source_ip"]
        if anomaly["severity"] >= 4:  # High severity - block all traffic
            return f"iptables -A INPUT -s {source_ip} -j DROP"
        else:  # Lower severity - log and limit rate
            return (
                f"iptables -A INPUT -s {source_ip} -m limit --limit 5/min -j LOG --log-prefix 'Malicious IP: '\n"
                f"iptables -A INPUT -s {source_ip} -m limit --limit 5/min -j DROP"
            )

    def generate_rules(self, report: SecurityReport | ConsolidatedReport, timestamp: str) -> None:
        """Generate security rules from a report."""
        # Track unique source IPs and malware types
        source_ips: Set[str] = set()
        malware_types: Set[str] = set()

        # Generate Suricata rules
        suricata_rules = []
        rule_id = 1000000  # Starting SID for custom rules

        for anomaly in report.anomalies:
            # Convert Anomaly model to dict for processing
            anomaly_dict = anomaly.model_dump()

            malware_info = self._extract_malware_info(anomaly_dict)
            if malware_info:
                if "source_ip" in malware_info:
                    source_ips.add(malware_info["source_ip"])
                if "type" in malware_info:
                    malware_types.add(malware_info["type"])

                rule = self._generate_suricata_rule(anomaly_dict, rule_id)
                if rule:
                    suricata_rules.append(rule)
                    rule_id += 1

        if suricata_rules:
            suricata_path = self.rules_dir / f"suricata_rules_{timestamp}.rules"
            with open(suricata_path, "w") as f:
                f.write("# Suricata rules generated from security analysis\n")
                f.write(f"# Generated at: {datetime.now().isoformat()}\n")
                f.write("# These rules detect malware activity based on observed patterns\n\n")
                f.write("\n".join(suricata_rules))
            logger.info(f"Suricata rules saved to {suricata_path}")

        # Generate ClamAV signatures
        clamav_sigs = []
        for anomaly in report.anomalies:
            sig = self._generate_clamav_signature(anomaly.model_dump())
            if sig:
                clamav_sigs.append(sig)

        if clamav_sigs:
            clamav_path = self.rules_dir / f"clamav_signatures_{timestamp}.ndb"
            with open(clamav_path, "w") as f:
                f.write("# ClamAV signatures generated from security analysis\n")
                f.write(f"# Generated at: {datetime.now().isoformat()}\n")
                f.write("# These signatures detect malware based on observed patterns\n\n")
                f.write("\n".join(clamav_sigs))
            logger.info(f"ClamAV signatures saved to {clamav_path}")

        # Generate iptables rules
        iptables_rules = []
        for anomaly in report.anomalies:
            rule = self._generate_iptables_rule(anomaly.model_dump())
            if rule:
                iptables_rules.append(rule)

        if iptables_rules:
            iptables_path = self.rules_dir / f"iptables_rules_{timestamp}.sh"
            with open(iptables_path, "w") as f:
                f.write("#!/bin/bash\n\n")
                f.write("# Generated by Cortex Security Analysis\n")
                f.write(f"# Generated at: {datetime.now().isoformat()}\n")
                f.write("# These rules block malicious IPs based on observed attacks\n\n")
                f.write("# Flush existing rules\n")
                f.write("iptables -F\n\n")
                f.write("# Set default policies\n")
                f.write("iptables -P INPUT DROP\n")
                f.write("iptables -P FORWARD DROP\n")
                f.write("iptables -P OUTPUT ACCEPT\n\n")
                f.write("# Allow established connections\n")
                f.write("iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT\n\n")
                f.write("# Allow local traffic\n")
                f.write("iptables -A INPUT -i lo -j ACCEPT\n\n")
                f.write("# Block malicious IPs\n")
                f.write("\n".join(iptables_rules))
            iptables_path.chmod(0o755)  # Make executable
            logger.info(f"iptables rules saved to {iptables_path}")

        # Create detailed summary of detected threats
        summary = {
            "analysis_period": {
                "start": report.summary["analysis_timestamp"],
                "end": datetime.now().isoformat(),
            },
            "threat_summary": {
                "total_malicious_ips": len(source_ips),
                "malicious_ips": list(source_ips),
                "malware_types": list(malware_types),
                "severity_distribution": {},
                "blocked_traffic": {
                    "suricata_rules": len(suricata_rules),
                    "clamav_signatures": len(clamav_sigs),
                    "iptables_blocks": len(iptables_rules),
                },
            },
            "risk_assessment": {
                "risk_level": report.risk_assessment.risk_level,
                "risk_score": report.risk_assessment.risk_score,
                "risk_factors": report.risk_assessment.risk_factors,
            },
            "recommendations": [
                {
                    "title": "Network Detection",
                    "priority": "HIGH",
                    "action": "Deploy generated Suricata rules",
                    "details": {
                        "rules_count": len(suricata_rules),
                        "coverage": list(malware_types),
                    },
                    "steps": [
                        "Install rules in Suricata configuration",
                        "Enable real-time alerting",
                        "Monitor rule effectiveness",
                    ],
                },
                {
                    "title": "Malware Prevention",
                    "priority": "HIGH",
                    "action": "Update ClamAV signatures",
                    "details": {
                        "signatures_count": len(clamav_sigs),
                        "malware_types": list(malware_types),
                    },
                    "steps": [
                        "Add signatures to ClamAV database",
                        "Run full system scan",
                        "Enable real-time protection",
                    ],
                },
                {
                    "title": "Network Blocking",
                    "priority": "HIGH",
                    "action": "Apply iptables rules",
                    "details": {"blocked_ips": len(source_ips), "rule_count": len(iptables_rules)},
                    "steps": [
                        "Review and test rules",
                        "Apply rules to production",
                        "Monitor for false positives",
                    ],
                },
                {
                    "title": "Ongoing Monitoring",
                    "priority": "MEDIUM",
                    "action": "Enhance security monitoring",
                    "details": {"focus_areas": ["Network traffic", "System logs", "File activity"]},
                    "steps": [
                        "Configure log aggregation",
                        "Set up alerts for anomalies",
                        "Review security dashboards",
                    ],
                },
            ],
        }

        # Count severity distribution
        for anomaly in report.anomalies:
            severity = str(anomaly.severity)
            if severity in summary["threat_summary"]["severity_distribution"]:
                summary["threat_summary"]["severity_distribution"][severity] += 1
            else:
                summary["threat_summary"]["severity_distribution"][severity] = 1

        summary_path = self.rules_dir / "rules_summary.json"
        with open(summary_path, "w") as f:
            json.dump(summary, f, indent=2)
        logger.info(f"Rules summary saved to {summary_path}")

    def generate_consolidated_rules(self, report: ConsolidatedReport) -> None:
        """Generate consolidated security rules from final report."""
        timestamp = datetime.now().strftime("%Y-%m-%dT%H-%M-%S")
        self.generate_rules(report, f"final_{timestamp}")
