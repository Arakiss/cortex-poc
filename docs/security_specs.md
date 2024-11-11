# Security Agents Specification for Cortex

## Overview
This document outlines the technical specifications for implementing security-focused agents within the Cortex system, specifically addressing threat detection, pattern analysis, and anomaly detection in network traffic. The system is designed to provide both historical pattern-based analysis and basic real-time anomaly detection capabilities.

## Use Cases

### UC1: Pattern-Based Threat Detection and Mitigation
Implementation of agents for analyzing security logs and generating mitigation rules, focusing on historical pattern analysis without real-time processing requirements.

#### Description
This use case focuses on the application's capability to periodically analyze multiple log sources (such as Suricata, iptables, and others), identify attack patterns and threats from different IP ranges across multiple countries and continents, and automatically generate rules to block these attacks.

#### Workflow

1. **Log Collection Phase**
   - Regular collection of logs from multiple sources (Suricata, iptables, etc.)
   - Logs can come from various locations and represent historical network access events and potential security incidents
   - Components Required:
     - **Log Collection Agent**
       - Purpose: Collect and normalize logs from multiple sources
       - Input Sources: Suricata, iptables
       - Output Format: Standardized JSON structure

2. **Preprocessing and Parsing**
   - Custom tool parses and normalizes logs
   - Extracts key fields: source IP, destination IP, ports, protocol type, connection time
   - Structures data in a homogeneous format (JSON) for subsequent analysis

3. **Pattern Analysis and Threat Detection**
   - Components Required:
     - **Pattern Analysis Agent**
       - Purpose: Analyze normalized logs for attack patterns
       - Features:
         - IP-based pattern recognition
         - Geographic location analysis (country and continent)
         - Attack frequency analysis
         - Protocol analysis
         - Port scan detection
         - Brute force attempt identification
         - Unusual traffic pattern recognition

4. **Rule Generation**
   - Components Required:
     - **Rule Generation Agent**
       - Purpose: Create security rules based on detected patterns
       - Output Types:
         - Suricata rules: Custom rules for temporary or permanent IP/range blocking
         - iptables rules: Connection limiting or blocking from suspicious IPs/ranges
       - Features:
         - Rule validation
         - Conflict detection
         - Priority assignment
         - Central rule repository management
         - Manual review option
         - Automatic implementation capability

5. **Reporting and Visualization**
   - Components Required:
     - **Reporting Agent**
       - Purpose: Generate comprehensive security reports
       - Output:
         - Attack pattern summaries
         - Geographic distribution
         - Rule effectiveness metrics
         - Dashboard visualization
         - Region-based event analysis
         - Attack type classification
         - Volume metrics

#### Objective
To effectively identify distributed attack patterns, providing an automated solution that doesn't require real-time analysis but enables preventive blocking with high precision.

### UC2: Network Traffic Anomaly Analysis
Implementation of agents for basic real-time traffic pattern analysis, complementing the pattern-based threat detection without requiring complex geopolitical trend analysis.

#### Description
This use case involves simple network traffic anomaly analysis, detecting unusual patterns in traffic volume or connection attempts from specific IPs within short time intervals.

#### Workflow

1. **Recent Log Collection and Storage**
   - Components Required:
     - **Traffic Monitor Agent**
       - Purpose: Monitor and analyze network traffic patterns
       - Features:
         - Connection frequency analysis
         - Traffic volume monitoring
         - IP-based behavior tracking
         - Short-interval log collection
         - Immediate parsing and normalization

2. **Traffic Pattern Anomaly Analysis**
   - Components Required:
     - **Anomaly Detection Agent**
       - Purpose: Identify unusual traffic patterns
       - Features:
         - Baseline pattern establishment
         - Deviation detection
         - Connection frequency monitoring
         - Volume spike identification
         - Simple rule-based analysis
         - Alert generation

3. **Alert Generation and Blocking Recommendations**
   - Automatic alert generation for significant anomalies
   - Temporary IP blocking recommendations
   - Security team notification system
   - Investigation support data

#### Objective
To add a basic predictive analysis layer enabling the security team to identify suspicious behavior and respond to unusual traffic patterns quickly, without requiring complex historical analysis.

## Technical Implementation

### Agent Structure
Each agent will implement the existing Agent protocol:

```python
class AgentProtocol(ABC):
    """Protocol definition that all agents must implement."""

    @abstractmethod
    def get_name(self) -> str:
        """Get the name of the agent."""
        pass

    @abstractmethod
    def get_role(self) -> str:
        """Describe the agent's role."""
        pass

    @abstractmethod
    def run(self):
        """Abstract method to run the agent's main functionality."""
        pass
```

### Data Models
New Pydantic models required for implementation:

```python
# Security Event Models
class SecurityEvent(BaseModel):
    timestamp: datetime
    source_ip: str
    destination_ip: str
    protocol: str
    event_type: str
    severity: int
    raw_log: str
    country_code: Optional[str]
    continent_code: Optional[str]
    connection_count: Optional[int]

class AttackPattern(BaseModel):
    pattern_id: str
    source_ips: List[str]
    geographic_data: Dict[str, Any]
    frequency: int
    attack_type: str
    confidence_score: float
    first_seen: datetime
    last_seen: datetime
    affected_ports: List[int]
    protocol_distribution: Dict[str, int]

class SecurityRule(BaseModel):
    rule_id: str
    rule_type: str  # "suricata" or "iptables"
    rule_content: str
    priority: int
    expiration: Optional[datetime]
    created_at: datetime
    status: str  # "active", "pending", "expired"
    geographic_scope: Optional[List[str]]
    auto_approved: bool
    effectiveness_score: Optional[float]

class AnomalyAlert(BaseModel):
    alert_id: str
    timestamp: datetime
    ip_address: str
    alert_type: str  # "volume_spike", "connection_frequency", "pattern_deviation"
    severity: int
    baseline_value: float
    current_value: float
    recommendation: str
    requires_immediate_action: bool
```

## Implementation Phases

### Phase 1: Core Agent Framework Enhancement
- Implement base security agent classes
- Develop log collection and normalization system
- Create basic pattern recognition functionality
- Set up central rule repository

### Phase 2: Pattern Analysis Implementation
- Develop geographic IP analysis
- Implement attack pattern recognition
- Create rule generation system
- Develop visualization dashboard

### Phase 3: Anomaly Detection
- Implement traffic monitoring
- Develop baseline analysis
- Create alert generation system
- Integrate with existing security workflows

## Integration Points

### External Systems
- Suricata IDS/IPS
- iptables firewall
- Log management systems
- Geographic IP databases
- Security information and event management (SIEM) systems
- Alert notification systems

### Internal Components
- Existing agent framework
- Message handling system
- Streaming capabilities
- Rule management interface
- Reporting and visualization system