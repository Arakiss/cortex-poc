# Cortex POC

A proof of concept to validate the viability of security log analysis using LLMs within the RODELA platform.

## Overview

This POC aims to demonstrate the effectiveness of using GPT OpenAI models to analyze security logs and generate actionable intelligence. The focus is on processing historical log data and generating structured analysis that can be consumed by downstream systems.

## Development Framework & Scaffolding

### CoreSight Framework
The project utilizes CoreSight, a lightweight and transparent micro-framework for orchestrating LLM-based agents. CoreSight was chosen for its:
- Direct developer control
- Minimal complexity
- Transparent operation
- Efficient agent orchestration

CoreSight was created by Petru Arakiss (petruarakiss@gmail.com) and is used under private license for this project.

### Development Abstractions
In addition to CoreSight, this POC leverages several personal abstractions and utilities developed by Petru Arakiss. These components serve as development scaffolding to:
- Accelerate initial development and prototyping
- Provide temporary structuring patterns
- Enable rapid iteration and testing
- Facilitate proof of concept validation

These additional abstractions are used purely for development purposes and are not intended to be part of the final production implementation. They serve as a temporary framework to validate concepts and patterns that will be properly implemented in the final version.

## Dataset Specifications

### Test Dataset
- Total events: 400 events
- Event types distribution:
  - SQL injections (15.50%)
  - Port scans (14.75%)
  - Protocol abuse (14.75%)
  - Unusual traffic (14.75%)
  - DDoS attacks (14.75%)
  - Brute force attempts (13.25%)
  - Geographic pattern anomalies (12.25%)
- Multiple protocols (HTTP, TCP, UDP, ICMP, FILE)
- Various severity levels (1-5)

### Batch Processing
- Recommended batch size: 50-100 events
- Estimated tokens per event: ~300-400
- Total batches: 4-8

## POC Scope

### Core Objectives
- Validate OpenAI's GPT-4 LLM's model capabilities to understand and analyze security logs
- Demonstrate generation of useful, actionable insights
- Evaluate quality and structure of generated recommendations
- Assess processing costs and performance metrics
- Validate CoreSight framework effectiveness in security analysis

### Out of Scope
- Real-time processing
- External system integrations (except CoreSight)
- User interface implementation
- Automated rule deployment

## Key Features

### Log Analysis
- Processing of security events from JSONL files using CoreSight agents
- Pattern recognition across event types:
  - Port scanning detection
  - Brute force attack identification
  - SQL injection attempts
  - DDoS attack patterns
  - Protocol abuse detection
  - Geographic anomaly detection
  - Unusual traffic analysis
- Severity assessment and prioritization
- Attack pattern identification

### Intelligence Generation
- Structured JSON output through CoreSight agents
- Attack pattern summaries
- Mitigation recommendations
- Risk level assessments
- Critical IP identification
- Protocol-specific analysis
- Geographic pattern analysis

## Technical Implementation

### Core Components
- CoreSight Framework: Orchestrates LLM-based agents
- Log Parser: Processes JSONL security logs
- Batch Processor: Groups related events (50-100 per batch)
- LLM Interface: Manages GPT-4 interactions
- Output Formatter: Structures analysis results

### Agent Architecture
- Orchestration Agent: Manages workflow and task distribution
- Analysis Agents: Specialized in different attack patterns
- Synthesis Agent: Combines findings and generates recommendations
- Validation Agent: Ensures output quality and consistency

### Data Flow
1. Input: JSONL security logs (400 events)
2. Processing: Event grouping and context building
3. Analysis: CoreSight-managed LLM-based pattern detection
4. Output: Structured JSON intelligence

## System Requirements

### Minimum Requirements
- Python 3.11+
- OpenAI API access with GPT-4 capabilities
- CoreSight framework installation
- ~2GB RAM
- Storage for log files

### Dependencies
- CoreSight micro-framework
- OpenAI Python library
- Basic JSON processing utilities
- Minimal logging framework

## POC Metrics

### Success Criteria
- Accurate pattern detection for all event types
- Actionable recommendations for identified threats
- Structured, parseable JSON output
- Processing cost under budget constraints
- Efficient agent orchestration via CoreSight

### Performance Targets
- Batch size: 50-100 events/request
- Response time: <30s per batch
- Cost efficiency: <$0.02 per event
- Total processing time: <5 minutes for full dataset
- Agent orchestration overhead: <5% of total processing time

## Getting Started

1. Clone the repository
2. Install CoreSight framework (private distribution)
3. Install dependencies: `pip install -r requirements.txt`
4. Set OpenAI API key: `export OPENAI_API_KEY="your-key"`
5. Run analysis: `python analyze_logs.py input.jsonl`

## Sample Output

```json
{
  "analysis": {
    "patterns": [
      {
        "type": "port_scan",
        "severity_distribution": {"high": 20, "medium": 45, "low": 35},
        "notable_ips": ["x.x.x.x", "y.y.y.y"],
        "protocols": ["TCP", "UDP", "HTTP"]
      },
      {
        "type": "ddos",
        "protocols": ["ICMP", "UDP", "TCP"],
        "severity_levels": [1, 2, 3, 4, 5]
      }
    ],
    "recommendations": [
      {
        "threat": "port_scanning",
        "mitigation": "Implement rate limiting",
        "priority": "high"
      },
      {
        "threat": "geographic_pattern",
        "mitigation": "Review and update geofencing rules",
        "priority": "medium"
      }
    ],
    "risk_level": "medium",
    "critical_ips": ["x.x.x.x", "y.y.y.y"]
  },
  "metrics": {
    "events_processed": 50,
    "processing_time": "25s",
    "token_cost": "$0.10",
    "batch_number": "1/4",
    "agent_orchestration_time": "1.2s"
  }
}
```

## Limitations

### Technical Limitations
- Batch processing only (no real-time)
- Fixed log format (JSONL only)
- Support for specific event types:
  - Port scan
  - Brute force
  - SQL injection
  - DDoS
  - Protocol abuse
  - Geographic pattern
  - Unusual traffic
- Basic output structure
- No persistent storage
- No authentication/authorization

### Development Dependencies
- CoreSight framework required (private distribution)
- Temporary development abstractions and utilities
- Development scaffolding will be replaced in production
- Proof of concept patterns require production implementation

## Development Timeline

- Week 1: Core implementation
  - Day 1: CoreSight framework setup and configuration
  - Day 2: Agent development and orchestration setup
  - Day 3-4: LLM integration and prompt engineering
  - Day 5: Output formatting and testing
- Week 2: Testing and refinement
  - Day 1-2: Performance testing and optimization
  - Day 3-4: Cost analysis and batch size optimization
  - Day 5: Documentation and final adjustments

## Security Note

This POC processes sensitive security logs. Ensure proper data handling procedures are followed.

## Framework Credits

CoreSight micro-framework created by Petru Arakiss (petruarakiss@gmail.com). Used under private license.

## Copyright

Copyright © 2024 All rights reserved.

---

**Note**: This is a proof of concept implementation. Not intended for production use.