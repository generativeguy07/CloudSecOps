"""
CloudWatch Dashboard Generator & Metrics Publisher for CloudSecOps Platform

Builds and deploys CloudWatch Dashboard with widgets for:
1. Security Findings by Severity (Critical, High, Medium, Low)
2. CloudSecOps Compliance Score (%)
3. Estimated Monthly Cost Savings ($)
4. Auto-Remediated Findings Count
5. Service-Level Breakdown of Security Flaws
"""

import json
import boto3
from datetime import datetime, timezone
from botocore.exceptions import ClientError

DEFAULT_DASHBOARD_NAME = "CloudSecOps-Security-Hub"
DEFAULT_REGION = "ap-south-1"
NAMESPACE = "CloudSecOps"

def get_cloudwatch_client(session=None, region=DEFAULT_REGION):
    if session:
        return session.client('cloudwatch', region_name=region)
    return boto3.client('cloudwatch', region_name=region)

def build_dashboard_body(region=DEFAULT_REGION):
    """
    Returns the JSON-compatible dictionary defining the CloudWatch Dashboard widgets.
    """
    body = {
        "widgets": [
            # Header Widget
            {
                "type": "text",
                "x": 0,
                "y": 0,
                "width": 24,
                "height": 2,
                "properties": {
                    "markdown": f"# 🛡️ CloudSecOps Security Hub & Audit Dashboard\n**Region**: `{region}` | **Real-Time Flaws, Compliance Health & Cost Optimization**"
                }
            },
            # Metric Widget 1: Security Findings by Severity (Time Series)
            {
                "type": "metric",
                "x": 0,
                "y": 2,
                "width": 12,
                "height": 6,
                "properties": {
                    "metrics": [
                        [NAMESPACE, "CriticalFindings", { "color": "#dc2626", "stat": "Maximum", "label": "Critical Findings" }],
                        [".", "HighFindings", { "color": "#f97316", "stat": "Maximum", "label": "High Findings" }],
                        [".", "MediumFindings", { "color": "#eab308", "stat": "Maximum", "label": "Medium Findings" }],
                        [".", "LowFindings", { "color": "#3b82f6", "stat": "Maximum", "label": "Low Findings" }]
                    ],
                    "view": "timeSeries",
                    "stacked": False,
                    "region": region,
                    "title": "🔴 Security Findings by Severity",
                    "period": 300,
                    "yAxis": {
                        "left": {
                            "min": 0,
                            "label": "Count"
                        }
                    }
                }
            },
            # Metric Widget 2: Compliance Score % (Single Value Gauge)
            {
                "type": "metric",
                "x": 12,
                "y": 2,
                "width": 6,
                "height": 6,
                "properties": {
                    "metrics": [
                        [NAMESPACE, "ComplianceScore", { "color": "#10b981", "stat": "Average", "label": "Compliance Score (%)" }]
                    ],
                    "view": "singleValue",
                    "region": region,
                    "title": "✅ Compliance Health Score (%)",
                    "period": 300
                }
            },
            # Metric Widget 3: Estimated Monthly Cost Savings
            {
                "type": "metric",
                "x": 18,
                "y": 2,
                "width": 6,
                "height": 6,
                "properties": {
                    "metrics": [
                        [NAMESPACE, "EstimatedCostSavings", { "color": "#8b5cf6", "stat": "Maximum", "label": "Est. Monthly Savings ($)" }]
                    ],
                    "view": "singleValue",
                    "region": region,
                    "title": "💰 Potential Monthly Cost Savings ($)",
                    "period": 300
                }
            },
            # Metric Widget 4: Auto-Remediated / Resolved Findings
            {
                "type": "metric",
                "x": 0,
                "y": 8,
                "width": 12,
                "height": 6,
                "properties": {
                    "metrics": [
                        [NAMESPACE, "ResolvedFindings", { "color": "#10b981", "stat": "Maximum", "label": "Auto-Remediated / Resolved" }],
                        [".", "OpenFindings", { "color": "#ef4444", "stat": "Maximum", "label": "Open Findings" }]
                    ],
                    "view": "bar",
                    "stacked": True,
                    "region": region,
                    "title": "🔧 Auto-Remediation & Resolution Status",
                    "period": 300
                }
            },
            # Metric Widget 5: Findings by Resource Service
            {
                "type": "metric",
                "x": 12,
                "y": 8,
                "width": 12,
                "height": 6,
                "properties": {
                    "metrics": [
                        [NAMESPACE, "S3Findings", { "stat": "Maximum", "label": "S3 Buckets" }],
                        [".", "EC2Findings", { "stat": "Maximum", "label": "EC2 Instances" }],
                        [".", "RDSFindings", { "stat": "Maximum", "label": "RDS Databases" }],
                        [".", "IAMFindings", { "stat": "Maximum", "label": "IAM Credentials" }]
                    ],
                    "view": "timeSeries",
                    "stacked": True,
                    "region": region,
                    "title": "☁️ Flaws Breakdown by AWS Service",
                    "period": 300
                }
            }
        ]
    }
    return body

def deploy_cloudwatch_dashboard(session=None, dashboard_name=DEFAULT_DASHBOARD_NAME, region=DEFAULT_REGION):
    """
    Deploys or updates the CloudWatch Dashboard in the target AWS account & region.
    """
    cw_client = get_cloudwatch_client(session, region)
    dashboard_dict = build_dashboard_body(region)
    dashboard_body_json = json.dumps(dashboard_dict)

    try:
        response = cw_client.put_dashboard(
            DashboardName=dashboard_name,
            DashboardBody=dashboard_body_json
        )
        return {
            "success": True,
            "dashboard_name": dashboard_name,
            "region": region,
            "messages": response.get("DashboardValidationMessages", []),
            "console_url": get_console_url(dashboard_name, region)
        }
    except ClientError as e:
        return {
            "success": False,
            "error": str(e),
            "dashboard_name": dashboard_name
        }

def publish_cloudsecops_metrics(findings, session=None, region=DEFAULT_REGION):
    """
    Publishes real-time CloudSecOps metrics to CloudWatch namespace so dashboard widgets populate.
    """
    cw_client = get_cloudwatch_client(session, region)
    
    # Calculate counts
    critical = sum(1 for f in findings if f.get('severity') == 'CRITICAL' and f.get('status') != 'RESOLVED')
    high = sum(1 for f in findings if f.get('severity') == 'HIGH' and f.get('status') != 'RESOLVED')
    medium = sum(1 for f in findings if f.get('severity') == 'MEDIUM' and f.get('status') != 'RESOLVED')
    low = sum(1 for f in findings if f.get('severity') == 'LOW' and f.get('status') != 'RESOLVED')
    resolved = sum(1 for f in findings if f.get('status') == 'RESOLVED')
    open_findings = len(findings) - resolved

    # Service counts
    s3_cnt = sum(1 for f in findings if 'S3' in f.get('resource_type', ''))
    ec2_cnt = sum(1 for f in findings if 'EC2' in f.get('resource_type', '') or 'Volume' in f.get('resource_type', ''))
    rds_cnt = sum(1 for f in findings if 'RDS' in f.get('resource_type', ''))
    iam_cnt = sum(1 for f in findings if 'IAM' in f.get('resource_type', ''))

    # Estimate savings
    savings = 0.0
    for f in findings:
        cost_str = f.get('cost_impact', '')
        if '$' in cost_str:
            import re
            numbers = re.findall(r'\d+(?:\.\d+)?', cost_str)
            if numbers:
                savings += float(numbers[0])

    # Calculate compliance score (out of 100)
    penalty = (critical * 15) + (high * 8) + (medium * 3) + (low * 1)
    compliance_score = max(0, min(100, round(100 - penalty, 1)))

    timestamp = datetime.now(timezone.utc)

    metric_data = [
        {"MetricName": "CriticalFindings", "Value": critical, "Unit": "Count", "Timestamp": timestamp},
        {"MetricName": "HighFindings", "Value": high, "Unit": "Count", "Timestamp": timestamp},
        {"MetricName": "MediumFindings", "Value": medium, "Unit": "Count", "Timestamp": timestamp},
        {"MetricName": "LowFindings", "Value": low, "Unit": "Count", "Timestamp": timestamp},
        {"MetricName": "TotalFindings", "Value": len(findings), "Unit": "Count", "Timestamp": timestamp},
        {"MetricName": "OpenFindings", "Value": open_findings, "Unit": "Count", "Timestamp": timestamp},
        {"MetricName": "ResolvedFindings", "Value": resolved, "Unit": "Count", "Timestamp": timestamp},
        {"MetricName": "ComplianceScore", "Value": compliance_score, "Unit": "Percent", "Timestamp": timestamp},
        {"MetricName": "EstimatedCostSavings", "Value": round(savings, 2), "Unit": "None", "Timestamp": timestamp},
        {"MetricName": "S3Findings", "Value": s3_cnt, "Unit": "Count", "Timestamp": timestamp},
        {"MetricName": "EC2Findings", "Value": ec2_cnt, "Unit": "Count", "Timestamp": timestamp},
        {"MetricName": "RDSFindings", "Value": rds_cnt, "Unit": "Count", "Timestamp": timestamp},
        {"MetricName": "IAMFindings", "Value": iam_cnt, "Unit": "Count", "Timestamp": timestamp}
    ]

    try:
        cw_client.put_metric_data(
            Namespace=NAMESPACE,
            MetricData=metric_data
        )
        return {
            "success": True,
            "metrics_count": len(metric_data),
            "compliance_score": compliance_score,
            "estimated_savings": savings
        }
    except Exception as e:
        print(f"Error publishing CloudWatch metrics: {e}")
        return {
            "success": False,
            "error": str(e)
        }

def get_console_url(dashboard_name=DEFAULT_DASHBOARD_NAME, region=DEFAULT_REGION):
    """Returns direct CloudWatch Dashboard URL in AWS Management Console."""
    return f"https://{region}.console.aws.amazon.com/cloudwatch/home?region={region}#dashboards:name={dashboard_name}"
