import os
import boto3
from datetime import datetime, timezone

TABLE_NAME = os.environ.get('TABLE_NAME', 'SecurityFindings')
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN')

def get_sns_client(session=None):
    if session:
        return session.client('sns')
    return boto3.client('sns')

def get_dynamodb_resource(session=None):
    if session:
        return session.resource('dynamodb')
    return boto3.resource('dynamodb')

def lambda_handler(event, context):
    """
    AWS Lambda handler for CloudSecOps Alerter.
    Routes findings by severity:
      - CRITICAL: immediate urgent alert email
      - HIGH: aggregated digest summary email
    """
    findings = event.get('findings', [])
    sns_arn = event.get('topic_arn', SNS_TOPIC_ARN)
    
    if not findings:
        return {
            "statusCode": 200,
            "body": "No findings to alert."
        }
    
    return process_alerts(findings, topic_arn=sns_arn)

def process_alerts(findings, topic_arn=None, session=None):
    """
    Process findings and send alerts based on severity routing rules.
    """
    sns_arn = topic_arn or os.environ.get('SNS_TOPIC_ARN')
    sns_client = get_sns_client(session)
    
    # If topic ARN not provided, attempt to discover existing cloudsecops-alerts topic
    if not sns_arn:
        try:
            topics = sns_client.list_topics().get('Topics', [])
            for t in topics:
                if 'cloudsecops-alerts' in t.get('TopicArn', ''):
                    sns_arn = t.get('TopicArn')
                    break
        except Exception as e:
            print(f"Could not auto-discover SNS topic: {e}")

    # Separate findings by severity
    critical_findings = [f for f in findings if f.get('severity') == 'CRITICAL' and f.get('status', 'OPEN') == 'OPEN']
    high_findings = [f for f in findings if f.get('severity') == 'HIGH' and f.get('status', 'OPEN') == 'OPEN']
    
    sent_critical = 0
    sent_high = 0

    if not sns_arn:
        return {
            "statusCode": 400,
            "error": "No SNS topic ARN configured or discovered.",
            "critical_count": len(critical_findings),
            "high_count": len(high_findings)
        }

    # 1. CRITICAL Findings: Route to Immediate Urgent Alert Email
    if critical_findings:
        send_critical_alert(sns_client, sns_arn, critical_findings)
        sent_critical = len(critical_findings)

    # 2. HIGH Findings: Route to Aggregated Digest Alert Email
    if high_findings:
        send_high_digest_alert(sns_client, sns_arn, high_findings)
        sent_high = len(high_findings)

    return {
        "statusCode": 200,
        "message": f"Alert routing completed. Dispatched alerts for {sent_critical} CRITICAL and {sent_high} HIGH findings.",
        "topic_arn": sns_arn,
        "critical_sent": sent_critical,
        "high_sent": sent_high
    }

def send_critical_alert(sns_client, topic_arn, findings):
    """Sends an immediate urgent alert email for CRITICAL security findings."""
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    subject = f"🚨 [CRITICAL ALERT] CloudSecOps Security Hub - {len(findings)} Urgent Vulnerability(ies) Detected"
    
    message_lines = [
        "===========================================================",
        "        🚨 CLOUDSECOPS PLATFORM - CRITICAL SECURITY ALERT   ",
        "===========================================================",
        f"Timestamp: {timestamp}",
        f"Severity: CRITICAL (IMMEDIATE ACTION REQUIRED)",
        f"Total Critical Findings: {len(findings)}",
        "-----------------------------------------------------------",
        "",
        "CRITICAL FINDINGS DETAILS:"
    ]

    for idx, f in enumerate(findings, 1):
        message_lines.extend([
            f"[{idx}] Resource ID:   {f.get('resource_id')}",
            f"    Resource Type: {f.get('resource_type')}",
            f"    Issue:         {f.get('issue')}",
            f"    Risk Score:    {f.get('risk_score', 'N/A')} / 100",
            f"    Source:        {f.get('source', 'RuntimeAuditor')}",
            f"    Remediation:   Run Auto-Remediation via CloudSecOps Dashboard or apply safe fix.",
            "    -------------------------------------------------------"
        ])

    message_lines.extend([
        "",
        "Action Plan:",
        "1. Open CloudSecOps Dashboard: http://localhost:5000",
        "2. Review affected resources in the Overview findings table.",
        "3. Trigger 'Fix Now' or 'Run Auto-Remediate' to safely patch public access.",
        "",
        "CloudSecOps Security Platform - Automated Alerting Engine"
    ])

    body = "\n".join(message_lines)
    return sns_client.publish(
        TopicArn=topic_arn,
        Subject=subject[:100],  # SNS subject max 100 chars
        Message=body
    )

def send_high_digest_alert(sns_client, topic_arn, findings):
    """Sends an aggregated digest alert email for HIGH security findings."""
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    subject = f"⚠️ [HIGH DIGEST] CloudSecOps Security Hub - {len(findings)} High Severity Finding(s)"
    
    message_lines = [
        "===========================================================",
        "       ⚠️ CLOUDSECOPS PLATFORM - HIGH SEVERITY DIGEST       ",
        "===========================================================",
        f"Timestamp: {timestamp}",
        f"Severity: HIGH (Aggregated Security Digest)",
        f"Total Findings in Digest: {len(findings)}",
        "-----------------------------------------------------------",
        "",
        "DIGEST SUMMARY OF FINDINGS:"
    ]

    # Group by resource type
    by_type = {}
    for f in findings:
        rtype = f.get('resource_type', 'Other')
        by_type.setdefault(rtype, []).append(f)

    for rtype, rfindings in by_type.items():
        message_lines.append(f"\nResource Type: {rtype} ({len(rfindings)} issue(s))")
        for f in rfindings:
            message_lines.extend([
                f"  - Resource: {f.get('resource_id')}",
                f"    Issue:    {f.get('issue')}",
                f"    Risk:     {f.get('risk_score', 'N/A')} / 100"
            ])

    message_lines.extend([
        "",
        "-----------------------------------------------------------",
        "Review these findings in your CloudSecOps Dashboard to prevent privilege escalation or exposure.",
        "CloudSecOps Security Platform - Automated Alerting Engine"
    ])

    body = "\n".join(message_lines)
    return sns_client.publish(
        TopicArn=topic_arn,
        Subject=subject[:100],
        Message=body
    )

def send_test_alert(sns_client, topic_arn, test_email=None):
    """Sends a sample/test alert email to verify SNS configuration."""
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    subject = "🧪 [TEST ALERT] CloudSecOps Platform Alert Pipeline Verification"
    body = f"""===========================================================
  🧪 CLOUDSECOPS PLATFORM - TEST NOTIFICATION PIPELINE
===========================================================
Timestamp: {timestamp}
Status: VERIFIED & OPERATIONAL
Recipient Endpoint: {test_email or 'Subscribed Email'}

This is a sample test notification from your CloudSecOps Platform.
Your SNS Alerting pipeline (Week 6) is properly connected and functioning.

Severity Routing Policy:
  • CRITICAL: Real-time immediate alerts with vulnerability details.
  • HIGH:     Aggregated digest summaries.
  • MEDIUM:   Logged to DynamoDB & CloudWatch Dashboard.
  • LOW:      Tracked in audit logs and compliance score.

To trigger real scans and alerts, connect your AWS account and run 'Sync Account'.
===========================================================
CloudSecOps Security Platform
"""
    return sns_client.publish(
        TopicArn=topic_arn,
        Subject=subject[:100],
        Message=body
    )
