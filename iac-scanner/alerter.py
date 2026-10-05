import os
import boto3
from datetime import datetime, timezone

sns_client = boto3.client('sns')
dynamodb = boto3.resource('dynamodb')

TABLE_NAME = os.environ.get('TABLE_NAME', 'SecurityFindings')
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN')
table = dynamodb.Table(TABLE_NAME)

def lambda_handler(event, context):
    # Get findings from the event (triggered by Runtime Auditor)
    findings = event.get('findings', [])
    
    if not findings:
        return {
            "statusCode": 200,
            "body": "No findings to alert."
        }
    
    # Separate by severity
    critical = [f for f in findings if f.get('severity') == 'CRITICAL']
    high = [f for f in findings if f.get('severity') == 'HIGH']
    
    # Send immediate alerts for CRITICAL
    if critical:
        send_immediate_alert(critical, "CRITICAL")
    
    # Send immediate alerts for HIGH (can be changed to digest later)
    if high:
        send_immediate_alert(high, "HIGH")
    
    return {
        "statusCode": 200,
        "body": f"Sent alerts for {len(critical)} CRITICAL and {len(high)} HIGH findings."
    }

def send_immediate_alert(findings, severity):
    subject = f"[{severity}] CloudSecOps Security Alert - {len(findings)} findings detected"
    
    message = f"""
CloudSecOps Security Alert
Severity: {severity}
Timestamp: {datetime.now(timezone.utc).isoformat()}
Total Findings: {len(findings)}

Findings:
"""
    for finding in findings:
        message += f"""
- Resource: {finding.get('resource_id')}
  Type: {finding.get('resource_type')}
  Issue: {finding.get('issue')}
  Severity: {finding.get('severity')}
  Risk Score: {finding.get('risk_score', 'N/A')}
"""
    
    message += "\nPlease review and take action."
    
    try:
        sns_client.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=subject,
            Message=message
        )
    except Exception as e:
        print(f"Failed to send alert: {str(e)}")
