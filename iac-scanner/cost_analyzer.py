import os
import uuid
from datetime import datetime, timezone, timedelta
import boto3

# Initialize Clients
ec2_client = boto3.client('ec2')
cloudwatch_client = boto3.client('cloudwatch')
dynamodb = boto3.resource('dynamodb')

TABLE_NAME = os.environ.get('TABLE_NAME', 'SecurityFindings')
table = dynamodb.Table(TABLE_NAME)

def lambda_handler(event, context):
    findings = []
    
    findings.extend(check_idle_ec2_instances())
    findings.extend(check_unattached_ebs_volumes())
    
    save_findings_to_dynamodb(findings)

    return {
        "statusCode": 200,
        "body": f"Cost Analysis completed. Recorded {len(findings)} cost-saving findings."
    }

def check_idle_ec2_instances():
    """Identifies EC2 instances with average CPU utilization < 5% over the past 7 days."""
    findings = []
    instances = ec2_client.describe_instances()
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(days=7)

    for reservation in instances.get('Reservations', []):
        for instance in reservation.get('Instances', []):
            if instance['State']['Name'] != 'running':
                continue

            instance_id = instance['InstanceId']
            
            # Query CloudWatch for CPU utilization
            stats = cloudwatch_client.get_metric_statistics(
                Namespace='AWS/EC2',
                MetricName='CPUUtilization',
                Dimensions=[{'Name': 'InstanceId', 'Value': instance_id}],
                StartTime=start_time,
                EndTime=end_time,
                Period=86400,
                Statistics=['Average']
            )

            datapoints = stats.get('Datapoints', [])
            if datapoints:
                avg_cpu = sum(dp['Average'] for dp in datapoints) / len(datapoints)
                if avg_cpu < 5.0:
                    findings.append(create_cost_finding(
                        resource_id=instance_id,
                        resource_type='AWS::EC2::Instance',
                        severity='LOW',
                        issue=f'EC2 Instance is idle (Average CPU {avg_cpu:.1f}% over last 7 days)',
                        cost_impact='~$15 - $50 / month savings'
                    ))
    return findings

def check_unattached_ebs_volumes():
    """Identifies available (unattached) EBS volumes generating extra storage charges."""
    findings = []
    volumes = ec2_client.describe_volumes(
        Filters=[{'Name': 'status', 'Values': ['available']}]
    ).get('Volumes', [])

    for vol in volumes:
        vol_id = vol['VolumeId']
        size_gb = vol['Size']
        findings.append(create_cost_finding(
            resource_id=vol_id,
            resource_type='AWS::EC2::Volume',
            severity='MEDIUM',
            issue=f'Unattached EBS Volume ({size_gb} GB) incurring useless storage costs',
            cost_impact=f'~${size_gb * 0.10:.2f} / month savings'
        ))
    return findings

def create_cost_finding(resource_id, resource_type, severity, issue, cost_impact):
    return {
        'finding_id': str(uuid.uuid4()),
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'source': 'CostAnalyzer',
        'severity': severity,
        'resource_id': resource_id,
        'resource_type': resource_type,
        'issue': issue,
        'cost_impact': cost_impact,
        'status': 'OPEN',
        'remediation_status': 'PENDING'
    }

def save_findings_to_dynamodb(findings):
    with table.batch_writer() as batch:
        for finding in findings:
            batch.put_item(Item=finding)