import os
import uuid
from datetime import datetime, timezone, timedelta
import boto3

TABLE_NAME = os.environ.get('TABLE_NAME', 'SecurityFindings')

def get_clients(session=None):
    if session:
        return (
            session.client('ec2'),
            session.client('cloudwatch'),
            session.resource('dynamodb')
        )
    return (
        boto3.client('ec2'),
        boto3.client('cloudwatch'),
        boto3.resource('dynamodb')
    )

def lambda_handler(event, context):
    return run_cost_analysis()

def run_cost_analysis(session=None):
    ec2_client, cloudwatch_client, dynamodb = get_clients(session)
    table = dynamodb.Table(TABLE_NAME)
    findings = []
    
    findings.extend(check_idle_ec2_instances(ec2_client, cloudwatch_client))
    findings.extend(check_unattached_ebs_volumes(ec2_client))
    
    save_findings_to_dynamodb(table, findings)

    return {
        "statusCode": 200,
        "message": f"Cost Analysis completed. Recorded {len(findings)} cost-saving findings.",
        "findings_count": len(findings),
        "findings": findings
    }

def check_idle_ec2_instances(ec2_client, cloudwatch_client):
    """Identifies EC2 instances with average CPU utilization < 5% over the past 7 days."""
    findings = []
    try:
        instances = ec2_client.describe_instances()
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(days=7)

        for reservation in instances.get('Reservations', []):
            for instance in reservation.get('Instances', []):
                if instance['State']['Name'] != 'running':
                    continue

                instance_id = instance['InstanceId']
                
                # Query CloudWatch for CPU utilization
                try:
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
                                cost_impact='~$25.00 / month savings'
                            ))
                except Exception as e:
                    print(f"Could not get CPU metric for {instance_id}: {e}")
    except Exception as e:
        print(f"Error querying EC2 instances for cost: {e}")

    return findings

def check_unattached_ebs_volumes(ec2_client):
    """Identifies available (unattached) EBS volumes generating extra storage charges."""
    findings = []
    try:
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
    except Exception as e:
        print(f"Error checking EBS volumes: {e}")

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

def save_findings_to_dynamodb(table, findings):
    if not findings:
        return
    with table.batch_writer() as batch:
        for finding in findings:
            batch.put_item(Item=finding)