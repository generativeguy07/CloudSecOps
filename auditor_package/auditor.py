import os
import uuid
from datetime import datetime, timezone
import boto3
from botocore.exceptions import ClientError

TABLE_NAME = os.environ.get('TABLE_NAME', 'SecurityFindings')

def get_clients(session=None):
    if session:
        return (
            session.client('ec2'),
            session.client('rds'),
            session.client('s3'),
            session.client('iam'),
            session.resource('dynamodb')
        )
    return (
        boto3.client('ec2'),
        boto3.client('rds'),
        boto3.client('s3'),
        boto3.client('iam'),
        boto3.resource('dynamodb')
    )

def lambda_handler(event, context):
    return run_runtime_audit()

def run_runtime_audit(session=None):
    """
    Executes full runtime security audit against target AWS account.
    Checks EC2, RDS, S3, IAM, and Security Groups.
    """
    ec2_client, rds_client, s3_client, iam_client, dynamodb = get_clients(session)
    table = dynamodb.Table(TABLE_NAME)
    findings = []
    
    # Run Checks
    findings.extend(check_ec2_instances(ec2_client))
    findings.extend(check_rds_databases(rds_client))
    findings.extend(check_s3_buckets(s3_client))
    findings.extend(check_iam_keys(iam_client))
    findings.extend(check_security_groups(ec2_client))

    # Write to DynamoDB
    save_findings_to_dynamodb(table, findings)

    return {
        "statusCode": 200,
        "message": f"Runtime Audit completed. Processed {len(findings)} findings.",
        "findings_count": len(findings),
        "findings": findings
    }

def check_ec2_instances(ec2_client):
    findings = []
    try:
        response = ec2_client.describe_instances()
        for reservation in response.get('Reservations', []):
            for instance in reservation.get('Instances', []):
                instance_id = instance['InstanceId']
                
                # Check 1: Missing Tags
                tags = {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
                if 'Environment' not in tags or 'Owner' not in tags:
                    findings.append(create_finding_dict(
                        resource_id=instance_id,
                        resource_type='AWS::EC2::Instance',
                        severity='LOW',
                        issue='EC2 Instance missing required tags (Environment, Owner)'
                    ))
                
                # Check 2: Public IP attached
                if instance.get('PublicIpAddress'):
                    findings.append(create_finding_dict(
                        resource_id=instance_id,
                        resource_type='AWS::EC2::Instance',
                        severity='HIGH',
                        issue='EC2 Instance is directly exposed to public internet with a Public IP'
                    ))
    except Exception as e:
        print(f"Error checking EC2 instances: {e}")
    return findings

def check_rds_databases(rds_client):
    findings = []
    try:
        response = rds_client.describe_db_instances()
        for db in response.get('DBInstances', []):
            db_id = db['DBInstanceIdentifier']
            
            # Check 1: Storage Encryption
            if not db.get('StorageEncrypted', False):
                findings.append(create_finding_dict(
                    resource_id=db_id,
                    resource_type='AWS::RDS::DBInstance',
                    severity='HIGH',
                    issue='RDS instance does not have storage encryption enabled'
                ))
                
            # Check 2: Automated Backups
            if db.get('BackupRetentionPeriod', 0) < 7:
                findings.append(create_finding_dict(
                    resource_id=db_id,
                    resource_type='AWS::RDS::DBInstance',
                    severity='MEDIUM',
                    issue='RDS backup retention period is under 7 days'
                ))
    except Exception as e:
        print(f"Error checking RDS: {e}")
    return findings

def check_s3_buckets(s3_client):
    findings = []
    try:
        buckets = s3_client.list_buckets().get('Buckets', [])
        for bucket in buckets:
            bucket_name = bucket['Name']
            
            # Check 1: Block Public Access
            try:
                pba = s3_client.get_public_access_block(Bucket=bucket_name)
                config = pba.get('PublicAccessBlockConfiguration', {})
                if not all([config.get('BlockPublicAcls'), config.get('IgnorePublicAcls'), 
                            config.get('BlockPublicPolicy'), config.get('RestrictPublicBuckets')]):
                    findings.append(create_finding_dict(
                        resource_id=bucket_name,
                        resource_type='AWS::S3::Bucket',
                        severity='CRITICAL',
                        issue='S3 Bucket does not have all Block Public Access settings enabled'
                    ))
            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                    findings.append(create_finding_dict(
                        resource_id=bucket_name,
                        resource_type='AWS::S3::Bucket',
                        severity='CRITICAL',
                        issue='S3 Bucket lacks Public Access Block configuration'
                    ))

            # Check 2: Default Server-Side Encryption
            try:
                s3_client.get_bucket_encryption(Bucket=bucket_name)
            except ClientError as e:
                if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                    findings.append(create_finding_dict(
                        resource_id=bucket_name,
                        resource_type='AWS::S3::Bucket',
                        severity='HIGH',
                        issue='S3 Bucket does not have default server-side encryption enabled'
                    ))
    except Exception as e:
        print(f"Error checking S3: {e}")

    return findings

def check_iam_keys(iam_client):
    findings = []
    try:
        users = iam_client.list_users().get('Users', [])
        now = datetime.now(timezone.utc)
        
        for user in users:
            username = user['UserName']
            keys = iam_client.list_access_keys(UserName=username).get('AccessKeyMetadata', [])
            
            for key in keys:
                if key['Status'] == 'Active':
                    age_days = (now - key['CreateDate']).days
                    if age_days > 90:
                        findings.append(create_finding_dict(
                            resource_id=f"{username}:{key['AccessKeyId']}",
                            resource_type='AWS::IAM::AccessKey',
                            severity='HIGH',
                            issue=f'IAM Access key is older than 90 days ({age_days} days old)'
                        ))
    except Exception as e:
        print(f"Error checking IAM keys: {e}")
    return findings

def check_security_groups(ec2_client):
    findings = []
    try:
        sgs = ec2_client.describe_security_groups().get('SecurityGroups', [])
        for sg in sgs:
            sg_id = sg['GroupId']
            sg_name = sg.get('GroupName', '')
            for rule in sg.get('IpPermissions', []):
                from_port = rule.get('FromPort')
                to_port = rule.get('ToPort')
                ip_ranges = [ip.get('CidrIp') for ip in rule.get('IpRanges', [])]

                if '0.0.0.0/0' in ip_ranges:
                    # SSH (Port 22) open to world
                    if from_port is not None and to_port is not None and from_port <= 22 <= to_port:
                        findings.append(create_finding_dict(
                            resource_id=sg_id,
                            resource_type='AWS::EC2::SecurityGroup',
                            severity='CRITICAL',
                            issue=f'Security Group ({sg_name}) has SSH port 22 open to the public internet (0.0.0.0/0)'
                        ))
                    # RDP (Port 3389) open to world
                    elif from_port is not None and to_port is not None and from_port <= 3389 <= to_port:
                        findings.append(create_finding_dict(
                            resource_id=sg_id,
                            resource_type='AWS::EC2::SecurityGroup',
                            severity='CRITICAL',
                            issue=f'Security Group ({sg_name}) has RDP port 3389 open to the public internet (0.0.0.0/0)'
                        ))
    except Exception as e:
        print(f"Error checking Security Groups: {e}")
    return findings

def create_finding_dict(resource_id, resource_type, severity, issue):
    return {
        'finding_id': str(uuid.uuid4()),
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'source': 'RuntimeAuditor',
        'severity': severity,
        'resource_id': resource_id,
        'resource_type': resource_type,
        'issue': issue,
        'status': 'OPEN',
        'remediation_status': 'PENDING'
    }

def save_findings_to_dynamodb(table, findings):
    if not findings:
        return
    with table.batch_writer() as batch:
        for finding in findings:
            batch.put_item(Item=finding)