import os
import uuid
from datetime import datetime, timezone
import boto3
from botocore.exceptions import ClientError

# Initialize Clients
ec2_client = boto3.client('ec2')
rds_client = boto3.client('rds')
s3_client = boto3.client('s3')
iam_client = boto3.client('iam')
dynamodb = boto3.resource('dynamodb')

TABLE_NAME = os.environ.get('TABLE_NAME', 'SecurityFindings')
table = dynamodb.Table(TABLE_NAME)

def lambda_handler(event, context):
    findings = []
    
    # Run Checks
    findings.extend(check_ec2_instances())
    findings.extend(check_rds_databases())
    findings.extend(check_s3_buckets())
    findings.extend(check_iam_keys())

    # Write to DynamoDB
    save_findings_to_dynamodb(findings)

    return {
        "statusCode": 200,
        "body": f"Runtime Audit completed. Processed {len(findings)} findings."
    }

def check_ec2_instances():
    findings = []
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
    return findings

def check_rds_databases():
    findings = []
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
    return findings

def check_s3_buckets():
    findings = []
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

    return findings

def check_iam_keys():
    findings = []
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

def save_findings_to_dynamodb(findings):
    with table.batch_writer() as batch:
        for finding in findings:
            batch.put_item(Item=finding)