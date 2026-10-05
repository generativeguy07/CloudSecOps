import os
import boto3
from botocore.exceptions import ClientError

s3_client = boto3.client('s3')
iam_client = boto3.client('iam')
ec2_client = boto3.client('ec2')
dynamodb = boto3.resource('dynamodb')

TABLE_NAME = os.environ.get('TABLE_NAME', 'SecurityFindings')
table = dynamodb.Table(TABLE_NAME)

def lambda_handler(event, context):
    # Fetch OPEN findings needing remediation
    response = table.scan(
        FilterExpression="#st = :open_status AND #rem = :pending",
        ExpressionAttributeNames={"#st": "status", "#rem": "remediation_status"},
        ExpressionAttributeValues={":open_status": "OPEN", ":pending": "PENDING"}
    )
    findings = response.get('Items', [])
    remediated_count = 0

    for item in findings:
        res_type = item.get('resource_type')
        res_id = item.get('resource_id')
        issue = item.get('issue', '')
        success = False

        # Rule 1 & 2: S3 Public Block & Encryption
        if res_type == 'AWS::S3::Bucket':
            if 'Block Public Access' in issue:
                success = fix_s3_block_public_access(res_id)
            elif 'encryption' in issue.lower():
                success = fix_s3_encryption(res_id)

        # Rule 3: Disable Old IAM Access Keys
        elif res_type == 'AWS::IAM::AccessKey' and 'older than 90 days' in issue:
            username, key_id = res_id.split(':')
            success = fix_old_iam_key(username, key_id)

        # Rule 4: EC2 Missing Tags
        elif res_type == 'AWS::EC2::Instance' and 'missing required tags' in issue:
            success = fix_ec2_missing_tags(res_id)

        # Update DynamoDB upon successful remediation
        if success:
            mark_finding_remediated(item['finding_id'], item['timestamp'])
            remediated_count += 1

    return {
        "statusCode": 200,
        "body": f"Auto-Remediation engine processed and fixed {remediated_count} issues."
    }

def fix_s3_block_public_access(bucket_name):
    try:
        s3_client.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True
            }
        )
        return True
    except ClientError:
        return False

def fix_s3_encryption(bucket_name):
    try:
        s3_client.put_bucket_encryption(
            Bucket=bucket_name,
            ServerSideEncryptionConfiguration={
                'Rules': [{'ApplyServerSideEncryptionByDefault': {'SSEAlgorithm': 'AES256'}}]
            }
        )
        return True
    except ClientError:
        return False

def fix_old_iam_key(username, access_key_id):
    try:
        iam_client.update_access_key(
            UserName=username,
            AccessKeyId=access_key_id,
            Status='Inactive'
        )
        return True
    except ClientError:
        return False

def fix_ec2_missing_tags(instance_id):
    try:
        ec2_client.create_tags(
            Resources=[instance_id],
            Tags=[
                {'Key': 'Environment', 'Value': 'AuditRemediated'},
                {'Key': 'Owner', 'Value': 'CloudSecOpsPlatform'}
            ]
        )
        return True
    except ClientError:
        return False

def mark_finding_remediated(finding_id, timestamp):
    table.update_item(
        Key={'finding_id': finding_id, 'timestamp': timestamp},
        UpdateExpression="SET #st = :rem_status, #rem = :done",
        ExpressionAttributeNames={"#st": "status", "#rem": "remediation_status"},
        ExpressionAttributeValues={":rem_status": "RESOLVED", ":done": "COMPLETED"}
    )