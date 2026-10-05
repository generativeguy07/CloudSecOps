import os
import boto3
from botocore.exceptions import ClientError
from datetime import datetime, timezone

TABLE_NAME = os.environ.get('TABLE_NAME', 'SecurityFindings')

def get_clients(session=None):
    if session:
        return (
            session.client('s3'),
            session.client('iam'),
            session.client('ec2'),
            session.resource('dynamodb')
        )
    return (
        boto3.client('s3'),
        boto3.client('iam'),
        boto3.client('ec2'),
        boto3.resource('dynamodb')
    )

def lambda_handler(event, context):
    """
    AWS Lambda handler for Auto-Remediate.
    Fetches open findings and applies the 5 safe automated fixes.
    """
    return run_auto_remediation()

def run_auto_remediation(session=None):
    """
    Runs the auto-remediation engine across all open, pending findings in DynamoDB.
    Supported 5 Safe Fixes:
      1. Enforce S3 Block Public Access (all 4 settings).
      2. Enforce S3 Default Server-Side Encryption (AES256).
      3. Inactivate IAM Access Keys older than 90 days.
      4. Apply required tags (Environment, Owner) to EC2 instances.
      5. Restrict Security Group open ingress (0.0.0.0/0) on SSH (22) and RDP (3389).
    """
    s3_client, iam_client, ec2_client, dynamodb = get_clients(session)
    table = dynamodb.Table(TABLE_NAME)

    try:
        response = table.scan(
            FilterExpression="#st = :open_status",
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues={":open_status": "OPEN"}
        )
        findings = response.get('Items', [])
    except ClientError as e:
        return {
            "statusCode": 500,
            "error": f"Failed to scan DynamoDB: {str(e)}"
        }

    remediated_findings = []
    failed_findings = []

    for item in findings:
        res_type = item.get('resource_type', '')
        res_id = item.get('resource_id', '')
        issue = item.get('issue', '').lower()
        success = False
        action_taken = ""
        err_msg = ""

        # Safe Fix 1: S3 Block Public Access
        if res_type == 'AWS::S3::Bucket' and ('block public access' in issue or 'public access block' in issue or 'public access' in issue):
            success, err_msg = fix_s3_block_public_access(s3_client, res_id)
            if success:
                action_taken = "Enforced S3 Block Public Access (all 4 flags enabled)"

        # Safe Fix 2: S3 Server-Side Encryption
        elif res_type == 'AWS::S3::Bucket' and ('encryption' in issue):
            success, err_msg = fix_s3_encryption(s3_client, res_id)
            if success:
                action_taken = "Enforced AES256 Default Server-Side Encryption on S3 Bucket"

        # Safe Fix 3: Inactivate Old IAM Access Keys (> 90 days)
        elif res_type == 'AWS::IAM::AccessKey' and ('older than 90 days' in issue or '90 days' in issue):
            if ':' in res_id:
                username, key_id = res_id.split(':', 1)
                success, err_msg = fix_old_iam_key(iam_client, username, key_id)
                if success:
                    action_taken = f"Deactivated stale IAM Access Key {key_id} for user {username}"

        # Safe Fix 4: EC2 Missing Required Tags
        elif res_type == 'AWS::EC2::Instance' and ('missing required tags' in issue or 'missing tags' in issue):
            success, err_msg = fix_ec2_missing_tags(ec2_client, res_id)
            if success:
                action_taken = "Applied mandatory tags (Environment=AuditRemediated, Owner=CloudSecOpsPlatform)"

        # Safe Fix 5: Security Group Open Ingress (0.0.0.0/0 on SSH/RDP) or S3 Versioning
        elif 'securitygroup' in res_type.lower() or 'security group' in issue or 'port 22' in issue or '0.0.0.0/0' in issue:
            success, err_msg = fix_open_security_group(ec2_client, res_id)
            if success:
                action_taken = "Revoked open public 0.0.0.0/0 ingress on sensitive administration ports"

        # Fallback Safe Fix for S3 Versioning / Protection
        elif res_type == 'AWS::S3::Bucket' and 'versioning' in issue:
            success, err_msg = fix_s3_versioning(s3_client, res_id)
            if success:
                action_taken = "Enabled S3 Bucket Versioning"

        if success:
            mark_finding_remediated(table, item['finding_id'], item['timestamp'], action_taken)
            remediated_findings.append({
                "finding_id": item['finding_id'],
                "resource_id": res_id,
                "action": action_taken
            })
        else:
            # If not fixable automatically or failed
            failed_findings.append({
                "finding_id": item.get('finding_id'),
                "resource_id": res_id,
                "reason": "Not eligible for automatic remediation or client error"
            })

    return {
        "statusCode": 200,
        "message": f"Auto-Remediation engine processed {len(findings)} findings. Fixed {len(remediated_findings)} issues.",
        "remediated_count": len(remediated_findings),
        "remediated_findings": remediated_findings,
        "total_scanned": len(findings)
    }

def remediate_single_finding(finding_id, session=None):
    """
    Remediates a single finding by ID.
    """
    s3_client, iam_client, ec2_client, dynamodb = get_clients(session)
    table = dynamodb.Table(TABLE_NAME)

    # Scan finding by finding_id
    response = table.scan(
        FilterExpression="finding_id = :fid",
        ExpressionAttributeValues={":fid": finding_id}
    )
    items = response.get('Items', [])
    if not items:
        return {"success": False, "error": f"Finding ID '{finding_id}' not found."}

    item = items[0]
    res_type = item.get('resource_type', '')
    res_id = item.get('resource_id', '')
    issue = item.get('issue', '').lower()
    success = False
    action_taken = ""
    err_msg = ""

    if res_type == 'AWS::S3::Bucket':
        if 'block public access' in issue or 'public access block' in issue or 'public access' in issue:
            success, err_msg = fix_s3_block_public_access(s3_client, res_id)
            action_taken = "Enforced S3 Block Public Access"
        elif 'encryption' in issue:
            success, err_msg = fix_s3_encryption(s3_client, res_id)
            action_taken = "Enforced AES256 Default SSE"
        else:
            # Safe default for bucket: enforce public access block
            success, err_msg = fix_s3_block_public_access(s3_client, res_id)
            action_taken = "Applied S3 Public Access Block"

    elif res_type == 'AWS::IAM::AccessKey':
        if ':' in res_id:
            username, key_id = res_id.split(':', 1)
            success, err_msg = fix_old_iam_key(iam_client, username, key_id)
            action_taken = f"Deactivated IAM Key {key_id}"

    elif res_type == 'AWS::EC2::Instance':
        success, err_msg = fix_ec2_missing_tags(ec2_client, res_id)
        action_taken = "Applied required tags (Environment, Owner)"

    elif 'securitygroup' in res_type.lower() or 'sg-' in res_id:
        success, err_msg = fix_open_security_group(ec2_client, res_id)
        action_taken = "Restricted open security group ingress"
    else:
        err_msg = f"Unsupported resource type or issue for auto-remediation: {res_type} - {issue}"

    if success:
        mark_finding_remediated(table, item['finding_id'], item['timestamp'], action_taken)
        return {
            "success": True,
            "message": f"Finding {finding_id} successfully remediated: {action_taken}",
            "action_taken": action_taken
        }
    else:
        return {
            "success": False,
            "error": f"Unable to safely auto-remediate finding {finding_id} ({res_type}: {res_id}). Reason: {err_msg}"
        }

# --- 5 Safe Fix Implementations ---

# Fix 1: S3 Block Public Access
def fix_s3_block_public_access(s3_client, bucket_name):
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
        return True, ""
    except ClientError as e:
        err_msg = f"Error blocking public access on {bucket_name}: {e}"
        print(err_msg)
        return False, err_msg

# Fix 2: S3 Server-Side Encryption
def fix_s3_encryption(s3_client, bucket_name):
    try:
        s3_client.put_bucket_encryption(
            Bucket=bucket_name,
            ServerSideEncryptionConfiguration={
                'Rules': [{'ApplyServerSideEncryptionByDefault': {'SSEAlgorithm': 'AES256'}}]
            }
        )
        return True, ""
    except ClientError as e:
        err_msg = f"Error applying encryption on {bucket_name}: {e}"
        print(err_msg)
        return False, err_msg

# Fix 3: Inactivate IAM Access Key (> 90 days)
def fix_old_iam_key(iam_client, username, access_key_id):
    try:
        iam_client.update_access_key(
            UserName=username,
            AccessKeyId=access_key_id,
            Status='Inactive'
        )
        return True, ""
    except ClientError as e:
        err_msg = f"Error deactivating IAM key {access_key_id}: {e}"
        print(err_msg)
        return False, err_msg

# Fix 4: EC2 Missing Required Tags
def fix_ec2_missing_tags(ec2_client, instance_id):
    try:
        ec2_client.create_tags(
            Resources=[instance_id],
            Tags=[
                {'Key': 'Environment', 'Value': 'AuditRemediated'},
                {'Key': 'Owner', 'Value': 'CloudSecOpsPlatform'},
                {'Key': 'RemediatedAt', 'Value': datetime.now(timezone.utc).isoformat()}
            ]
        )
        return True, ""
    except ClientError as e:
        err_msg = f"Error applying EC2 tags on {instance_id}: {e}"
        print(err_msg)
        return False, err_msg

# Fix 5: Restrict Security Group open 0.0.0.0/0 ingress on SSH/RDP
def fix_open_security_group(ec2_client, sg_id):
    try:
        # Revoke open 0.0.0.0/0 ingress on ports 22 (SSH) and 3389 (RDP)
        ec2_client.revoke_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 22,
                    'ToPort': 22,
                    'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                },
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 3389,
                    'ToPort': 3389,
                    'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                }
            ]
        )
        return True, ""
    except ClientError as e:
        err_msg = f"Error revoking open SG ingress on {sg_id}: {e}"
        print(err_msg)
        return False, err_msg

# Auxiliary safe fix: S3 Versioning
def fix_s3_versioning(s3_client, bucket_name):
    try:
        s3_client.put_bucket_versioning(
            Bucket=bucket_name,
            VersioningConfiguration={'Status': 'Enabled'}
        )
        return True, ""
    except ClientError as e:
        err_msg = f"Error enabling versioning on {bucket_name}: {e}"
        print(err_msg)
        return False, err_msg

def mark_finding_remediated(table, finding_id, timestamp, action_taken="Automated Remediation Completed"):
    try:
        table.update_item(
            Key={'finding_id': finding_id, 'timestamp': timestamp},
            UpdateExpression="SET #st = :rem_status, #rem = :done, #act = :action, #rt = :rtime",
            ExpressionAttributeNames={
                "#st": "status",
                "#rem": "remediation_status",
                "#act": "remediation_action",
                "#rt": "remediated_at"
            },
            ExpressionAttributeValues={
                ":rem_status": "RESOLVED",
                ":done": "COMPLETED",
                ":action": action_taken,
                ":rtime": datetime.now(timezone.utc).isoformat()
            }
        )
    except Exception as e:
        print(f"Error marking finding {finding_id} remediated: {e}")