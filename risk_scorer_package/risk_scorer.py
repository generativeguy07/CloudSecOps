import os
import boto3
from datetime import datetime, timezone

TABLE_NAME = os.environ.get('TABLE_NAME', 'SecurityFindings')

SEVERITY_WEIGHTS = {
    'CRITICAL': 40,
    'HIGH': 25,
    'MEDIUM': 10,
    'LOW': 5
}

def get_dynamodb(session=None):
    if session:
        return session.resource('dynamodb')
    return boto3.resource('dynamodb')

def lambda_handler(event, context):
    return run_risk_scoring()

def run_risk_scoring(session=None):
    dynamodb = get_dynamodb(session)
    table = dynamodb.Table(TABLE_NAME)

    # Scan OPEN findings from SecurityFindings
    try:
        response = table.scan(
            FilterExpression="#st = :open_status",
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues={":open_status": "OPEN"}
        )
        items = response.get('Items', [])
    except Exception as e:
        return {
            "statusCode": 500,
            "error": f"Failed to scan DynamoDB: {str(e)}"
        }

    scored_count = 0
    for item in items:
        score = calculate_risk_score(item)
        
        # Update DynamoDB with calculated risk_score
        try:
            table.update_item(
                Key={
                    'finding_id': item['finding_id'],
                    'timestamp': item['timestamp']
                },
                UpdateExpression="SET risk_score = :s",
                ExpressionAttributeValues={':s': score}
            )
            scored_count += 1
        except Exception as e:
            print(f"Error updating score for {item.get('finding_id')}: {e}")

    return {
        "statusCode": 200,
        "message": f"Risk Scorer processed {scored_count} findings.",
        "scored_count": scored_count
    }

def calculate_risk_score(item):
    base_score = SEVERITY_WEIGHTS.get(item.get('severity', 'LOW'), 5)
    
    # Extra weight if finding has an associated cost impact
    if 'cost_impact' in item:
        base_score += 15
        
    # Extra weight for S3/IAM public exposure or credentials or open security groups
    res_type = item.get('resource_type', '')
    if res_type in ['AWS::S3::Bucket', 'AWS::IAM::AccessKey', 'AWS::EC2::SecurityGroup']:
        base_score += 20
        
    return min(base_score, 100)