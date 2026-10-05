import os
import boto3
from datetime import datetime, timezone

dynamodb = boto3.resource('dynamodb')
TABLE_NAME = os.environ.get('TABLE_NAME', 'SecurityFindings')
table = dynamodb.Table(TABLE_NAME)

SEVERITY_WEIGHTS = {
    'CRITICAL': 40,
    'HIGH': 25,
    'MEDIUM': 10,
    'LOW': 5
}

def lambda_handler(event, context):
    # Scan OPEN findings from SecurityFindings
    response = table.scan(
        FilterExpression="#st = :open_status",
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={":open_status": "OPEN"}
    )
    items = response.get('Items', [])

    scored_count = 0
    for item in items:
        score = calculate_risk_score(item)
        
        # Update DynamoDB with calculated risk_score
        table.update_item(
            Key={
                'finding_id': item['finding_id'],
                'timestamp': item['timestamp']
            },
            UpdateExpression="SET risk_score = :s",
            ExpressionAttributeValues={':s': score}
        )
        scored_count += 1

    return {
        "statusCode": 200,
        "body": f"Risk Scorer processed {scored_count} findings."
    }

def calculate_risk_score(item):
    base_score = SEVERITY_WEIGHTS.get(item.get('severity', 'LOW'), 5)
    
    # Extra weight if finding has an associated cost impact
    if 'cost_impact' in item:
        base_score += 15
        
    # Extra weight for S3/IAM public exposure or credentials
    res_type = item.get('resource_type', '')
    if res_type in ['AWS::S3::Bucket', 'AWS::IAM::AccessKey']:
        base_score += 20
        
    return min(base_score, 100)