# 🚀 CloudSecOps - Deployment & Infrastructure Setup Guide

This guide details step-by-step instructions for deploying the **CloudSecOps Audit & Security Platform** on AWS, including IAM policies, DynamoDB tables, SNS topics, CloudWatch dashboards, and Lambda packaging.

---

## 📑 Table of Contents
1. [Prerequisites](#1-prerequisites)
2. [IAM Configuration & Permissions](#2-iam-configuration--permissions)
3. [DynamoDB Table Setup](#3-dynamodb-table-setup)
4. [SNS Alerts Topic Setup](#4-sns-alerts-topic-setup)
5. [Packaging & Deploying Lambda Functions](#5-packaging--deploying-lambda-functions)
6. [CloudWatch Dashboard Deployment](#6-cloudwatch-dashboard-deployment)
7. [Running the Web Platform](#7-running-the-web-platform)
8. [Automated CI/CD via GitHub Actions](#8-automated-cicd-via-github-actions)

---

## 1. Prerequisites

- **AWS Account** with administrative or scoped permissions in `ap-south-1` (or your preferred region).
- **AWS CLI v2** installed and configured (`aws configure --profile cloudsecops`).
- **Python 3.11+** installed locally.
- **Git** installed.

---

## 2. IAM Configuration & Permissions

Create an IAM policy named `CloudSecOps-Admin-Policy` with the following permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "LambdaManagement",
      "Effect": "Allow",
      "Action": [
        "lambda:CreateFunction",
        "lambda:UpdateFunctionCode",
        "lambda:UpdateFunctionConfiguration",
        "lambda:GetFunction",
        "lambda:ListFunctions",
        "lambda:InvokeFunction",
        "lambda:DeleteFunction"
      ],
      "Resource": "arn:aws:lambda:*:*:function:cloudsecops-*"
    },
    {
      "Sid": "DynamoDBManagement",
      "Effect": "Allow",
      "Action": [
        "dynamodb:CreateTable",
        "dynamodb:DescribeTable",
        "dynamodb:UpdateTable",
        "dynamodb:PutItem",
        "dynamodb:GetItem",
        "dynamodb:Query",
        "dynamodb:Scan"
      ],
      "Resource": "arn:aws:dynamodb:*:*:table/SecurityFindings"
    },
    {
      "Sid": "CloudWatchAndSNS",
      "Effect": "Allow",
      "Action": [
        "cloudwatch:PutMetricData",
        "cloudwatch:GetMetricData",
        "cloudwatch:PutDashboard",
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "sns:Publish",
        "sns:CreateTopic",
        "sns:Subscribe",
        "sns:ListSubscriptionsByTopic",
        "sns:ListTopics"
      ],
      "Resource": "*"
    },
    {
      "Sid": "IAMRoleManagementForLambda",
      "Effect": "Allow",
      "Action": [
        "iam:CreateRole",
        "iam:GetRole",
        "iam:PassRole",
        "iam:AttachRolePolicy",
        "iam:PutRolePolicy"
      ],
      "Resource": "arn:aws:iam::*:role/cloudsecops-*"
    },
    {
      "Sid": "ReadOnlyAuditingAndRemediation",
      "Effect": "Allow",
      "Action": [
        "ec2:Describe*",
        "ec2:CreateTags",
        "ec2:RevokeSecurityGroupIngress",
        "rds:Describe*",
        "s3:GetBucketPublicAccessBlock",
        "s3:PutPublicAccessBlock",
        "s3:GetEncryptionConfiguration",
        "s3:PutBucketEncryption",
        "s3:PutBucketVersioning",
        "s3:ListAllMyBuckets",
        "iam:ListAccessKeys",
        "iam:UpdateAccessKey",
        "iam:ListUsers"
      ],
      "Resource": "*"
    }
  ]
}
```

Attach this policy to the user or execution role that runs CloudSecOps.

---

## 3. DynamoDB Table Setup

Create the centralized findings table:

```bash
aws dynamodb create-table \
    --table-name SecurityFindings \
    --attribute-definitions \
        AttributeName=finding_id,AttributeType=S \
        AttributeName=timestamp,AttributeType=S \
    --key-schema \
        AttributeName=finding_id,KeyType=HASH \
        AttributeName=timestamp,KeyType=RANGE \
    --billing-mode PAY_PER_REQUEST \
    --region ap-south-1 \
    --profile cloudsecops
```

---

## 4. SNS Alerts Topic Setup

Create the SNS topic for real-time alerts:

```bash
aws sns create-topic \
    --name cloudsecops-alerts \
    --region ap-south-1 \
    --profile cloudsecops
```

Subscribe your email to receive security alerts:

```bash
aws sns subscribe \
    --topic-arn arn:aws:sns:ap-south-1:<YOUR_ACCOUNT_ID>:cloudsecops-alerts \
    --protocol email \
    --notification-endpoint your-email@example.com \
    --region ap-south-1 \
    --profile cloudsecops
```
*Note: Check your email and click the confirmation link to confirm subscription.*

---

## 5. Packaging & Deploying Lambda Functions

Package each Lambda into a deployment ZIP file:

```bash
# 1. Runtime Auditor
cd auditor_package && zip -r ../auditor.zip . && cd ..

# 2. Cost Analyzer
cd cost_analyzer_package && zip -r ../cost_analyzer.zip . && cd ..

# 3. Risk Scorer
cd risk_scorer_package && zip -r ../risk_scorer.zip . && cd ..

# 4. Alerter
cd alerter_package && zip -r ../alerter.zip . && cd ..

# 5. Auto-Remediate
cd auto_remediate_package && zip -r ../auto_remediate.zip . && cd ..

# 6. Report Generator
cd report_generator_package && zip -r ../report_generator.zip . && cd ..
```

Deploy or update Lambda function code:
```bash
aws lambda update-function-code \
    --function-name cloudsecops-runtime-auditor \
    --zip-file fileb://auditor.zip \
    --region ap-south-1 --profile cloudsecops

aws lambda update-function-code \
    --function-name cloudsecops-cost-analyzer \
    --zip-file fileb://cost_analyzer.zip \
    --region ap-south-1 --profile cloudsecops

aws lambda update-function-code \
    --function-name cloudsecops-risk-scorer \
    --zip-file fileb://risk_scorer.zip \
    --region ap-south-1 --profile cloudsecops

aws lambda update-function-code \
    --function-name cloudsecops-alerter \
    --zip-file fileb://alerter.zip \
    --region ap-south-1 --profile cloudsecops

aws lambda update-function-code \
    --function-name cloudsecops-auto-remediate \
    --zip-file fileb://auto_remediate.zip \
    --region ap-south-1 --profile cloudsecops
```

---

## 6. CloudWatch Dashboard Deployment

Run the automated CloudWatch dashboard generator:

```bash
python -c "
import boto3
from cloudwatch_dashboard import deploy_cloudwatch_dashboard
session = boto3.Session(profile_name='cloudsecops', region_name='ap-south-1')
res = deploy_cloudwatch_dashboard(session)
print('Deployment Result:', res)
"
```
The CloudWatch dashboard is accessible in AWS Console at:
`https://ap-south-1.console.aws.amazon.com/cloudwatch/home?region=ap-south-1#dashboards:name=CloudSecOps-Security-Hub`

---

## 7. Running the Web Platform

Start the Flask application:

```bash
python app.py
```
Access the application at `http://localhost:5000`.

To run behind Gunicorn / production server:
```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

---

## 8. Automated CI/CD via GitHub Actions

Configure repository secrets in GitHub:
- `AWS_ACCESS_KEY_ID`: IAM Access Key
- `AWS_SECRET_ACCESS_KEY`: IAM Secret Key
- `AWS_REGION`: e.g. `ap-south-1`

Every push to `main` executes:
1. Automated linting with `flake8`.
2. CloudFormation YAML template validation.
3. Unit and integration tests with `pytest` / `unittest`.
4. Packaging Lambda ZIP files and uploading artifacts.
5. Deploying the CloudWatch dashboard in AWS.
