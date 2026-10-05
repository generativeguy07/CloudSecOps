"""
Security rules for CloudFormation/Terraform scanning
Each rule defines a check for common misconfigurations
"""

SECURITY_RULES = {
    "open-security-group": {
        "severity": "CRITICAL",
        "description": "Security group allows unrestricted access (0.0.0.0/0)",
        "resource_types": ["AWS::EC2::SecurityGroup", "AWS::EC2::SecurityGroupIngress"],
        "check_function": "check_open_security_group"
    },
    "unencrypted-rds": {
        "severity": "HIGH",
        "description": "RDS database is not encrypted",
        "resource_types": ["AWS::RDS::DBInstance"],
        "check_function": "check_rds_encryption"
    },
    "public-s3-bucket": {
        "severity": "HIGH",
        "description": "S3 bucket allows public access (Block Public Access not enabled)",
        "resource_types": ["AWS::S3::Bucket"],
        "check_function": "check_s3_public"
    },
    "missing-backup": {
        "severity": "MEDIUM",
        "description": "No backup/retention configured",
        "resource_types": ["AWS::RDS::DBInstance"],
        "check_function": "check_backup_retention"
    },
    "missing-logging": {
        "severity": "MEDIUM",
        "description": "Logging is not enabled",
        "resource_types": ["AWS::RDS::DBInstance", "AWS::S3::Bucket"],
        "check_function": "check_logging"
    },
    "untagged-resource": {
        "severity": "LOW",
        "description": "Resource has no Owner tag (cost tracking)",
        "resource_types": ["AWS::EC2::Instance", "AWS::RDS::DBInstance", "AWS::S3::Bucket"],
        "check_function": "check_owner_tag"
    },
    "root-access-key": {
        "severity": "CRITICAL",
        "description": "Root account access keys exist (security risk)",
        "resource_types": ["AWS::IAM::AccessKey"],
        "check_function": "check_root_access_key"
    },
    "public-rds": {
        "severity": "CRITICAL",
        "description": "RDS database is publicly accessible",
        "resource_types": ["AWS::RDS::DBInstance"],
        "check_function": "check_rds_public"
    }
}
