"""
IaC Security Scanner - Scans CloudFormation templates for security issues
"""

import json
import yaml
from pathlib import Path
from security_rules import SECURITY_RULES
from datetime import datetime

# Add custom constructors for CloudFormation intrinsic functions
def cf_constructor(loader, node):
    """Generic constructor for CloudFormation intrinsic functions"""
    if isinstance(node, yaml.ScalarNode):
        return {'Fn::' + node.tag[1:]: loader.construct_scalar(node)}
    elif isinstance(node, yaml.SequenceNode):
        return {'Fn::' + node.tag[1:]: loader.construct_sequence(node, deep=True)}
    else:
        return {'Fn::' + node.tag[1:]: loader.construct_mapping(node, deep=True)}

yaml.SafeLoader.add_constructor('!Ref', cf_constructor)
yaml.SafeLoader.add_constructor('!Sub', cf_constructor)
yaml.SafeLoader.add_constructor('!GetAtt', cf_constructor)
yaml.SafeLoader.add_constructor('!Join', cf_constructor)
yaml.SafeLoader.add_constructor('!ImportValue', cf_constructor)
yaml.SafeLoader.add_constructor('!If', cf_constructor)

class IaCScanner:
    def __init__(self):
        self.findings = []
        self.resources_scanned = 0
        
    def load_template(self, template_path):
        """Load CloudFormation template (JSON or YAML)"""
        try:
            with open(template_path, 'r') as f:
                content = f.read()
                
            # Try JSON first
            try:
                template = json.loads(content)
            except json.JSONDecodeError:
                # Try YAML with SafeLoader (has custom CF constructors)
                template = yaml.load(content, Loader=yaml.SafeLoader)
            
            return template
        except Exception as e:
            print(f"Error loading template: {str(e)}")
            return None
    
    def scan_template(self, template_path):
        """Scan CloudFormation template for security issues"""
        template = self.load_template(template_path)
        
        if not template or 'Resources' not in template:
            return {
                "error": "Invalid CloudFormation template",
                "findings": [],
                "summary": {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
            }
        
        return self._scan_template_dict(template)
    
    def scan_dict(self, template_dict):
        """Scan CloudFormation template from dictionary (for Lambda)"""
        if not template_dict or 'Resources' not in template_dict:
            return {
                "error": "Invalid CloudFormation template",
                "findings": [],
                "summary": {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
            }
        
        return self._scan_template_dict(template_dict)
    
    def _scan_template_dict(self, template):
        """Internal method to scan template dictionary"""
        self.findings = []
        self.resources_scanned = 0
        resources = template.get('Resources', {})
        
        # Scan each resource
        for resource_id, resource in resources.items():
            resource_type = resource.get('Type', '')
            properties = resource.get('Properties', {})
            
            self.resources_scanned += 1
            
            # Apply each rule
            for rule_id, rule in SECURITY_RULES.items():
                # Check if this rule applies to this resource type
                if resource_type in rule['resource_types']:
                    # Call the appropriate check function
                    result = self._run_check(rule_id, rule, resource_id, resource_type, properties)
                    if result:
                        self.findings.append(result)
        
        return self._format_output()
    
    def _run_check(self, rule_id, rule, resource_id, resource_type, properties):
        """Run a specific security check"""
        
        # Check: Open Security Group
        if rule_id == "open-security-group" and resource_type == "AWS::EC2::SecurityGroup":
            ingress = properties.get('SecurityGroupIngress', [])
            for rule in ingress:
                if rule.get('CidrIp') == '0.0.0.0/0' or rule.get('CidrIpv6') == '::/0':
                    return {
                        "resource_id": resource_id,
                        "resource_type": resource_type,
                        "rule": rule_id,
                        "severity": "CRITICAL",
                        "description": f"Security group allows unrestricted access from {rule.get('CidrIp', rule.get('CidrIpv6'))}",
                        "recommendation": "Restrict ingress to specific IP ranges or security groups"
                    }
        
        # Check: RDS Encryption
        if rule_id == "unencrypted-rds" and resource_type == "AWS::RDS::DBInstance":
            storage_encrypted = properties.get('StorageEncrypted', False)
            if not storage_encrypted:
                return {
                    "resource_id": resource_id,
                    "resource_type": resource_type,
                    "rule": rule_id,
                    "severity": "HIGH",
                    "description": "RDS database is not encrypted at rest",
                    "recommendation": "Enable StorageEncrypted: true"
                }
        
        # Check: Public S3 Bucket
        if rule_id == "public-s3-bucket" and resource_type == "AWS::S3::Bucket":
            bucket_policy = properties.get('BucketEncryption', None)
            public_access = properties.get('PublicAccessBlockConfiguration', {})
            
            if not public_access.get('BlockPublicAcls', False):
                return {
                    "resource_id": resource_id,
                    "resource_type": resource_type,
                    "rule": rule_id,
                    "severity": "HIGH",
                    "description": "S3 bucket does not block public access",
                    "recommendation": "Enable PublicAccessBlockConfiguration with all blocks set to true"
                }
        
        # Check: Backup Retention
        if rule_id == "missing-backup" and resource_type == "AWS::RDS::DBInstance":
            backup_retention = properties.get('BackupRetentionPeriod', 0)
            if backup_retention == 0:
                return {
                    "resource_id": resource_id,
                    "resource_type": resource_type,
                    "rule": rule_id,
                    "severity": "MEDIUM",
                    "description": "RDS database has no backup retention configured",
                    "recommendation": "Set BackupRetentionPeriod to at least 7 days"
                }
        
        # Check: Logging
        if rule_id == "missing-logging":
            if resource_type == "AWS::RDS::DBInstance":
                enable_cloudwatch = properties.get('EnableCloudwatchLogsExports', [])
                if not enable_cloudwatch:
                    return {
                        "resource_id": resource_id,
                        "resource_type": resource_type,
                        "rule": rule_id,
                        "severity": "MEDIUM",
                        "description": "RDS database does not have CloudWatch logs enabled",
                        "recommendation": "Enable EnableCloudwatchLogsExports for error and general logs"
                    }
        
        # Check: Owner Tag
        if rule_id == "untagged-resource":
            tags = properties.get('Tags', [])
            has_owner = any(tag.get('Key') == 'Owner' for tag in tags)
            if not has_owner:
                return {
                    "resource_id": resource_id,
                    "resource_type": resource_type,
                    "rule": rule_id,
                    "severity": "LOW",
                    "description": "Resource does not have Owner tag for cost tracking",
                    "recommendation": "Add Tags with Key=Owner and appropriate Value"
                }
        
        # Check: Public RDS
        if rule_id == "public-rds" and resource_type == "AWS::RDS::DBInstance":
            publicly_accessible = properties.get('PubliclyAccessible', False)
            if publicly_accessible:
                return {
                    "resource_id": resource_id,
                    "resource_type": resource_type,
                    "rule": rule_id,
                    "severity": "CRITICAL",
                    "description": "RDS database is publicly accessible (high security risk)",
                    "recommendation": "Set PubliclyAccessible to false and use VPC for access"
                }
        
        return None
    
    def _format_output(self):
        """Format scan results"""
        summary = {
            "total_findings": len(self.findings),
            "critical": len([f for f in self.findings if f['severity'] == 'CRITICAL']),
            "high": len([f for f in self.findings if f['severity'] == 'HIGH']),
            "medium": len([f for f in self.findings if f['severity'] == 'MEDIUM']),
            "low": len([f for f in self.findings if f['severity'] == 'LOW']),
            "resources_scanned": self.resources_scanned
        }
        
        return {
            "timestamp": datetime.now().isoformat(),
            "findings": self.findings,
            "summary": summary,
            "pass": summary['total_findings'] == 0
        }


def scan_file(template_path):
    """Convenience function to scan a single file"""
    scanner = IaCScanner()
    return scanner.scan_template(template_path)


def lambda_handler(event, context):
    """
    AWS Lambda handler for IaC security scanning.
    
    Expects event to contain either:
    - 'template_body' (dict/json string): CloudFormation template as dict or JSON string
    - 'template_string' (string): CloudFormation template as YAML/JSON string
    
    Returns scan results in Lambda response format.
    """
    scanner = IaCScanner()
    
    # Get template from event
    template_body = event.get("template_body")
    template_string = event.get("template_string")
    
    if template_body:
        # Handle dict or JSON string
        if isinstance(template_body, str):
            try:
                template = json.loads(template_body)
            except json.JSONDecodeError:
                return {
                    "statusCode": 400,
                    "body": json.dumps({
                        "status": "ERROR",
                        "message": "Invalid JSON in template_body"
                    })
                }
        else:
            template = template_body
    elif template_string:
        # Handle YAML/JSON string
        try:
            # Try JSON first
            try:
                template = json.loads(template_string)
            except json.JSONDecodeError:
                # Try YAML
                template = yaml.load(template_string, Loader=yaml.SafeLoader)
        except Exception as e:
            return {
                "statusCode": 400,
                "body": json.dumps({
                    "status": "ERROR",
                    "message": f"Failed to parse template: {str(e)}"
                })
            }
    else:
        return {
            "statusCode": 400,
            "body": json.dumps({
                "status": "ERROR",
                "message": "Missing template_body or template_string in event"
            })
        }
    
    # Scan the template
    result = scanner.scan_dict(template)
    
    # Format for Lambda response
    if "error" in result:
        return {
            "statusCode": 400,
            "body": json.dumps({
                "status": "ERROR",
                "message": result["error"]
            })
        }
    
    return {
        "statusCode": 200,
        "body": json.dumps({
            "status": "PASSED" if result["pass"] else "FAILED",
            "findings_count": result["summary"]["total_findings"],
            "findings": result["findings"],
            "summary": result["summary"],
            "timestamp": result["timestamp"]
        })
    }


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python scanner.py <template_path>")
        print("Example: python scanner.py ../tests/bad-security-group.yaml")
        sys.exit(1)
    
    template_path = sys.argv[1]
    result = scan_file(template_path)
    print(json.dumps(result, indent=2))