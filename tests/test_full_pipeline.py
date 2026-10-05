import unittest
import json
import os
from unittest.mock import MagicMock, patch
import boto3

# Modules to test
import app
from cloudwatch_dashboard import build_dashboard_body, DEFAULT_DASHBOARD_NAME
from alerter_package.alerter import process_alerts, send_critical_alert, send_high_digest_alert
from auto_remediate_package.auto_remediate import (
    fix_s3_block_public_access,
    fix_s3_encryption,
    fix_old_iam_key,
    fix_ec2_missing_tags,
    fix_open_security_group,
    run_auto_remediation
)
from report_generator_package.report_generator import (
    calculate_compliance_and_stats,
    generate_html_report
)
from risk_scorer_package.risk_scorer import calculate_risk_score
from auditor_package.auditor import create_finding_dict

class TestCloudSecOpsPipeline(unittest.TestCase):
    def setUp(self):
        self.app = app.app
        self.client = self.app.test_client()

    # --- Test 1: Account Connection & Manager ---
    def test_account_manager_initialization(self):
        mgr = app.AWSAccountManager()
        self.assertIsNotNone(mgr.region)
        # Should be initialized
        info = self.client.get('/api/account-info').json
        self.assertTrue(info['success'])
        self.assertIn('is_connected', info)
        self.assertIn('available_profiles', info)

    # --- Test 2: Risk Scorer Calculation ---
    def test_risk_scorer_weights(self):
        crit_item = {'severity': 'CRITICAL', 'resource_type': 'AWS::EC2::Instance'}
        self.assertEqual(calculate_risk_score(crit_item), 40)

        # Critical + S3 Bucket resource boost
        s3_crit = {'severity': 'CRITICAL', 'resource_type': 'AWS::S3::Bucket'}
        self.assertEqual(calculate_risk_score(s3_crit), 60)

        # Critical + S3 + Cost impact boost
        s3_cost = {'severity': 'CRITICAL', 'resource_type': 'AWS::S3::Bucket', 'cost_impact': '$50'}
        self.assertEqual(calculate_risk_score(s3_cost), 75)

        # High severity
        high_item = {'severity': 'HIGH', 'resource_type': 'AWS::RDS::DBInstance'}
        self.assertEqual(calculate_risk_score(high_item), 25)

    # --- Test 3: Alerter Severity Routing ---
    @patch('alerter_package.alerter.get_sns_client')
    def test_alerter_routing(self, mock_sns_getter):
        mock_sns = MagicMock()
        mock_sns_getter.return_value = mock_sns

        findings = [
            {'finding_id': '1', 'severity': 'CRITICAL', 'status': 'OPEN', 'resource_id': 'bucket-1', 'issue': 'Public Bucket'},
            {'finding_id': '2', 'severity': 'HIGH', 'status': 'OPEN', 'resource_id': 'user:key-1', 'issue': 'Old IAM Key'},
            {'finding_id': '3', 'severity': 'LOW', 'status': 'OPEN', 'resource_id': 'i-12345', 'issue': 'Missing tags'}
        ]

        result = process_alerts(findings, topic_arn='arn:aws:sns:ap-south-1:123456789012:test-topic')
        self.assertEqual(result['statusCode'], 200)
        self.assertEqual(result['critical_sent'], 1)
        self.assertEqual(result['high_sent'], 1)
        # Verify publish was called twice (1 for CRITICAL urgent, 1 for HIGH digest)
        self.assertEqual(mock_sns.publish.call_count, 2)

    # --- Test 4: CloudWatch Dashboard Generation ---
    def test_cloudwatch_dashboard_widgets(self):
        body = build_dashboard_body(region='ap-south-1')
        self.assertIn('widgets', body)
        widgets = body['widgets']
        self.assertGreaterEqual(len(widgets), 4)

        # Check widget titles
        titles = [w.get('properties', {}).get('title', '') for w in widgets if 'properties' in w]
        self.assertTrue(any('Severity' in t for t in titles))
        self.assertTrue(any('Compliance' in t for t in titles))
        self.assertTrue(any('Cost' in t for t in titles))

    # --- Test 5: Report Generator Calculations & HTML Output ---
    def test_report_generator_stats(self):
        sample_findings = [
            {'severity': 'CRITICAL', 'status': 'OPEN', 'cost_impact': '$20.00 / month'},
            {'severity': 'HIGH', 'status': 'OPEN', 'cost_impact': '$15.00 / month'},
            {'severity': 'LOW', 'status': 'RESOLVED'},
        ]
        stats = calculate_compliance_and_stats(sample_findings)
        self.assertEqual(stats['total'], 3)
        self.assertEqual(stats['critical'], 1)
        self.assertEqual(stats['high'], 1)
        self.assertEqual(stats['resolved'], 1)
        self.assertEqual(stats['savings'], 35.0)

        # Test HTML generation
        html = generate_html_report('123456789012', 'ap-south-1', sample_findings, stats)
        self.assertIn('CloudSecOps Weekly Security Audit', html)
        self.assertIn('123456789012', html)
        self.assertIn('CRITICAL', html)

    # --- Test 6: Auto-Remediation 5 Safe Fixes ---
    def test_auto_remediate_safe_fixes(self):
        mock_s3 = MagicMock()
        mock_iam = MagicMock()
        mock_ec2 = MagicMock()

        # Fix 1: S3 Public Access Block
        res1, _ = fix_s3_block_public_access(mock_s3, 'test-bucket')
        self.assertTrue(res1)
        mock_s3.put_public_access_block.assert_called_once()

        # Fix 2: S3 Encryption
        res2, _ = fix_s3_encryption(mock_s3, 'test-bucket')
        self.assertTrue(res2)
        mock_s3.put_bucket_encryption.assert_called_once()

        # Fix 3: Old IAM Key
        res3, _ = fix_old_iam_key(mock_iam, 'test-user', 'AKIA12345')
        self.assertTrue(res3)
        mock_iam.update_access_key.assert_called_once_with(UserName='test-user', AccessKeyId='AKIA12345', Status='Inactive')

        # Fix 4: EC2 Missing Tags
        res4, _ = fix_ec2_missing_tags(mock_ec2, 'i-0123456789')
        self.assertTrue(res4)
        mock_ec2.create_tags.assert_called_once()

        # Fix 5: Open Security Group Ingress
        res5, _ = fix_open_security_group(mock_ec2, 'sg-0123456789')
        self.assertTrue(res5)
        mock_ec2.revoke_security_group_ingress.assert_called_once()

    # --- Test 7: API Endpoints ---
    def test_api_endpoints_availability(self):
        # /api/summary
        r_sum = self.client.get('/api/summary')
        self.assertEqual(r_sum.status_code, 200)
        self.assertTrue(r_sum.json['success'])

        # /api/findings
        r_find = self.client.get('/api/findings')
        self.assertEqual(r_find.status_code, 200)
        self.assertTrue(r_find.json['success'])

        # /api/cloudwatch/preview
        r_cw = self.client.get('/api/cloudwatch/preview')
        self.assertEqual(r_cw.status_code, 200)
        self.assertIn('console_url', r_cw.json)

        # /api/reports
        r_rep = self.client.get('/api/reports')
        self.assertEqual(r_rep.status_code, 200)
        self.assertTrue(r_rep.json['success'])

        # /api/sns/status
        r_sns = self.client.get('/api/sns/status')
        self.assertEqual(r_sns.status_code, 200)
        self.assertTrue(r_sns.json['success'])

if __name__ == '__main__':
    unittest.main()
