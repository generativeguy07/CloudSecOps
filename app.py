import os
import json
import decimal
import boto3
from datetime import datetime, timezone
from flask import Flask, render_template, jsonify, request, send_file, send_from_directory
from botocore.exceptions import ClientError, ProfileNotFound

# Import local CloudSecOps packages
from cloudwatch_dashboard import (
    deploy_cloudwatch_dashboard,
    publish_cloudsecops_metrics,
    build_dashboard_body,
    get_console_url,
    DEFAULT_DASHBOARD_NAME,
    DEFAULT_REGION
)
from alerter_package.alerter import process_alerts, send_test_alert
from auto_remediate_package.auto_remediate import run_auto_remediation, remediate_single_finding
from report_generator_package.report_generator import (
    generate_and_store_report,
    list_generated_reports,
    REPORTS_DIR
)
from auditor_package.auditor import run_runtime_audit
from cost_analyzer_package.cost_analyzer import run_cost_analysis
from risk_scorer_package.risk_scorer import run_risk_scoring

app = Flask(__name__)

# --- State Management for Connected AWS Account ---
class AWSAccountManager:
    def __init__(self):
        self.session = None
        self.profile_name = os.environ.get('AWS_PROFILE', 'cloudsecops')
        self.region = os.environ.get('AWS_DEFAULT_REGION', DEFAULT_REGION)
        self.account_id = None
        self.caller_arn = None
        self.user_id = None
        self.connection_mode = 'none' # 'profile', 'credentials', or 'none'
        self.is_connected = False
        self.last_synced = None
        self.sns_topic_arn = os.environ.get('SNS_TOPIC_ARN')

    def try_initial_connect(self):
        for candidate_profile in [self.profile_name, 'default']:
            try:
                test_sess = boto3.Session(profile_name=candidate_profile, region_name=self.region)
                sts = test_sess.client('sts')
                identity = sts.get_caller_identity()
                self.session = test_sess
                self.profile_name = candidate_profile
                self.account_id = identity.get('Account')
                self.caller_arn = identity.get('Arn')
                self.user_id = identity.get('UserId')
                self.connection_mode = 'profile'
                self.is_connected = True
                self.discover_sns_topic()
                return True
            except Exception:
                continue

        # If profile connection fails, check environment keys
        try:
            test_sess = boto3.Session(region_name=self.region)
            sts = test_sess.client('sts')
            identity = sts.get_caller_identity()
            self.session = test_sess
            self.account_id = identity.get('Account')
            self.caller_arn = identity.get('Arn')
            self.user_id = identity.get('UserId')
            self.connection_mode = 'environment'
            self.is_connected = True
            self.discover_sns_topic()
            return True
        except Exception:
            self.is_connected = False
            return False

    def connect_with_profile(self, profile_name, region=None):
        reg = region or self.region
        try:
            sess = boto3.Session(profile_name=profile_name, region_name=reg)
            sts = sess.client('sts')
            identity = sts.get_caller_identity()
            self.session = sess
            self.profile_name = profile_name
            self.region = reg
            self.account_id = identity.get('Account')
            self.caller_arn = identity.get('Arn')
            self.user_id = identity.get('UserId')
            self.connection_mode = 'profile'
            self.is_connected = True
            self.discover_sns_topic()
            return True, "Successfully connected via AWS Profile"
        except Exception as e:
            return False, str(e)

    def connect_with_keys(self, access_key, secret_key, session_token=None, region=None):
        reg = region or self.region
        try:
            sess = boto3.Session(
                aws_access_key_id=access_key.strip(),
                aws_secret_access_key=secret_key.strip(),
                aws_session_token=session_token.strip() if session_token else None,
                region_name=reg
            )
            sts = sess.client('sts')
            identity = sts.get_caller_identity()
            self.session = sess
            self.profile_name = None
            self.region = reg
            self.account_id = identity.get('Account')
            self.caller_arn = identity.get('Arn')
            self.user_id = identity.get('UserId')
            self.connection_mode = 'credentials'
            self.is_connected = True
            self.discover_sns_topic()
            return True, "Successfully connected via IAM Access Key"
        except Exception as e:
            return False, str(e)

    def disconnect(self):
        self.session = None
        self.account_id = None
        self.caller_arn = None
        self.user_id = None
        self.connection_mode = 'none'
        self.is_connected = False
        return True

    def discover_sns_topic(self):
        if not self.session:
            return None
        if self.sns_topic_arn:
            return self.sns_topic_arn
        try:
            sns = self.session.client('sns', region_name=self.region)
            topics = sns.list_topics().get('Topics', [])
            for t in topics:
                arn = t.get('TopicArn', '')
                if 'cloudsecops-alerts' in arn:
                    self.sns_topic_arn = arn
                    return arn
            if topics:
                self.sns_topic_arn = topics[0].get('TopicArn')
                return self.sns_topic_arn
        except Exception as e:
            print(f"Could not discover SNS topics: {e}")
        return None

    def get_dynamodb_table(self, table_name='SecurityFindings'):
        if self.session:
            return self.session.resource('dynamodb', region_name=self.region).Table(table_name)
        return boto3.resource('dynamodb', region_name=self.region).Table(table_name)

    def get_lambda_client(self):
        if self.session:
            return self.session.client('lambda', region_name=self.region)
        return boto3.client('lambda', region_name=self.region)

aws_mgr = AWSAccountManager()

def convert_dynamodb_item(item):
    """Safely converts DynamoDB item values (handling Decimal, low-level type dicts, strings)."""
    clean_item = {}
    for k, v in item.items():
        if isinstance(v, dict):
            # Might be low level {'S': '...'} or {'N': '...'}
            if 'S' in v:
                clean_item[k] = v['S']
            elif 'N' in v:
                clean_item[k] = float(v['N']) if '.' in v['N'] else int(v['N'])
            elif 'BOOL' in v:
                clean_item[k] = v['BOOL']
            else:
                clean_item[k] = v
        elif isinstance(v, decimal.Decimal):
            clean_item[k] = int(v) if v % 1 == 0 else float(v)
        else:
            clean_item[k] = v
    return clean_item

# --- Main Page ---
@app.route('/')
def dashboard():
    return render_template('dashboard.html')

# --- AWS Account Connection Endpoints ---
@app.route('/api/account-info')
def get_account_info():
    available_profiles = []
    try:
        available_profiles = boto3.Session().available_profiles
    except Exception:
        pass

    return jsonify({
        "success": True,
        "is_connected": aws_mgr.is_connected,
        "account_id": aws_mgr.account_id,
        "caller_arn": aws_mgr.caller_arn,
        "user_id": aws_mgr.user_id,
        "region": aws_mgr.region,
        "connection_mode": aws_mgr.connection_mode,
        "profile_name": aws_mgr.profile_name,
        "last_synced": aws_mgr.last_synced,
        "sns_topic_arn": aws_mgr.sns_topic_arn,
        "available_profiles": available_profiles
    })

@app.route('/api/connect-aws', methods=['POST'])
def connect_aws():
    data = request.get_json() or {}
    mode = data.get('mode', 'profile')
    region = data.get('region', aws_mgr.region)

    if mode == 'profile':
        profile_name = data.get('profile_name', 'cloudsecops')
        success, msg = aws_mgr.connect_with_profile(profile_name, region)
    elif mode == 'credentials':
        ak = data.get('access_key_id', '')
        sk = data.get('secret_access_key', '')
        token = data.get('session_token')
        if not ak or not sk:
            return jsonify({"success": False, "error": "Access Key ID and Secret Key are required."}), 400
        success, msg = aws_mgr.connect_with_keys(ak, sk, token, region)
    else:
        return jsonify({"success": False, "error": "Invalid connection mode."}), 400

    if success:
        # Trigger sync if requested
        if data.get('auto_sync', True):
            try:
                sync_result = execute_full_sync()
                return jsonify({
                    "success": True,
                    "message": msg,
                    "account_id": aws_mgr.account_id,
                    "caller_arn": aws_mgr.caller_arn,
                    "sync_result": sync_result
                })
            except Exception as e:
                return jsonify({
                    "success": True,
                    "message": f"{msg}, but initial sync had warning: {str(e)}",
                    "account_id": aws_mgr.account_id
                })
        return jsonify({
            "success": True,
            "message": msg,
            "account_id": aws_mgr.account_id,
            "caller_arn": aws_mgr.caller_arn
        })
    else:
        return jsonify({"success": False, "error": msg}), 400

@app.route('/api/disconnect-aws', methods=['POST'])
def disconnect_aws():
    aws_mgr.disconnect()
    return jsonify({
        "success": True,
        "message": "AWS account disconnected."
    })

# --- Full Sync Pipeline ---
def execute_full_sync():
    """
    Executes end-to-end sync workflow:
      1. Runtime Auditor (EC2, RDS, S3, IAM, SG)
      2. Cost Analyzer (Idle EC2, Unattached EBS)
      3. Risk Scorer (computes 0-100 score)
      4. CloudWatch Metrics Publisher (publishes custom metrics)
      5. Alerter (routes CRITICAL -> now, HIGH -> digest)
      6. Report Generator (HTML snapshot)
    """
    session = aws_mgr.session
    steps_log = []

    # Step 1: Auditor
    try:
        audit_res = run_runtime_audit(session=session)
        steps_log.append(f"Runtime Auditor scanned and saved {audit_res.get('findings_count', 0)} security findings.")
    except Exception as e:
        steps_log.append(f"Auditor warning: {str(e)}")

    # Step 2: Cost Analyzer
    try:
        cost_res = run_cost_analysis(session=session)
        steps_log.append(f"Cost Analyzer recorded {cost_res.get('findings_count', 0)} cost-saving findings.")
    except Exception as e:
        steps_log.append(f"Cost Analyzer warning: {str(e)}")

    # Step 3: Risk Scorer
    try:
        score_res = run_risk_scoring(session=session)
        steps_log.append(f"Risk Scorer scored {score_res.get('scored_count', 0)} open findings.")
    except Exception as e:
        steps_log.append(f"Risk Scorer warning: {str(e)}")

    # Fetch current findings
    findings = []
    try:
        table = aws_mgr.get_dynamodb_table('SecurityFindings')
        raw_items = table.scan().get('Items', [])
        findings = [convert_dynamodb_item(item) for item in raw_items]
    except Exception as e:
        steps_log.append(f"Error fetching findings for metrics: {e}")

    # Step 4: CloudWatch Metrics Sync
    try:
        cw_res = publish_cloudsecops_metrics(findings, session=session, region=aws_mgr.region)
        if cw_res.get('success'):
            steps_log.append(f"CloudWatch metrics updated ({cw_res.get('metrics_count')} metrics, Compliance: {cw_res.get('compliance_score')}%).")
    except Exception as e:
        steps_log.append(f"CloudWatch metrics warning: {str(e)}")

    # Step 5: Alerter
    try:
        topic_arn = aws_mgr.discover_sns_topic()
        alert_res = process_alerts(findings, topic_arn=topic_arn, session=session)
        steps_log.append(alert_res.get('message', 'Alerter processed findings.'))
    except Exception as e:
        steps_log.append(f"Alerter warning: {str(e)}")

    # Step 6: Weekly Report Generator
    try:
        rep_res = generate_and_store_report(session=session, region=aws_mgr.region)
        steps_log.append(f"Security audit report generated: {rep_res.get('filename')}.")
    except Exception as e:
        steps_log.append(f"Report generator warning: {str(e)}")

    aws_mgr.last_synced = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    return {
        "success": True,
        "last_synced": aws_mgr.last_synced,
        "findings_count": len(findings),
        "steps_log": steps_log
    }

@app.route('/api/sync-account', methods=['POST'])
def sync_account():
    if not aws_mgr.is_connected:
        return jsonify({"success": False, "error": "No AWS Account connected. Please connect an account first."}), 400

    try:
        result = execute_full_sync()
        return jsonify(result)
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# --- Findings & Summary Endpoints ---
@app.route('/api/findings')
def get_findings():
    try:
        table = aws_mgr.get_dynamodb_table('SecurityFindings')
        response = table.scan(ConsistentRead=True)
        raw_items = response.get('Items', [])
        findings = [convert_dynamodb_item(item) for item in raw_items]

        # Sort: OPEN first, then by risk score descending
        findings.sort(key=lambda x: (
            0 if x.get('status') == 'OPEN' else 1,
            -float(x.get('risk_score') or 0)
        ))

        return jsonify({
            'success': True,
            'findings': findings,
            'count': len(findings)
        })
    except ClientError as e:
        return jsonify({'success': False, 'error': str(e)}), 500
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/summary')
def get_summary():
    try:
        table = aws_mgr.get_dynamodb_table('SecurityFindings')
        response = table.scan(ConsistentRead=True)
        raw_items = response.get('Items', [])
        findings = [convert_dynamodb_item(item) for item in raw_items]

        total = len(findings)
        critical = 0
        high = 0
        medium = 0
        low = 0
        resolved = 0
        open_cnt = 0
        total_risk = 0
        savings = 0.0

        for f in findings:
            sev = f.get('severity', 'LOW').upper()
            status = f.get('status', 'OPEN').upper()
            risk = float(f.get('risk_score') or 0)
            total_risk += risk

            if status == 'RESOLVED':
                resolved += 1
            else:
                open_cnt += 1
                if sev == 'CRITICAL':
                    critical += 1
                elif sev == 'HIGH':
                    high += 1
                elif sev == 'MEDIUM':
                    medium += 1
                elif sev == 'LOW':
                    low += 1

            cost_str = f.get('cost_impact', '')
            if '$' in cost_str:
                import re
                numbers = re.findall(r'\d+(?:\.\d+)?', cost_str)
                if numbers:
                    savings += float(numbers[0])

        avg_risk = round(total_risk / total, 1) if total > 0 else 0
        deduction = (critical * 20) + (high * 10) + (medium * 4) + (low * 1)
        compliance_score = max(0, min(100, round(100 - deduction, 1)))

        return jsonify({
            'success': True,
            'summary': {
                'total': total,
                'critical': critical,
                'high': high,
                'medium': medium,
                'low': low,
                'resolved': resolved,
                'open': open_cnt,
                'avg_risk': avg_risk,
                'compliance_score': compliance_score,
                'savings': round(savings, 2)
            }
        })
    except ClientError as e:
        return jsonify({'success': False, 'error': str(e)}), 500
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# --- CloudWatch Dashboard Endpoints ---
@app.route('/api/cloudwatch/deploy', methods=['POST'])
def deploy_dashboard():
    try:
        res = deploy_cloudwatch_dashboard(session=aws_mgr.session, region=aws_mgr.region)
        return jsonify(res)
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/cloudwatch/preview')
def preview_cloudwatch():
    body = build_dashboard_body(region=aws_mgr.region)
    url = get_console_url(DEFAULT_DASHBOARD_NAME, aws_mgr.region)
    return jsonify({
        "success": True,
        "dashboard_name": DEFAULT_DASHBOARD_NAME,
        "region": aws_mgr.region,
        "console_url": url,
        "body": body
    })

# --- SNS Alerts Endpoints ---
@app.route('/api/sns/status')
def sns_status():
    topic_arn = aws_mgr.discover_sns_topic()
    subscriptions = []
    if topic_arn and aws_mgr.session:
        try:
            sns = aws_mgr.session.client('sns', region_name=aws_mgr.region)
            subs = sns.list_subscriptions_by_topic(TopicArn=topic_arn).get('Subscriptions', [])
            for s in subs:
                subscriptions.append({
                    'protocol': s.get('Protocol'),
                    'endpoint': s.get('Endpoint'),
                    'subscription_arn': s.get('SubscriptionArn')
                })
        except Exception as e:
            print(f"Could not list SNS subscriptions: {e}")

    return jsonify({
        "success": True,
        "topic_arn": topic_arn,
        "subscriptions": subscriptions,
        "subscriber_count": len(subscriptions)
    })

@app.route('/api/sns/subscribe', methods=['POST'])
def sns_subscribe():
    data = request.get_json() or {}
    email = data.get('email', '').strip()
    if not email or '@' not in email:
        return jsonify({"success": False, "error": "A valid email address is required."}), 400

    topic_arn = aws_mgr.discover_sns_topic()

    try:
        sns = aws_mgr.session.client('sns', region_name=aws_mgr.region)
        if not topic_arn:
            topic_arn = sns.create_topic(Name='cloudsecops-alerts').get('TopicArn')
            aws_mgr.sns_topic_arn = topic_arn

        res = sns.subscribe(
            TopicArn=topic_arn,
            Protocol='email',
            Endpoint=email
        )
        return jsonify({
            "success": True,
            "message": f"Confirmation email sent to {email}. Please confirm in your inbox.",
            "subscription_arn": res.get('SubscriptionArn')
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/sns/test', methods=['POST'])
def test_sns_alert():
    topic_arn = aws_mgr.discover_sns_topic()
    if not topic_arn:
        return jsonify({"success": False, "error": "No SNS topic found."}), 400

    try:
        sns = aws_mgr.session.client('sns', region_name=aws_mgr.region)
        res = send_test_alert(sns, topic_arn)
        return jsonify({
            "success": True,
            "message": f"Sample security alert email dispatched to topic {topic_arn}!",
            "message_id": res.get('MessageId')
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# --- Weekly Reporting & S3 Endpoints ---
@app.route('/api/trigger-report', methods=['POST'])
def trigger_report():
    try:
        res = generate_and_store_report(session=aws_mgr.session, region=aws_mgr.region)
        return jsonify(res)
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/reports')
def get_reports():
    reports = list_generated_reports()
    return jsonify({
        "success": True,
        "reports": reports,
        "count": len(reports)
    })

@app.route('/api/reports/download/<path:filename>')
def download_report(filename):
    safe_name = os.path.basename(filename)
    return send_from_directory(REPORTS_DIR, safe_name, as_attachment=True)

@app.route('/api/reports/preview/<path:filename>')
def preview_report(filename):
    safe_name = os.path.basename(filename)
    return send_from_directory(REPORTS_DIR, safe_name, as_attachment=False)

# --- Auto-Remediation Endpoints ---
@app.route('/api/trigger-auto-remediate', methods=['POST'])
def trigger_auto_remediate():
    try:
        # Check if Lambda exists or run internal engine
        res = run_auto_remediation(session=aws_mgr.session)
        return jsonify({
            "success": True,
            "message": res.get("message", "Auto-Remediation engine completed."),
            "remediated_count": res.get("remediated_count", 0),
            "remediated_findings": res.get("remediated_findings", [])
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/remediate-finding/<finding_id>', methods=['POST'])
def remediate_single(finding_id):
    try:
        res = remediate_single_finding(finding_id, session=aws_mgr.session)
        if res.get('success'):
            return jsonify(res)
        return jsonify(res), 400
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# --- Individual Lambda Triggers ---
@app.route('/api/trigger-auditor', methods=['POST'])
def trigger_auditor():
    try:
        # Invoke via local package for reliability and instant feedback
        res = run_runtime_audit(session=aws_mgr.session)
        return jsonify({
            'success': True,
            'message': res.get('message', 'Runtime Auditor completed successfully'),
            'findings_count': res.get('findings_count', 0)
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/trigger-cost-analyzer', methods=['POST'])
def trigger_cost_analyzer():
    try:
        res = run_cost_analysis(session=aws_mgr.session)
        return jsonify({
            'success': True,
            'message': res.get('message', 'Cost Analyzer completed successfully'),
            'findings_count': res.get('findings_count', 0)
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/trigger-risk-scorer', methods=['POST'])
def trigger_risk_scorer():
    try:
        res = run_risk_scoring(session=aws_mgr.session)
        return jsonify({
            'success': True,
            'message': res.get('message', 'Risk Scorer completed successfully'),
            'scored_count': res.get('scored_count', 0)
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

if __name__ == '__main__':
    print("Starting CloudSecOps Server on http://localhost:5000...")
    app.run(debug=True, host='0.0.0.0', port=5000)
