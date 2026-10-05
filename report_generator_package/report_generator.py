import os
import re
import boto3
from datetime import datetime, timezone
from botocore.exceptions import ClientError

TABLE_NAME = os.environ.get('TABLE_NAME', 'SecurityFindings')
REPORTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'reports')

def get_clients(session=None):
    if session:
        return session.client('s3'), session.resource('dynamodb'), session.client('sts')
    return boto3.client('s3'), boto3.resource('dynamodb'), boto3.client('sts')

def lambda_handler(event, context):
    """
    AWS Lambda handler for Report Generator (Scheduled every Friday at 5 PM or triggered on-demand).
    """
    return generate_and_store_report()

def calculate_compliance_and_stats(findings):
    """
    Calculates security score, letter grade, and breakdown statistics.
    """
    total = len(findings)
    critical = sum(1 for f in findings if f.get('severity') == 'CRITICAL' and f.get('status') != 'RESOLVED')
    high = sum(1 for f in findings if f.get('severity') == 'HIGH' and f.get('status') != 'RESOLVED')
    medium = sum(1 for f in findings if f.get('severity') == 'MEDIUM' and f.get('status') != 'RESOLVED')
    low = sum(1 for f in findings if f.get('severity') == 'LOW' and f.get('status') != 'RESOLVED')
    resolved = sum(1 for f in findings if f.get('status') == 'RESOLVED')
    open_count = total - resolved

    # Savings calculation
    savings = 0.0
    for f in findings:
        cost_str = f.get('cost_impact', '')
        if '$' in cost_str:
            numbers = re.findall(r'\d+(?:\.\d+)?', cost_str)
            if numbers:
                savings += float(numbers[0])

    # Compliance score formula
    deduction = (critical * 20) + (high * 10) + (medium * 4) + (low * 1)
    compliance_score = max(0, min(100, round(100 - deduction, 1)))

    if compliance_score >= 90:
        grade = 'A'
        grade_color = '#10b981' # emerald
        grade_desc = 'EXCELLENT - Strong Security Posture'
    elif compliance_score >= 75:
        grade = 'B'
        grade_color = '#3b82f6' # blue
        grade_desc = 'GOOD - Minor Vulnerabilities Detected'
    elif compliance_score >= 60:
        grade = 'C'
        grade_color = '#eab308' # yellow
        grade_desc = 'MODERATE - Action Recommended'
    elif compliance_score >= 40:
        grade = 'D'
        grade_color = '#f97316' # orange
        grade_desc = 'POOR - High Risk Exposure'
    else:
        grade = 'F'
        grade_color = '#ef4444' # red
        grade_desc = 'CRITICAL - Immediate Remediation Needed'

    return {
        'total': total,
        'open': open_count,
        'resolved': resolved,
        'critical': critical,
        'high': high,
        'medium': medium,
        'low': low,
        'savings': savings,
        'compliance_score': compliance_score,
        'grade': grade,
        'grade_color': grade_color,
        'grade_desc': grade_desc
    }

def generate_html_report(account_id, region, findings, stats):
    """
    Renders an executive, self-contained HTML report with modern design and actionable insights.
    """
    report_time = datetime.now(timezone.utc).strftime("%B %d, %Y - %H:%M:%S UTC")
    
    # Findings rows
    findings_rows = ""
    for idx, f in enumerate(findings, 1):
        sev = f.get('severity', 'LOW').upper()
        status = f.get('status', 'OPEN').upper()
        
        # Color coding for severity
        if sev == 'CRITICAL':
            sev_badge = '<span class="badge badge-critical">CRITICAL</span>'
        elif sev == 'HIGH':
            sev_badge = '<span class="badge badge-high">HIGH</span>'
        elif sev == 'MEDIUM':
            sev_badge = '<span class="badge badge-medium">MEDIUM</span>'
        else:
            sev_badge = '<span class="badge badge-low">LOW</span>'

        status_badge = '<span class="badge badge-resolved">RESOLVED</span>' if status == 'RESOLVED' else '<span class="badge badge-open">OPEN</span>'
        
        cost_txt = f.get('cost_impact', '-')
        risk = f.get('risk_score', 'N/A')

        findings_rows += f"""
        <tr>
            <td style="color:#94a3b8; font-family: monospace;">#{idx}</td>
            <td>{sev_badge}</td>
            <td><code class="code-res">{f.get('resource_id', 'N/A')}</code></td>
            <td><span class="type-pill">{f.get('resource_type', 'N/A')}</span></td>
            <td><strong>{f.get('issue', 'N/A')}</strong></td>
            <td><span class="risk-val">{risk}</span></td>
            <td style="color: #10b981; font-weight: 600;">{cost_txt}</td>
            <td>{status_badge}</td>
        </tr>
        """

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CloudSecOps Security Audit Report - AWS Account {account_id}</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg: #0b0f19;
            --surface: #111827;
            --surface-card: #1e293b;
            --border: #334155;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --accent: #6366f1;
            --accent-glow: rgba(99, 102, 241, 0.2);
            --danger: #ef4444;
            --warning: #f59e0b;
            --success: #10b981;
            --info: #3b82f6;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            background: var(--bg);
            color: var(--text-primary);
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            line-height: 1.6;
            padding: 40px 20px;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        .header {{
            background: linear-gradient(135deg, #1e1b4b 0%, #0f172a 100%);
            border: 1px solid #4338ca;
            border-radius: 16px;
            padding: 32px;
            margin-bottom: 28px;
            box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5);
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 20px;
        }}
        .header-title h1 {{
            font-size: 28px;
            font-weight: 800;
            letter-spacing: -0.5px;
            color: #ffffff;
            display: flex;
            align-items: center;
            gap: 12px;
        }}
        .header-meta {{
            margin-top: 8px;
            color: var(--text-secondary);
            font-size: 14px;
        }}
        .header-meta span {{
            margin-right: 18px;
            display: inline-flex;
            align-items: center;
            gap: 6px;
        }}
        .grade-box {{
            background: rgba(15, 23, 42, 0.8);
            border: 2px solid {stats['grade_color']};
            border-radius: 14px;
            padding: 16px 28px;
            text-align: center;
            box-shadow: 0 0 20px {stats['grade_color']}33;
        }}
        .grade-letter {{
            font-size: 48px;
            font-weight: 900;
            color: {stats['grade_color']};
            line-height: 1;
        }}
        .grade-label {{
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: var(--text-secondary);
            margin-top: 4px;
        }}
        .kpi-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 16px;
            margin-bottom: 28px;
        }}
        .kpi-card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px;
            transition: transform 0.2s;
        }}
        .kpi-title {{
            font-size: 13px;
            font-weight: 600;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        .kpi-value {{
            font-size: 32px;
            font-weight: 800;
            margin-top: 6px;
            color: #ffffff;
        }}
        .c-red {{ color: var(--danger); }}
        .c-orange {{ color: var(--warning); }}
        .c-green {{ color: var(--success); }}
        .c-blue {{ color: var(--info); }}
        .c-purple {{ color: #a855f7; }}

        .section-card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 14px;
            padding: 28px;
            margin-bottom: 28px;
        }}
        .section-header {{
            font-size: 18px;
            font-weight: 700;
            margin-bottom: 20px;
            color: #ffffff;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        .table-responsive {{
            overflow-x: auto;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 14px;
            text-align: left;
        }}
        th {{
            background: var(--surface-card);
            color: var(--text-secondary);
            padding: 12px 16px;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 11px;
            letter-spacing: 0.5px;
            border-bottom: 2px solid var(--border);
        }}
        td {{
            padding: 14px 16px;
            border-bottom: 1px solid #1f293d;
            vertical-align: middle;
        }}
        tr:hover td {{
            background: rgba(255, 255, 255, 0.02);
        }}
        .badge {{
            display: inline-block;
            padding: 4px 10px;
            border-radius: 9999px;
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 0.5px;
        }}
        .badge-critical {{ background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid #ef4444; }}
        .badge-high {{ background: rgba(249, 115, 22, 0.2); color: #fb923c; border: 1px solid #f97316; }}
        .badge-medium {{ background: rgba(234, 179, 8, 0.2); color: #facc15; border: 1px solid #eab308; }}
        .badge-low {{ background: rgba(59, 130, 246, 0.2); color: #60a5fa; border: 1px solid #3b82f6; }}
        .badge-resolved {{ background: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid #10b981; }}
        .badge-open {{ background: rgba(239, 68, 68, 0.15); color: #fca5a5; border: 1px solid rgba(239, 68, 68, 0.5); }}
        .code-res {{
            font-family: 'JetBrains Mono', monospace;
            background: rgba(0, 0, 0, 0.4);
            padding: 3px 6px;
            border-radius: 6px;
            font-size: 12px;
            color: #e2e8f0;
        }}
        .type-pill {{
            color: #93c5fd;
            font-size: 12px;
            font-weight: 500;
        }}
        .risk-val {{
            font-weight: 700;
            color: #f1f5f9;
        }}
        .recommendation-box {{
            background: rgba(99, 102, 241, 0.08);
            border-left: 4px solid var(--accent);
            padding: 16px 20px;
            border-radius: 8px;
            margin-top: 20px;
            font-size: 14px;
        }}
        .recommendation-box strong {{
            color: #c7d2fe;
        }}
        .footer {{
            text-align: center;
            font-size: 13px;
            color: var(--text-secondary);
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid var(--border);
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <div class="header-title">
                <h1>🛡️ CloudSecOps Weekly Security Audit</h1>
                <div class="header-meta">
                    <span>🏢 <strong>Account ID:</strong> {account_id}</span>
                    <span>🌐 <strong>Region:</strong> {region}</span>
                    <span>⏱️ <strong>Generated:</strong> {report_time}</span>
                </div>
            </div>
            <div class="grade-box">
                <div class="grade-letter">{stats['grade']}</div>
                <div class="grade-label">Security Grade</div>
            </div>
        </div>

        <!-- KPI Grid -->
        <div class="kpi-grid">
            <div class="kpi-card">
                <div class="kpi-title">Compliance Score</div>
                <div class="kpi-value c-green">{stats['compliance_score']}%</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-title">Total Findings</div>
                <div class="kpi-value">{stats['total']}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-title">Critical Flaws</div>
                <div class="kpi-value c-red">{stats['critical']}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-title">High Severity</div>
                <div class="kpi-value c-orange">{stats['high']}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-title">Auto-Remediated</div>
                <div class="kpi-value c-green">{stats['resolved']}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-title">Est. Monthly Savings</div>
                <div class="kpi-value c-purple">${stats['savings']:.2f}</div>
            </div>
        </div>

        <!-- Executive Summary & Recommendations -->
        <div class="section-card">
            <div class="section-header">📋 Executive Summary & Posture Analysis</div>
            <p style="color: var(--text-secondary);">
                CloudSecOps automated scans analyzed cloud resources across <strong>Amazon EC2, S3, RDS, and IAM</strong>.
                Your cloud environment currently holds a <strong>Grade {stats['grade']} ({stats['grade_desc']})</strong>.
            </p>
            <div class="recommendation-box">
                <strong>💡 Priority Action Items:</strong>
                <ul style="margin-left: 20px; margin-top: 8px;">
                    <li>Ensure all Amazon S3 buckets enforce <strong>Block Public Access</strong> and <strong>AES256 SSE Encryption</strong>.</li>
                    <li>Deactivate IAM Access Keys inactive or older than 90 days to prevent credential leak exploitation.</li>
                    <li>Terminate or resize idle EC2 instances to capture estimated monthly savings of <strong>${stats['savings']:.2f}</strong>.</li>
                    <li>Utilize the CloudSecOps 1-click Auto-Remediation engine to immediately resolve safe misconfigurations.</li>
                </ul>
            </div>
        </div>

        <!-- Detailed Findings Table -->
        <div class="section-card">
            <div class="section-header">🔍 Detailed Security Findings & Risk Audit ({stats['total']} Resources)</div>
            <div class="table-responsive">
                <table>
                    <thead>
                        <tr>
                            <th>#</th>
                            <th>Severity</th>
                            <th>Resource ID</th>
                            <th>Type</th>
                            <th>Identified Flaw / Security Issue</th>
                            <th>Risk Score</th>
                            <th>Cost Impact</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        {findings_rows if findings_rows else '<tr><td colspan="8" style="text-align:center; padding:30px; color:#94a3b8;">🎉 No security findings recorded! Your environment is in great shape.</td></tr>'}
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Footer -->
        <div class="footer">
            Generated automatically by <strong>CloudSecOps Platform</strong> • End-to-End Cloud Security, Compliance & Cost Remediation
        </div>
    </div>
</body>
</html>"""
    return html

def generate_and_store_report(session=None, region="ap-south-1"):
    """
    Generates report, saves locally to reports/, and attempts upload to S3.
    """
    s3_client, dynamodb, sts_client = get_clients(session)
    table = dynamodb.Table(TABLE_NAME)

    # 1. Get Account ID
    try:
        identity = sts_client.get_caller_identity()
        account_id = identity.get('Account', 'UnknownAccount')
    except Exception:
        account_id = '848237287172'

    # 2. Fetch Findings
    try:
        response = table.scan()
        findings = response.get('Items', [])
    except Exception as e:
        print(f"Error fetching findings: {e}")
        findings = []

    # 3. Calculate Stats & Generate HTML
    stats = calculate_compliance_and_stats(findings)
    html_content = generate_html_report(account_id, region, findings, stats)

    # 4. Save Locally
    os.makedirs(REPORTS_DIR, exist_ok=True)
    timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"cloudsecops_report_{account_id}_{timestamp_str}.html"
    local_path = os.path.join(REPORTS_DIR, filename)

    with open(local_path, 'w', encoding='utf-8') as f:
        f.write(html_content)

    # 5. Attempt S3 Upload
    s3_bucket = f"cloudsecops-reports-{account_id}"
    s3_key = f"reports/{filename}"
    s3_uploaded = False
    s3_url = None

    try:
        s3_client.put_object(
            Bucket=s3_bucket,
            Key=s3_key,
            Body=html_content.encode('utf-8'),
            ContentType='text/html'
        )
        s3_uploaded = True
        s3_url = f"https://{s3_bucket}.s3.{region}.amazonaws.com/{s3_key}"
    except ClientError as e:
        # If bucket does not exist or access denied, keep locally and report fallback
        print(f"S3 upload fallback (local copy saved): {e}")

    return {
        "success": True,
        "filename": filename,
        "local_path": local_path,
        "s3_bucket": s3_bucket,
        "s3_uploaded": s3_uploaded,
        "s3_url": s3_url,
        "compliance_score": stats['compliance_score'],
        "grade": stats['grade'],
        "total_findings": stats['total'],
        "critical_count": stats['critical'],
        "high_count": stats['high'],
        "resolved_count": stats['resolved'],
        "savings": stats['savings'],
        "generated_at": datetime.now(timezone.utc).isoformat()
    }

def list_generated_reports():
    """
    Returns list of all available generated HTML reports from the reports directory.
    """
    if not os.path.exists(REPORTS_DIR):
        return []

    reports = []
    for fname in os.listdir(REPORTS_DIR):
        if fname.endswith('.html'):
            fpath = os.path.join(REPORTS_DIR, fname)
            stat = os.stat(fpath)
            reports.append({
                'filename': fname,
                'size_bytes': stat.st_size,
                'created_at': datetime.fromtimestamp(stat.st_mtime, timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'),
                'download_url': f'/api/reports/download/{fname}',
                'preview_url': f'/api/reports/preview/{fname}'
            })
    
    # Sort newest first
    reports.sort(key=lambda x: x['created_at'], reverse=True)
    return reports
