# AWS IAM Security Auditor

An automated AWS cloud security auditing tool built with Python, AWS Lambda, IAM, Amazon S3, Amazon SNS, and EventBridge Scheduler.

The project continuously audits AWS IAM users for common identity and access management security risks and automatically generates security reports and email alerts.

## Architecture

```text
                    ┌─────────────────────────┐
                    │ EventBridge Scheduler    │
                    │       Every 1 Day        │
                    └────────────┬────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │       AWS Lambda         │
                    │   IAM Security Auditor   │
                    └────────────┬────────────┘
                                 │
                    ┌────────────┴────────────┐
                    │                         │
                    ▼                         ▼
             ┌─────────────┐          ┌─────────────┐
             │   AWS IAM   │          │  Amazon S3   │
             │             │          │              │
             │ MFA         │          │ JSON Report  │
             │ Access Keys │          └─────────────┘
             │ Admin Access│
             │ Wildcards   │
             └─────────────┘
                    │
                    ▼
             ┌─────────────┐
             │  Amazon SNS │
             │             │
             │ Email Alert │
             └─────────────┘
             Project Overview

The AWS IAM Security Auditor automatically identifies potentially dangerous IAM configurations.

The auditor checks:

IAM users without MFA
Access keys older than 90 days
Users with AdministratorAccess
Policies containing wildcard Action: "*"
Administrator access inherited through IAM groups
Wildcard permissions inherited through IAM groups

Security findings are classified by severity and stored as JSON reports in Amazon S3.

When security findings are detected, Amazon SNS sends an email alert.

Technologies Used
Python 3
AWS IAM
AWS Lambda
Amazon S3
Amazon SNS
Amazon EventBridge Scheduler
Boto3
Pytest
Git
GitHub
Security Checks
1. MFA Audit

The auditor checks every IAM user for an enabled MFA device.

Example finding:

MFA_NOT_ENABLED
Severity: HIGH
IAM user does not have MFA enabled.
2. Access Key Age

Access keys are checked for age.

Keys older than 90 days are reported as security findings.

Example:

OLD_ACCESS_KEY
Severity: HIGH
3. Administrator Access

The auditor checks users for the AWS managed policy:

AdministratorAccess

This is classified as:

Severity: CRITICAL

because it grants broad administrative privileges.

4. Wildcard Permissions

The auditor retrieves IAM policy documents and checks for unrestricted actions.

Example:

{
    "Effect": "Allow",
    "Action": "*",
    "Resource": "*"
}

Wildcard actions are reported as:

WILDCARD_ACTION
Severity: CRITICAL
5. IAM Group Auditing

The auditor also checks policies inherited through IAM groups.

This helps identify privilege escalation risks that may not be visible from directly attached user policies.

Automated Reporting

After every scan, the Lambda function creates a JSON security report.

Example:

{
    "summary": {
        "total_findings": 5,
        "mfa_issues": 1,
        "old_access_keys": 0,
        "admin_users": 2,
        "wildcard_findings": 2
    }
}

Reports are automatically uploaded to Amazon S3:

reports/
└── iam-security-report-YYYY-MM-DD-HH-MM-SS.json
Email Alerts

If security findings are detected, Amazon SNS sends an email containing:

Number of findings
MFA issues
Old access keys
Administrator users
Wildcard permissions
Affected IAM users
Severity
S3 report location
Automated Scheduling

Amazon EventBridge Scheduler invokes the Lambda function automatically.

Current schedule:

Every 1 day

This means the security audit can run automatically without manual intervention.

Example Security Scan

Example environment:

Total IAM users: 3

Findings:

cloud-security-lab
├── MFA not enabled          HIGH
├── AdministratorAccess      CRITICAL
└── Wildcard Action          CRITICAL

kedebi
├── AdministratorAccess      CRITICAL
└── Wildcard Action          CRITICAL

dev-alice
└── No critical findings

Summary:

Total findings:       5
MFA issues:           1
Old access keys:      0
Administrator users:  2
Wildcard findings:    2
Project Structure
aws-iam-security-auditor/
│
├── docs/
│   └── deployment-guide.md
│
├── iam/
│   └── lambda-policy.json
│
├── reports/
│   └── iam_security_report.json
│
├── src/
│   ├── config.py
│   ├── iam_auditor.py
│   ├── lambda_function.py
│   ├── requirements.txt
│   └── utils.py
│
├── tests/
│   └── test_lambda.py
│
├── .gitignore
├── LICENSE
└── README.md
Testing

The project uses Pytest for automated testing.

Run:

python -m pytest

Expected result:

7 passed
AWS Deployment
Lambda

The project uses an AWS Lambda function named:

aws-iam-security-auditor

The Lambda function runs the IAM security audit.

IAM Permissions

The Lambda execution role requires permissions to:

List IAM users
Check MFA devices
List access keys
Read IAM policies
Read IAM groups
Upload reports to S3
Publish security alerts to SNS

The EventBridge Scheduler uses a separate execution role to invoke the Lambda function.

S3

Security reports are stored in an S3 bucket under:

reports/
SNS

Amazon SNS is used to send security alerts by email.

EventBridge Scheduler

The scheduler automatically invokes the Lambda once per day.

Security Considerations

This project is designed for security auditing and monitoring.

The auditor does not automatically:

Delete IAM users
Disable users
Delete access keys
Remove policies
Change permissions

Instead, it identifies security risks and reports them so that an administrator can review and remediate them.

This follows a safer detection-first approach.

Future Improvements

Potential future improvements include:

CloudWatch dashboards
Security scoring
Slack notifications
Microsoft Teams notifications
CSV reports
HTML security reports
PDF security reports
AWS Security Hub integration
CloudTrail integration
Automated remediation
Least-privilege policy recommendations
CI/CD deployment with GitHub Actions
Infrastructure as Code using Terraform
Multi-account AWS auditing
Multi-region auditing
Learning Objectives

This project demonstrates practical experience with:

AWS IAM
Identity and Access Management
Cloud security
Least privilege
IAM policy analysis
Python automation
Boto3
AWS Lambda
Amazon S3
Amazon SNS
EventBridge Scheduler
Serverless architecture
Security monitoring
Automated testing
Git and GitHub
Disclaimer

This project is intended for educational and authorized security auditing purposes.

Only run security audits against AWS environments that you own or have explicit permission to assess.

Author

Ahmad kedebi Abubakar

Built as a practical cloud security engineering project demonstrating AWS IAM security automation.

GitHub: Kedebite