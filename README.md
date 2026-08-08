# AWS IAM Security Auditor

A Python-based AWS security auditing tool that automatically analyzes IAM users and identifies common security risks.

## Project Overview

The AWS IAM Security Auditor uses Python and Boto3 to inspect an AWS account's IAM configuration and identify potential security issues.

The tool currently performs the following security checks:

- IAM user inventory
- MFA compliance
- Access key age
- Administrator access
- Full wildcard permissions
- JSON security reporting

The goal of this project is to demonstrate practical cloud security, IAM auditing, Python automation, and AWS security best practices.

---

## Security Checks

### 1. IAM User Inventory

The auditor retrieves IAM users and displays:

- Username
- ARN
- Creation date

### 2. MFA Audit

The tool checks whether each IAM user has Multi-Factor Authentication enabled.

Users without MFA are reported as security findings.

### 3. Access Key Audit

The tool checks IAM access keys and calculates their age.

Access keys older than 90 days are flagged for review.

### 4. Administrator Access Audit

The auditor checks for users with the AWS managed policy:

`AdministratorAccess`

Users with this policy are reported as high-risk findings.

### 5. Wildcard Permission Audit

The auditor retrieves IAM policy documents and checks for full wildcard actions such as:

```text
Action: *