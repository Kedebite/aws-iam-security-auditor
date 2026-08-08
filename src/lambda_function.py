import json
import boto3
from datetime import datetime, timezone


iam = boto3.client("iam")
s3 = boto3.client("s3")
sns = boto3.client("sns")


# ============================================================
# AWS RESOURCES
# ============================================================

S3_BUCKET = "aws-iam-security-auditor-330124996671"

SNS_TOPIC_ARN = (
    "arn:aws:sns:us-east-1:330124996671:iam-security-alerts"
)


# ============================================================
# IAM POLICY FUNCTIONS
# ============================================================

def get_policy_document(policy_arn):
    """Retrieve the default version of an IAM managed policy."""

    policy = iam.get_policy(
        PolicyArn=policy_arn
    )

    default_version = policy["Policy"]["DefaultVersionId"]

    response = iam.get_policy_version(
        PolicyArn=policy_arn,
        VersionId=default_version
    )

    return response["PolicyVersion"]["Document"]


def contains_wildcard_action(document):
    """Check whether an IAM policy contains Action: '*'."""

    statements = document.get(
        "Statement",
        []
    )

    if isinstance(statements, dict):
        statements = [statements]

    for statement in statements:

        action = statement.get("Action")

        if action == "*":
            return True

        if isinstance(action, list) and "*" in action:
            return True

    return False


# ============================================================
# LAMBDA HANDLER
# ============================================================

def lambda_handler(event, context):

    findings = []

    # ========================================================
    # GET IAM USERS
    # ========================================================

    response = iam.list_users()

    for user in response["Users"]:

        username = user["UserName"]

        # ====================================================
        # 1. MFA CHECK
        # ====================================================

        mfa_devices = iam.list_mfa_devices(
            UserName=username
        )

        if len(mfa_devices["MFADevices"]) == 0:

            findings.append({
                "user": username,
                "issue": "MFA_NOT_ENABLED",
                "severity": "HIGH",
                "details": (
                    "IAM user does not have MFA enabled."
                )
            })

        # ====================================================
        # 2. ACCESS KEY CHECK
        # ====================================================

        keys = iam.list_access_keys(
            UserName=username
        )

        for key in keys["AccessKeyMetadata"]:

            created = key["CreateDate"]

            age = (
                datetime.now(timezone.utc) - created
            ).days

            if age > 90:

                findings.append({
                    "user": username,
                    "issue": "OLD_ACCESS_KEY",
                    "severity": "HIGH",
                    "details": (
                        f"Access key "
                        f"{key['AccessKeyId']} "
                        f"is {age} days old."
                    )
                })

        # ====================================================
        # 3. DIRECT USER POLICIES
        # ====================================================

        policies = iam.list_attached_user_policies(
            UserName=username
        )

        for policy in policies["AttachedPolicies"]:

            policy_name = policy["PolicyName"]
            policy_arn = policy["PolicyArn"]

            # -----------------------------------------------
            # AdministratorAccess
            # -----------------------------------------------

            if policy_name == "AdministratorAccess":

                findings.append({
                    "user": username,
                    "issue": "ADMINISTRATOR_ACCESS",
                    "severity": "CRITICAL",
                    "details": (
                        "User has AdministratorAccess."
                    )
                })

            # -----------------------------------------------
            # Wildcard Action
            # -----------------------------------------------

            try:

                document = get_policy_document(
                    policy_arn
                )

                if contains_wildcard_action(document):

                    findings.append({
                        "user": username,
                        "issue": "WILDCARD_ACTION",
                        "severity": "CRITICAL",
                        "details": (
                            f"Policy {policy_name} "
                            f"allows Action: *"
                        )
                    })

            except Exception as error:

                print(
                    f"Could not inspect policy "
                    f"{policy_name}: {error}"
                )

        # ====================================================
        # 4. GROUP POLICIES
        # ====================================================

        groups = iam.list_groups_for_user(
            UserName=username
        )

        for group in groups["Groups"]:

            group_name = group["GroupName"]

            group_policies = iam.list_attached_group_policies(
                GroupName=group_name
            )

            for policy in group_policies["AttachedPolicies"]:

                policy_name = policy["PolicyName"]
                policy_arn = policy["PolicyArn"]

                # -------------------------------------------
                # Group AdministratorAccess
                # -------------------------------------------

                if policy_name == "AdministratorAccess":

                    findings.append({
                        "user": username,
                        "issue": (
                            "GROUP_ADMINISTRATOR_ACCESS"
                        ),
                        "severity": "CRITICAL",
                        "details": (
                            f"User receives "
                            f"AdministratorAccess through "
                            f"group {group_name}."
                        )
                    })

                # -------------------------------------------
                # Group wildcard permissions
                # -------------------------------------------

                try:

                    document = get_policy_document(
                        policy_arn
                    )

                    if contains_wildcard_action(document):

                        findings.append({
                            "user": username,
                            "issue": (
                                "GROUP_WILDCARD_ACTION"
                            ),
                            "severity": "CRITICAL",
                            "details": (
                                f"Policy {policy_name} "
                                f"attached through group "
                                f"{group_name} allows "
                                f"Action: *"
                            )
                        })

                except Exception as error:

                    print(
                        f"Could not inspect group "
                        f"policy {policy_name}: {error}"
                    )

    # ========================================================
    # SECURITY SUMMARY
    # ========================================================

    summary = {

        "total_findings": len(findings),

        "mfa_issues": len([
            f for f in findings
            if f["issue"] == "MFA_NOT_ENABLED"
        ]),

        "old_access_keys": len([
            f for f in findings
            if f["issue"] == "OLD_ACCESS_KEY"
        ]),

        "admin_users": len([
            f for f in findings
            if f["issue"] in [
                "ADMINISTRATOR_ACCESS",
                "GROUP_ADMINISTRATOR_ACCESS"
            ]
        ]),

        "wildcard_findings": len([
            f for f in findings
            if f["issue"] in [
                "WILDCARD_ACTION",
                "GROUP_WILDCARD_ACTION"
            ]
        ]),

        "scan_time": datetime.now(
            timezone.utc
        ).isoformat()
    }

    # ========================================================
    # FINAL REPORT
    # ========================================================

    report = {
        "summary": summary,
        "findings": findings
    }

    # ========================================================
    # SAVE REPORT TO S3
    # ========================================================

    timestamp = datetime.now(
        timezone.utc
    ).strftime(
        "%Y-%m-%d-%H-%M-%S"
    )

    s3_key = (
        f"reports/"
        f"iam-security-report-{timestamp}.json"
    )

    s3.put_object(
        Bucket=S3_BUCKET,
        Key=s3_key,
        Body=json.dumps(
            report,
            indent=4,
            default=str
        ),
        ContentType="application/json"
    )

    report_location = (
        f"s3://{S3_BUCKET}/{s3_key}"
    )

    print(
        f"Security report saved to: "
        f"{report_location}"
    )

    # ========================================================
    # SEND SNS SECURITY ALERT
    # ========================================================

    if len(findings) > 0:

        email_message = (
            "AWS IAM SECURITY ALERT\n"
            "=======================\n\n"
            f"Security findings detected: "
            f"{len(findings)}\n\n"

            f"MFA issues: "
            f"{summary['mfa_issues']}\n"

            f"Old access keys: "
            f"{summary['old_access_keys']}\n"

            f"Administrator users: "
            f"{summary['admin_users']}\n"

            f"Wildcard findings: "
            f"{summary['wildcard_findings']}\n\n"

            "FINDINGS\n"
            "--------\n\n"
        )

        for finding in findings:

            email_message += (
                f"User: {finding['user']}\n"
                f"Issue: {finding['issue']}\n"
                f"Severity: {finding['severity']}\n"
                f"Details: {finding['details']}\n"
                "-----------------------------\n"
            )

        email_message += (
            "\nSecurity report:\n"
            f"{report_location}\n"
        )

        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject="AWS IAM Security Alert",
            Message=email_message
        )

        print(
            "SNS security alert sent successfully."
        )

    # ========================================================
    # PRINT REPORT
    # ========================================================

    print(
        json.dumps(
            report,
            indent=4,
            default=str
        )
    )

    # ========================================================
    # RETURN RESPONSE
    # ========================================================

    return {

        "statusCode": 200,

        "body": json.dumps({

            "message": (
                "IAM security audit completed successfully."
            ),

            "report_location": report_location,

            "summary": summary,

            "findings": findings

        }, default=str)
    }