import boto3
import json
from datetime import datetime, timezone
from urllib.parse import unquote
from pathlib import Path


class IAMAuditor:

    def __init__(self):
        self.iam = boto3.client("iam")
        self.findings = []

    # ---------------------------------------------------------
    # ADD SECURITY FINDING
    # ---------------------------------------------------------
    def add_finding(self, user, issue, severity, details):
        self.findings.append({
            "user": user,
            "issue": issue,
            "severity": severity,
            "details": details
        })

    # ---------------------------------------------------------
    # 1. LIST IAM USERS
    # ---------------------------------------------------------
    def list_users(self):

        response = self.iam.list_users()

        users = response["Users"]

        print("=" * 50)
        print("AWS IAM USERS")
        print("=" * 50)

        for user in users:

            print(f"User Name : {user['UserName']}")
            print(f"User ARN  : {user['Arn']}")
            print(f"Created   : {user['CreateDate']}")
            print("-" * 50)

    # ---------------------------------------------------------
    # 2. CHECK MFA
    # ---------------------------------------------------------
    def check_mfa(self):

        response = self.iam.list_users()

        print("\n" + "=" * 50)
        print("MFA STATUS REPORT")
        print("=" * 50)

        for user in response["Users"]:

            username = user["UserName"]

            mfa_devices = self.iam.list_mfa_devices(
                UserName=username
            )

            if len(mfa_devices["MFADevices"]) == 0:

                print(
                    f"❌ {username} - "
                    f"MFA NOT ENABLED"
                )

                self.add_finding(
                    username,
                    "MFA_NOT_ENABLED",
                    "HIGH",
                    "IAM user does not have MFA enabled."
                )

            else:

                print(
                    f"✅ {username} - "
                    f"MFA ENABLED"
                )

    # ---------------------------------------------------------
    # 3. CHECK ACCESS KEY AGE
    # ---------------------------------------------------------
    def check_access_keys(self):

        response = self.iam.list_users()

        print("\n" + "=" * 50)
        print("ACCESS KEY AUDIT")
        print("=" * 50)

        for user in response["Users"]:

            username = user["UserName"]

            print(f"\nUser: {username}")

            keys = self.iam.list_access_keys(
                UserName=username
            )

            if len(keys["AccessKeyMetadata"]) == 0:

                print("No access keys found.")

                continue

            for key in keys["AccessKeyMetadata"]:

                created = key["CreateDate"]

                age = (
                    datetime.now(timezone.utc) - created
                ).days

                print(
                    f"Access Key ID : "
                    f"{key['AccessKeyId']}"
                )

                print(
                    f"Created       : "
                    f"{created.date()}"
                )

                print(
                    f"Age           : "
                    f"{age} days"
                )

                if age > 90:

                    print(
                        "❌ WARNING: Access key "
                        "is older than 90 days."
                    )

                    self.add_finding(
                        username,
                        "OLD_ACCESS_KEY",
                        "MEDIUM",
                        f"Access key is {age} days old."
                    )

                else:

                    print(
                        "✅ Access key is within "
                        "the recommended age."
                    )

    # ---------------------------------------------------------
    # 4. CHECK ADMINISTRATOR ACCESS
    # ---------------------------------------------------------
    def check_admin_access(self):

        response = self.iam.list_users()

        print("\n" + "=" * 50)
        print("ADMINISTRATIVE ACCESS AUDIT")
        print("=" * 50)

        for user in response["Users"]:

            username = user["UserName"]

            policies = (
                self.iam.list_attached_user_policies(
                    UserName=username
                )
            )

            admin_found = False

            print(f"\nUser: {username}")

            for policy in policies["AttachedPolicies"]:

                policy_name = policy["PolicyName"]

                print(
                    f"Policy: {policy_name}"
                )

                if policy_name == "AdministratorAccess":

                    admin_found = True

            if admin_found:

                print(
                    "❌ HIGH RISK: "
                    "AdministratorAccess detected."
                )

                self.add_finding(
                    username,
                    "ADMINISTRATOR_ACCESS",
                    "CRITICAL",
                    "User has AdministratorAccess."
                )

            else:

                print(
                    "✅ No AdministratorAccess "
                    "detected."
                )

    # ---------------------------------------------------------
    # 5. CHECK WILDCARD PERMISSIONS
    # ---------------------------------------------------------
    def check_wildcard_permissions(self):

        response = self.iam.list_users()

        print("\n" + "=" * 50)
        print("WILDCARD PERMISSION AUDIT")
        print("=" * 50)

        for user in response["Users"]:

            username = user["UserName"]

            print(f"\nUser: {username}")

            policies = (
                self.iam.list_attached_user_policies(
                    UserName=username
                )
            )

            for policy in policies["AttachedPolicies"]:

                policy_name = policy["PolicyName"]
                policy_arn = policy["PolicyArn"]

                print(
                    f"\nChecking policy: "
                    f"{policy_name}"
                )

                try:

                    policy_info = self.iam.get_policy(
                        PolicyArn=policy_arn
                    )

                    default_version_id = (
                        policy_info["Policy"]
                        ["DefaultVersionId"]
                    )

                    policy_version = (
                        self.iam.get_policy_version(
                            PolicyArn=policy_arn,
                            VersionId=default_version_id
                        )
                    )

                    document = (
                        policy_version["PolicyVersion"]
                        ["Document"]
                    )

                    if isinstance(document, str):

                        document = unquote(document)

                    statements = document.get(
                        "Statement",
                        []
                    )

                    if isinstance(
                        statements,
                        dict
                    ):

                        statements = [statements]

                    dangerous_action_found = False

                    for statement in statements:

                        effect = statement.get(
                            "Effect"
                        )

                        action = statement.get(
                            "Action"
                        )

                        resource = statement.get(
                            "Resource"
                        )

                        if effect != "Allow":

                            continue

                        if isinstance(
                            action,
                            str
                        ):

                            actions = [action]

                        else:

                            actions = action or []

                        if isinstance(
                            resource,
                            str
                        ):

                            resources = [resource]

                        else:

                            resources = resource or []

                        if "*" in actions:

                            dangerous_action_found = True

                            print(
                                "❌ HIGH RISK: "
                                "Full wildcard Action detected."
                            )

                            print(
                                f"   Action: {actions}"
                            )

                            print(
                                f"   Resource: {resources}"
                            )

                            self.add_finding(
                                username,
                                "WILDCARD_ACTION",
                                "CRITICAL",
                                (
                                    f"Policy {policy_name} "
                                    f"allows Action: *"
                                )
                            )

                    if not dangerous_action_found:

                        print(
                            "✅ No full wildcard "
                            "Actions detected."
                        )

                except Exception as error:

                    print(
                        f"⚠️ Could not inspect "
                        f"policy: {error}"
                    )

    # ---------------------------------------------------------
    # 6. GENERATE JSON REPORT
    # ---------------------------------------------------------
    def generate_report(self):

        report_directory = Path("reports")

        report_directory.mkdir(
            exist_ok=True
        )

        total_users = len(
            self.iam.list_users()["Users"]
        )

        mfa_issues = sum(
            1
            for finding in self.findings
            if finding["issue"] == "MFA_NOT_ENABLED"
        )

        old_access_keys = sum(
            1
            for finding in self.findings
            if finding["issue"] == "OLD_ACCESS_KEY"
        )

        admin_users = sum(
            1
            for finding in self.findings
            if finding["issue"]
            == "ADMINISTRATOR_ACCESS"
        )

        wildcard_users = sum(
            1
            for finding in self.findings
            if finding["issue"]
            == "WILDCARD_ACTION"
        )

        report = {

            "scan_date": datetime.now(
                timezone.utc
            ).isoformat(),

            "summary": {

                "total_users": total_users,

                "mfa_issues": mfa_issues,

                "old_access_keys": old_access_keys,

                "admin_users": admin_users,

                "wildcard_users": wildcard_users,

                "total_findings": len(
                    self.findings
                )
            },

            "findings": self.findings
        }

        report_path = (
            report_directory
            / "iam_security_report.json"
        )

        with open(
            report_path,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                report,
                file,
                indent=4
            )

        print("\n" + "=" * 50)
        print("SECURITY REPORT")
        print("=" * 50)

        print(
            f"Report saved to: {report_path}"
        )

        print(
            f"Total users: {total_users}"
        )

        print(
            f"Total findings: "
            f"{len(self.findings)}"
        )

        print(
            f"MFA issues: "
            f"{mfa_issues}"
        )

        print(
            f"Old access keys: "
            f"{old_access_keys}"
        )

        print(
            f"Administrator users: "
            f"{admin_users}"
        )

        print(
            f"Wildcard findings: "
            f"{wildcard_users}"
        )


# ---------------------------------------------------------
# PROGRAM START
# ---------------------------------------------------------

if __name__ == "__main__":

    auditor = IAMAuditor()

    auditor.list_users()

    auditor.check_mfa()

    auditor.check_access_keys()

    auditor.check_admin_access()

    auditor.check_wildcard_permissions()

    auditor.generate_report()