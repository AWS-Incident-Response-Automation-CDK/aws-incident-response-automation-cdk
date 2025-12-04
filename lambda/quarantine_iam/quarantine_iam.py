import json
import boto3
import os


QUARANTINE_POLICY_ARN = os.environ.get("QUARANTINE_POLICY_ARN")

def lambda_handler(event, context):
    print("=== EVENT RECEIVED ===")
    print(json.dumps(event, indent=2))
    
    try:
        finding = event.get('detail', {})
        user_name = (
            finding.get('resource', {})
                    .get('accessKeyDetails', {})
                    .get('userName')
        )

        if not user_name:
            print("[WARNING] No IAM user found in this finding. Skipping.")
            return {"status": "no_user"}

        print(f"[ACTION] Quarantining IAM User '{user_name}'...")

        iam = boto3.client('iam')

        # Kiểm tra nếu policy đã được gán
        attached_policies = iam.list_attached_user_policies(UserName=user_name)['AttachedPolicies']
        policy_arns = [p['PolicyArn'] for p in attached_policies]

        if QUARANTINE_POLICY_ARN in policy_arns:
            print(f"[INFO] Policy {QUARANTINE_POLICY_ARN} is already attached to user {user_name}.")
        else:
            iam.attach_user_policy(
                UserName=user_name,
                PolicyArn=QUARANTINE_POLICY_ARN
            )
            print(f"[SUCCESS] Policy attached. User {user_name} is now quarantined.")
        
    except Exception as e:
        print(f"[ERROR] Failed to quarantine user: {str(e)}")
        raise e

    return {"status": "processed", "action": "iam_quarantined"}
