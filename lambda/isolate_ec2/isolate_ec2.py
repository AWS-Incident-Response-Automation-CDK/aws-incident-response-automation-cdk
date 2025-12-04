import json
import boto3
import os
from botocore.exceptions import ClientError 

ISOLATION_SG_ID = os.getenv('ISOLATION_SG_ID') 

def lambda_handler(event, context):
    print("=== ISOLATE EVENT RECEIVED ===")
    print(json.dumps(event, indent=2))
    
    instance_id = event.get('InstanceId')
    region = event.get('Region', 'ap-southeast-1')

    if not instance_id or not ISOLATION_SG_ID:
        print("[ERROR] Missing InstanceId or IsolationSGId in input. Cannot isolate.")
        return {"status": "isolation_failed", "InstanceId": instance_id, "error": "Missing input data"}

    try:
        ec2 = boto3.client('ec2', region_name=region)

        response = ec2.describe_instances(InstanceIds=[instance_id])
        instance = response['Reservations'][0]['Instances'][0]
        current_sgs = [sg['GroupId'] for sg in instance.get('SecurityGroups', [])]

        if ISOLATION_SG_ID in current_sgs:
            print(f"[INFO] {instance_id} already has isolation SG {ISOLATION_SG_ID}")
            return {
                **event,
                "status": "already_isolated",
                "InstanceId": instance_id,
                "Region": region,
                "IsolationSG": None
            }

        print(f"[ACTION] Isolating {instance_id} in {region} with SG {ISOLATION_SG_ID}")
        
        ec2.modify_instance_attribute(
            InstanceId=instance_id,
            Groups=[ISOLATION_SG_ID]
        )
        
        print(f"[SUCCESS] {instance_id} isolated with SG {ISOLATION_SG_ID}")
        
        return {
            **event,
            "status": "isolation_complete", 
            "InstanceId": instance_id,
            "Region": region,
            "IsolationSG": ISOLATION_SG_ID
        }

    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code')
        print(f"[ERROR] Isolation FAILED for {instance_id} ({error_code}): {str(e)}")
        
        return {
            "status": "isolation_failed", 
            "InstanceId": instance_id, 
            "error": str(e)
        }

    except Exception as e:
        print(f"[ERROR] Isolation FAILED (General) for {instance_id}: {str(e)}")
        raise e