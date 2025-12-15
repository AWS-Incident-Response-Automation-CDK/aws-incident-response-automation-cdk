import json
import boto3
import os
from botocore.exceptions import ClientError 

QUARANTINE_SG_MAP_JSON = os.getenv('QUARANTINE_SG_MAP')

if QUARANTINE_SG_MAP_JSON:
    QUARANTINE_SG_MAP = json.loads(QUARANTINE_SG_MAP_JSON)
else:
    QUARANTINE_SG_MAP = {}
    print("[WARNING] QUARANTINE_SG_MAP environment variable is missing or empty.")


def lambda_handler(event, context):
    print("=== ISOLATE EVENT RECEIVED ===")
    print(json.dumps(event, indent=2))
    
    instance_id = event.get('InstanceId')
    region = event.get('Region', 'ap-southeast-1')
    target_sg_id = None

    if not instance_id:
        print("[ERROR] Missing InstanceId in input. Cannot proceed.")
        return {"status": "isolation_failed", "InstanceId": None, "error": "Missing InstanceId"}

    try:
        ec2_client = boto3.client('ec2', region_name=region)

        response = ec2_client.describe_instances(InstanceIds=[instance_id])
        reservations = response.get('Reservations')
        
        if not reservations or not reservations[0].get('Instances'):
            print(f"[ERROR] Instance {instance_id} not found.")
            return {"status": "isolation_failed", "InstanceId": instance_id, "error": "Instance not found"}
            
        instance = reservations[0]['Instances'][0]
        vpc_id = instance.get('VpcId')
        current_sgs = [sg['GroupId'] for sg in instance.get('SecurityGroups', [])]
        
        if not vpc_id:
            print(f"[WARNING] Instance {instance_id} is not in a VPC. Assuming isolation is not possible/needed.")
            return {
                **event,
                "status": "not_vpc_instance",
                "InstanceId": instance_id,
                "Region": region
            }

        target_sg_id = QUARANTINE_SG_MAP.get(vpc_id)

        if not target_sg_id:
            print(f"[ERROR] No Quarantine Security Group found for VPC {vpc_id} in the map.")
            return {"status": "isolation_failed", "InstanceId": instance_id, "error": f"No isolation SG defined for VPC {vpc_id}"}
        
        if target_sg_id in current_sgs:
            print(f"[INFO] {instance_id} already has isolation SG {target_sg_id}")
            return {
                **event,
                "status": "already_isolated",
                "InstanceId": instance_id,
                "Region": region,
                "IsolationSG": target_sg_id
            }

        print(f"[ACTION] Isolating {instance_id} in {region} (VPC: {vpc_id}) with SG {target_sg_id}")
        
        ec2_client.modify_instance_attribute(
            InstanceId=instance_id,
            Groups=[target_sg_id]
        )
        
        print(f"[SUCCESS] {instance_id} isolated with SG {target_sg_id}")
        
        return {
            **event,
            "status": "isolation_complete", 
            "InstanceId": instance_id,
            "Region": region,
            "IsolationSG": target_sg_id
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