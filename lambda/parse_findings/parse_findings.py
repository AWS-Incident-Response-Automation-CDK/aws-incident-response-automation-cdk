import json
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    instance_ids = []
    
    detail = event.get('detail', {})
    
    region = event.get('region') or detail.get('region') or 'ap-southeast-1'
    
    instance_id_primary = detail.get('resource', {}).get('instanceDetails', {}).get('instanceId')
    if instance_id_primary:
        instance_ids.append(instance_id_primary)

    # --- 2. Extract from the older/secondary 'resources' array structure ---
    for r in detail.get("resources", []):
        if r.get("type") == "AwsEc2Instance":
            id_from_details = r.get('details', {}).get('instanceId')
            
            if id_from_details:
                instance_ids.append(id_from_details)
            else:
                arn_id = r.get('id')
                if arn_id and arn_id.startswith('arn:aws:ec2:'):
                    instance_ids.append(arn_id.split('/')[-1])
    
    unique_instance_ids = list(set([id for id in instance_ids if id]))
    
    return {
        "InstanceIds": unique_instance_ids, 
        "Region": region
    }