import json
import boto3
import gzip
import os
from datetime import datetime
from urllib.parse import unquote_plus

s3_client = boto3.client('s3')
glue_client = boto3.client('glue') 

DATABASE_NAME = os.environ.get("DATABASE_NAME", "security_logs")
TABLE_NAME_GUARDDUTY = os.environ.get("TABLE_NAME_GUARDDUTY", "processed_guardduty")
S3_LOCATION_GUARDDUTY = os.environ.get("S3_LOCATION_GUARDDUTY", "s3://vel-processed-guardduty/processed-guardduty/")
DESTINATION_BUCKET = os.environ.get("DESTINATION_BUCKET", "vel-processed-guardduty")

def add_partition_guardduty(year, month, day, type_partition):
    
    try:
        glue_client.create_partition(
            DatabaseName=DATABASE_NAME,
            TableName=TABLE_NAME_GUARDDUTY,
            PartitionInput={
                'Values': [type_partition, year, month, day], 
                'StorageDescriptor': {
                    'Location': (
                        f"{S3_LOCATION_GUARDDUTY}type={type_partition}/"
                        f"year={year}/month={month}/day={day}/"
                    ),
                    'InputFormat': 'org.apache.hadoop.mapred.TextInputFormat',
                    'OutputFormat': 'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat',
                    'SerdeInfo': {
                        'SerializationLibrary': 'org.openx.data.jsonserde.JsonSerDe',
                        'Parameters': {'serialization.format': '1'}
                    }
                }
            }
        )
        print(f"Added GuardDuty partition for {type_partition}/{year}-{month}-{day}")
    except glue_client.exceptions.AlreadyExistsException:
        print(f"GuardDuty partition for {type_partition}/{year}-{month}-{day} already exists")
    except Exception as e:
        print(f"Error adding GuardDuty partition for {type_partition}/{year}-{month}-{day}: {str(e)}")

def promote_network_details(finding_service):
    if not finding_service: return {}
    action = finding_service.get('action', {})
    net_conn_action = action.get('networkConnectionAction', {})
    if net_conn_action:
        remote_ip = net_conn_action.get('remoteIpDetails', {}).get('ipAddressV4') or \
                    net_conn_action.get('remoteIpDetails', {}).get('ipAddressV6')
        return {
            'remote_ip': remote_ip,
            'remote_port': net_conn_action.get('remotePortDetails', {}).get('port'),
            'connection_direction': net_conn_action.get('connectionDirection'),
            'protocol': net_conn_action.get('protocol'),
        }
    dns_action = action.get('dnsRequestAction', {})
    if dns_action:
        return {'dns_domain': dns_action.get('domain'), 'dns_protocol': dns_action.get('protocol')}
    port_probe_action = action.get('portProbeAction', {})
    if port_probe_action and port_probe_action.get('portProbeDetails'):
        detail = port_probe_action['portProbeDetails'][0]
        return {
            'scanned_ip': detail.get('remoteIpDetails', {}).get('ipAddressV4'),
            'scanned_port': detail.get('localPortDetails', {}).get('port'),
        }
    return {}

def promote_api_details(finding_service):
    if not finding_service: return {}
    action = finding_service.get('action', {})
    aws_api_action = action.get('awsApiCallAction', {})
    if aws_api_action:
        return {
            'aws_api_service': aws_api_action.get('serviceName'),
            'aws_api_name': aws_api_action.get('api'),
            'aws_api_caller_type': aws_api_action.get('callerType'),
            'aws_api_error': aws_api_action.get('errorCode'),
            'aws_api_remote_ip': aws_api_action.get('remoteIpDetails', {}).get('ipAddressV4'),
        }
    return {}

def promote_resource_details(finding_resource):
    if not finding_resource: return {}
    instance_details = finding_resource.get('instanceDetails', {})
    if instance_details:
        return {
            'target_resource_arn': instance_details.get('arn'),
            'instance_id': instance_details.get('instanceId'),
            'resource_region': instance_details.get('awsRegion'),
        }
    access_key_details = finding_resource.get('accessKeyDetails', {})
    if access_key_details:
        return {
            'access_key_id': access_key_details.get('accessKeyId'),
            'principal_id': access_key_details.get('principalId'),
            'user_name': access_key_details.get('userName'),
        }
    s3_details = finding_resource.get('s3BucketDetails', [])
    if s3_details:
        return {
            'target_resource_arn': s3_details[0].get('arn'),
            's3_bucket_name': s3_details[0].get('name'),
        }
    return {}

def process_guardduty_log(bucket, key):
    response = s3_client.get_object(Bucket=bucket, Key=key)
    if key.endswith('.gz'):
        content = gzip.decompress(response['Body'].read()).decode('utf-8')
    else:
        content = response['Body'].read().decode('utf-8')
        
    processed_findings = []
    for line in content.splitlines():
        if not line: continue
        try:
            finding = json.loads(line)
        except json.JSONDecodeError:
            print(f"Skipping malformed JSON line in {key}"); continue

        finding_type = finding.get('type', 'UNKNOWN')
        finding_service = finding.get('service', {})
        
        network_fields = promote_network_details(finding_service)
        api_fields = promote_api_details(finding_service)
        resource_fields = promote_resource_details(finding.get('resource', {}))
        
        created_at_str = finding.get('createdAt')
        event_last_seen_str = finding_service.get('eventLastSeen')

        dt_obj = datetime.now()
        if created_at_str:
            try:
                dt_obj = datetime.strptime(created_at_str, '%Y-%m-%dT%H:%M:%S.%fZ')
            except ValueError:
                try: dt_obj = datetime.strptime(created_at_str, '%Y-%m-%dT%H:%M:%SZ')
                except ValueError: pass

        year = dt_obj.strftime('%Y')
        month = dt_obj.strftime('%m')
        day = dt_obj.strftime('%d')
        type_partition = finding_type.replace(':', '_').replace('/', '_') 
        
        processed_record = {
            'finding_id': finding.get('id'), 'finding_type': finding_type,
            'title': finding.get('title'), 'severity': finding.get('severity'),
            'account_id': finding.get('accountId'), 'region': finding.get('region'),
            'created_at': created_at_str,
            'event_last_seen': event_last_seen_str,
            **network_fields, **api_fields, **resource_fields,
            'date': dt_obj.strftime('%Y-%m-%d'), 
            'year': year, 'month': month, 'day': day, 'type_partition': type_partition,
            'service_raw': json.dumps(finding_service), 'resource_raw': json.dumps(finding.get('resource', {})),
            'metadata_raw': json.dumps(finding.get('metadata', {})),
        }
        processed_findings.append(processed_record)
    return processed_findings

def save_processed_data(processed_events, source_key):
    
    if not processed_events:
        return
    
    first_event = processed_events[0]
    
    year = first_event.get('year', '0000')
    month = first_event.get('month', '00')
    day = first_event.get('day', '00')
    type_partition = first_event.get('type_partition', 'other')
    
    original_filename = source_key.split('/')[-1].replace('.gz', '').replace('.json', '')
    
    output_key = (
        f"processed-guardduty/type={type_partition}/"
        f"year={year}/month={month}/day={day}/"
        f"{original_filename}_processed.jsonl"
    )
    
    KEYS_TO_REMOVE = ['year', 'month', 'day', 'type_partition']
    
    json_lines = ""
    for event in processed_events:
        event_to_dump = event.copy()
        for key_to_remove in KEYS_TO_REMOVE:
            event_to_dump.pop(key_to_remove, None) 
            
        json_lines += json.dumps(event_to_dump) + "\n"
    compressed_data = gzip.compress(json_lines.encode('utf-8'))

    s3_client.put_object(
        Bucket=DESTINATION_BUCKET,
        Key=output_key,
        Body=compressed_data,
        ContentType='application/jsonl',
        ContentEncoding='gzip'
    )
    
    print(f"Saved processed data to: s3://{DESTINATION_BUCKET}/{output_key}")
    
    add_partition_guardduty(year, month, day, type_partition)


def lambda_handler(event, context):

    for record in event['Records']:
        bucket = record['s3']['bucket']['name']
        key = unquote_plus(record['s3']['object']['key'])
        
        print(f"Processing GuardDuty finding file: s3://{bucket}/{key}")
        
        try:
            processed_findings = process_guardduty_log(bucket, key)
            save_processed_data(processed_findings, key) # This now calls add_partition_guardduty
            print(f"Successfully processed {len(processed_findings)} findings from {key}")
            
        except Exception as e:
            print(f"Error processing {key}: {str(e)}")
            raise e
    
    return {
        'statusCode': 200,
        'body': json.dumps('GuardDuty findings processed successfully')
    }