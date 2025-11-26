import json
import os
import boto3
import gzip
from datetime import datetime
from urllib.parse import unquote_plus
from io import BytesIO

s3_client = boto3.client('s3')
glue_client = boto3.client('glue')

DATABASE_NAME = os.environ.get('DATABASE_NAME')
TABLE_NAME = os.environ.get('TABLE_NAME')
S3_LOCATION = os.environ.get('S3_LOCATION')
DESTINATION_BUCKET = os.environ.get('DESTINATION_BUCKET')

def add_partition(date_str):
    year, month, day = date_str.split('-')
    
    try:
        glue_client.create_partition(
            DatabaseName=DATABASE_NAME,
            TableName=TABLE_NAME,
            PartitionInput={
                'Values': [year, month, day],
                'StorageDescriptor': {
                    'Location': f'{S3_LOCATION}year={year}/month={month}/day={day}/',
                    'InputFormat': 'org.apache.hadoop.mapred.TextInputFormat',
                    'OutputFormat': 'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat',
                    'SerdeInfo': {
                        'SerializationLibrary': 'org.openx.data.jsonserde.JsonSerDe',
                        'Parameters': {'serialization.format': '1'}
                    }
                }
            }
        )
        print(f"Added partition for {date_str}")
    except glue_client.exceptions.AlreadyExistsException:
        print(f"Partition for {date_str} already exists")
    except Exception as e:
        # Removed the specific "Table is projected" check
        print(f"Error adding partition for {date_str}: {str(e)}")

def normalize_user_identity(user_identity):
    if not user_identity:
        return {
            'type': None, 'invokedby': None, 'principalid': None, 'arn': None, 
            'accountid': None, 'accesskeyid': None, 'username': None, 
            'sessioncontext': {'attributes': {}, 'sessionissuer': {'type': None, 'principalid': None, 'arn': None, 'accountid': None, 'username': None}},
            'inscopeof': {'issuertype': None, 'credentialsissuedto': None}
        }

    session_context = user_identity.get('sessionContext') or {}
    in_scope_of = user_identity.get('inScopeOf') or {}
    
    session_issuer = session_context.get('sessionIssuer') or {}
    normalized_session_issuer = {
        'type': session_issuer.get('type'),
        'principalid': session_issuer.get('principalId'),
        'arn': session_issuer.get('arn'),
        'accountid': session_issuer.get('accountId'),
        'username': session_issuer.get('userName')
    }

    normalized_session_context = {
        'attributes': session_context.get('attributes', {}) or {}, 
        'sessionissuer': normalized_session_issuer
    }
    
    normalized_in_scope_of = {
        'issuertype': in_scope_of.get('issuerType'),
        'credentialsissuedto': in_scope_of.get('credentialsIssuedTo')
    }

    return {
        'type': user_identity.get('type'),
        'invokedby': user_identity.get('invokedBy'),
        'principalid': user_identity.get('principalId'),
        'arn': user_identity.get('arn'),
        'accountid': user_identity.get('accountId'),
        'accesskeyid': user_identity.get('accessKeyId'),
        'username': user_identity.get('userName'),
        'sessioncontext': normalized_session_context,
        'inscopeof': normalized_in_scope_of
    }

def extract_and_promote_ir_fields(record):
    request_params = record.get('requestParameters') or {} 
    response_elements = record.get('responseElements') or {}
    user_identity = record.get('userIdentity') or {}

    return {
        'target_bucket': request_params.get('bucketName'),
        'target_key': request_params.get('key'),
        'target_username': request_params.get('userName'),
        'target_rolename': request_params.get('roleName'),
        'target_policyname': request_params.get('policyName'),
        'new_access_key': response_elements.get('accessKeyId'),
        'new_instance_id': response_elements.get('instanceId'),
        'target_group_id': request_params.get('groupId'),
        'identity_principalid': user_identity.get('principalId'),
    }


def process_cloudtrail_log(bucket, key):
    
    response = s3_client.get_object(Bucket=bucket, Key=key)
    
    if key.endswith('.gz'):
        content = gzip.decompress(response['Body'].read())
    else:
        content = response['Body'].read()
    
    log_data = json.loads(content.decode('utf-8'))
    
    processed_events = []
    
    for record in log_data.get('Records', []):
        
        user_identity_data = record.get('userIdentity') or {}
        
        ir_fields = extract_and_promote_ir_fields(record)
        
        raw_request_params = record.get('requestParameters') or {}
        raw_response_elements = record.get('responseElements') or {}
        raw_service_event_details = record.get('serviceEventDetails') or {}
        
        request_params_str = json.dumps(raw_request_params)
        response_elements_str = json.dumps(raw_response_elements)
        service_event_details_str = json.dumps(raw_service_event_details)
        
        processed_event = {
            'eventTime': record.get('eventTime'),
            'eventName': record.get('eventName'),
            'eventSource': record.get('eventSource'),
            'awsRegion': record.get('awsRegion'),
            'sourceIPAddress': record.get('sourceIPAddress'),
            'userAgent': record.get('userAgent'),
            
            'userIdentity': normalize_user_identity(user_identity_data),
            
            'requestParameters': request_params_str,
            'responseElements': response_elements_str,
            
            'resources': record.get('resources', []),
            'recipientAccountId': record.get('recipientAccountId'),
            'serviceEventDetails': service_event_details_str, 
            'errorCode': record.get('errorCode'),
            'errorMessage': record.get('errorMessage'),

            
            'date': record.get('eventTime', '')[:10] if record.get('eventTime') else '',
            'hour': record.get('eventTime', '')[11:13] if record.get('eventTime') else '',
            'userType': user_identity_data.get('type', ''),
            'userName': extract_user_name(user_identity_data),
            'isConsoleLogin': record.get('eventName') == 'ConsoleLogin',
            'isFailedLogin': record.get('eventName') == 'ConsoleLogin' and record.get('errorMessage'),
            'isRootUser': user_identity_data.get('type') == 'Root',
            'isAssumedRole': user_identity_data.get('type') == 'AssumedRole',
            
            'isHighRiskEvent': is_high_risk_event(record),
            'isPrivilegedAction': is_privileged_action(record.get('eventName', '')),
            'isDataAccess': is_data_access_event(record.get('eventName', '')),

            **ir_fields
        }
        
        processed_events.append(processed_event)
    
    return processed_events

def extract_user_name(user_identity):
    if not user_identity:
        return ''
    
    user_type = user_identity.get('type', '')
    
    if user_type == 'IAMUser':
        return user_identity.get('userName', '')
    elif user_type == 'AssumedRole':
        arn = user_identity.get('arn', '')
        if arn and ':assumed-role/' in arn:
            return arn.split(':assumed-role/')[-1].split('/')[0]
        return arn.split('/')[-1] if arn else ''
    elif user_type == 'Root':
        return 'root'
    elif user_type == 'SAMLUser':
        return user_identity.get('userName', '')
    else:
        return user_identity.get('principalId', '')

def is_high_risk_event(record):
    event_name = record.get('eventName', '')
    user_identity = record.get('userIdentity', {})
    
    high_risk_events = [
        'ConsoleLogin', 'AssumeRole', 'CreateUser', 'DeleteUser', 'AttachUserPolicy', 
        'DetachUserPolicy', 'CreateRole', 'DeleteRole', 'PutBucketPolicy', 
        'DeleteBucket', 'CreateAccessKey', 'DeleteAccessKey', 'ModifyDBInstance',
        'AuthorizeSecurityGroupIngress', 'RevokeSecurityGroupIngress', 
        'RunInstances', 'TerminateInstances'
    ]
    
    if event_name in high_risk_events:
        return True
    
    if record.get('errorCode') or record.get('errorMessage'):
        return True
    
    if user_identity.get('type') == 'Root':
        return True
    
    return False

def is_privileged_action(event_name):
    privileged_actions = [
        'CreateUser', 'DeleteUser', 'CreateRole', 'DeleteRole',
        'AttachUserPolicy', 'DetachUserPolicy', 'PutUserPolicy',
        'CreateAccessKey', 'DeleteAccessKey', 'UpdateAccessKey',
        'CreateGroup', 'DeleteGroup', 'AddUserToGroup',
        'RemoveUserFromGroup', 'CreatePolicy', 'DeletePolicy'
    ]
    
    return event_name in privileged_actions

def is_data_access_event(event_name):
    data_events = [
        'GetObject', 'PutObject', 'DeleteObject',
        'GetItem', 'PutItem', 'DeleteItem', 'Query', 'Scan'
    ]
    
    return event_name in data_events

def save_processed_data(processed_events, source_key):
    
    if not processed_events:
        return

    first_event = processed_events[0]
    date_str = first_event.get('date', datetime.now().strftime('%Y-%m-%d'))
    
    original_filename = source_key.split('/')[-1].replace('.json.gz', '').replace('.json', '')
    
    output_key = f"processed-cloudtrail/year={date_str[:4]}/month={date_str[5:7]}/day={date_str[8:10]}/{original_filename}_processed.jsonl.gz"

    json_lines = ""

    for event in processed_events:
        json_lines += json.dumps(event) + "\n"

    compressed_data = gzip.compress(json_lines.encode('utf-8'))

    s3_client.put_object(
        Bucket=DESTINATION_BUCKET,
        Key=output_key,
        Body=compressed_data,
        ContentType='application/json',
        ContentEncoding='gzip'
    )
    
    print(f"Saved processed data to: s3://{DESTINATION_BUCKET}/{output_key}")
    
    add_partition(date_str)


def lambda_handler(event, context):

    for record in event['Records']:
        bucket = record['s3']['bucket']['name']
        key = unquote_plus(record['s3']['object']['key'])
        
        print(f"Processing CloudTrail log: s3://{bucket}/{key}")
        
        try:
            processed_events = process_cloudtrail_log(bucket, key)
            
            save_processed_data(processed_events, key) 
            
            print(f"Successfully processed {len(processed_events)} events from {key}")
            
        except Exception as e:
            print(f"Error processing {key}: {str(e)}")
            raise e 
    
    return {
        'statusCode': 200,
        'body': json.dumps('CloudTrail logs processed successfully')
    }