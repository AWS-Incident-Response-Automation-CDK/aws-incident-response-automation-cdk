import json
import base64
import gzip
from io import BytesIO
import boto3
import os
import time

s3 = boto3.client('s3')

# --- CONFIGURATION ---
RAW_S3_BUCKET = os.environ.get("DESTINATION_BUCKET")

# The log group pattern constant is no longer used for filtering, but is kept for reference.
# VPC_DNS_LOG_PATTERN = '/aws/route53/query/' 


def is_vpc_dns_log(log_message):
    try:
        json_body = json.loads(log_message.strip())
        if 'query_name' in json_body and 'query_type' in json_body:
            return True
        return False
    except Exception:
        return False


def lambda_handler(event, context):
    try:
        compressed_payload = base64.b64decode(event['awslogs']['data'])
        f = BytesIO(compressed_payload)
        decompressed_data = gzip.GzipFile(fileobj=f).read()
        log_data = json.loads(decompressed_data.decode('utf-8'))
        
        log_lines = []
        for log_event in log_data.get('logEvents', []):
            log_lines.append(log_event.get('message', ''))

        if not log_lines:
            print(f"Batch skipped: No log events found in payload. Log Group: {log_data.get('logGroup')}")
            return {'statusCode': 200, 'body': 'Log batch ignored (No events).'}
        
        is_dns_log = is_vpc_dns_log(log_lines[0])
        
        if is_dns_log:
            key_prefix = 'vpc-dns-logs'
            filename_prefix = 'vpc-' # Add vpc- to the filename
        else:
            key_prefix = 'other-logs'
            filename_prefix = ''      # Keep filename blank for other logs
            
        output_content = '\n'.join(log_lines)
        
        full_log_group_name = log_data.get('logGroup', 'unknown-group')
        log_group_name_safe = full_log_group_name.strip('/').replace('/', '_')
        
        final_filename = f"{filename_prefix}{context.aws_request_id}.gz"
        
        s3_key = f'exportedlogs/{key_prefix}/{log_group_name_safe}/{final_filename}'
        
        buffer = BytesIO()
        with gzip.GzipFile(fileobj=buffer, mode='w') as gz:
            gz.write(output_content.encode('utf-8'))
        
        gzipped_data = buffer.getvalue()

        s3.put_object(
            Bucket=RAW_S3_BUCKET,
            Key=s3_key,
            Body=gzipped_data,
            ContentType='application/x-gzip' 
        )
        
        num_logs = len(log_lines)
        print(f"Exported {num_logs} raw log lines to s3://{RAW_S3_BUCKET}/{s3_key}")
        
        return {'statusCode': 200, 'body': f'Logs exported. {num_logs} events processed. Key Prefix: {key_prefix}'}
        
    except Exception as e:
        print(f"Error in CW Export Lambda: {e}")
        raise e