import boto3
import time
import os
import json

athena = boto3.client('athena')

# --- CONFIGURATION MAPPING ---
# This maps the "URL Path" (from API Gateway) to your "Athena Database" & "Table"
# You might need to adjust the 'table' names if they differ from your DB name.
RESOURCE_MAP = {
    '/logs/cloudtrail': { 
        'db': 'security_logs', 
        'table': 'processed_cloudtrail'     # REPLACE with actual table name
    },
    '/logs/guardduty': { 
        'db': 'security_logs', 
        'table': 'processed_guardduty'
    },
    '/logs/vpc': { 
        'db': 'security_logs', 
        'table': 'vpc_logs'
    },
    '/logs/eni_logs':{
        'db': 'security_logs',
        'table': 'eni_flow_logs'
    }
}

# --- CRITICAL FIX: ALWAYS USE THE RESULTS BUCKET ---
# Do not try to write results into the evidence buckets.
OUTPUT_BUCKET = f"athena-query-results-{self.account}-{self.region}"

def lambda_handler(event, context):
    print("Received event:", json.dumps(event)) 
    
    resource_path = event.get('resource') 
    config = RESOURCE_MAP.get(resource_path)
    
    if not config:
         return api_response(400, {'error': f'Unknown resource path: {resource_path}'})

    database_name = config['db']
    table_name = config['table']

    query_params = event.get('queryStringParameters', {}) or {}
    
    # Select specific columns based on table type
    if config['table'] == 'processed_cloudtrail':
        query_string = f"""SELECT * FROM {table_name} 
        where "date" >= cast((current_date - interval '3' day) as varchar)
        limit 100"""
        
    elif config['table'] == 'processed_guardduty':
        query_string = f"""SELECT * FROM {table_name} 
        WHERE cast(from_iso8601_timestamp(event_last_seen) as date) >= (current_date - interval '7' day)
        ORDER BY event_last_seen DESC"""

    elif config['table'] == 'vpc_logs':
        query_string = f"""SELECT * FROM {table_name}
        where "date" >= cast((current_date - interval '3' day) as varchar)
        limit 100"""

    elif config['table'] == 'eni_flow_logs':
        query_string = f"""SELECT * FROM {table_name} 
        where "date" >= cast((current_date - interval '3' day) as varchar)
        limit 100"""

    print(f"Querying DB: {database_name}, Table: {table_name}, Output: {OUTPUT_BUCKET}")
    
    try:
        # Start Query
        # We explicitly use the 'primary' workgroup. If you use a custom one, add WorkGroup='name' below.
        response = athena.start_query_execution(
            QueryString=query_string,
            QueryExecutionContext={'Database': database_name},
            ResultConfiguration={'OutputLocation': OUTPUT_BUCKET}
        )
        query_execution_id = response['QueryExecutionId']
        
        # Wait for results (Simple Polling)
        status = 'RUNNING'
        while status in ['RUNNING', 'QUEUED']:
            response = athena.get_query_execution(QueryExecutionId=query_execution_id)
            status = response['QueryExecution']['Status']['State']
            
            if status in ['FAILED', 'CANCELLED']:
                reason = response['QueryExecution']['Status'].get('StateChangeReason', 'Unknown')
                return api_response(500, {'error': f'Query Failed: {reason}'})
            
            time.sleep(1) 
            
        results = athena.get_query_results(QueryExecutionId=query_execution_id)
        return api_response(200, results)
        
    except Exception as e:
        print(f"Error: {str(e)}") 
        return api_response(500, {'error': str(e)})

def api_response(code, body):
    return {
        "statusCode": code,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, OPTIONS"
        },
        "body": json.dumps(body)
    }