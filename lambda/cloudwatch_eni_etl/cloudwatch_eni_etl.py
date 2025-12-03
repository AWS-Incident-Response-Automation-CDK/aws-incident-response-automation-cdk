import json
import boto3
import gzip
import os
from datetime import datetime

s3 = boto3.client("s3")
firehose = boto3.client("firehose")

# --------------------------------------------------
# CONFIGURATION
# --------------------------------------------------

FIREHOSE_STREAM_NAME = os.environ.get("FIREHOSE_STREAM_NAME")

# ----------------------------- UTILS -----------------------------

def read_gz(bucket, key):
    obj = s3.get_object(Bucket=bucket, Key=key)
    with gzip.GzipFile(fileobj=obj["Body"]) as f:
        return f.read().decode("utf-8", errors="replace")

def safe_int(x):
    try:
        return int(x)
    except:
        return None


def parse_flow_log_line(line):
    parts = line.strip().split(' ')
    
    if len(parts) < 14:
        return None

    try:
        start_timestamp = safe_int(parts[10])
        time_str = None
        if start_timestamp:
            dt_object = datetime.fromtimestamp(start_timestamp)
            time_str = dt_object.strftime('%Y-%m-%d %H:%M:%S')

        record = {
            "version": safe_int(parts[0]),       # Cột 1: version (int)
            "account_id": parts[1],              # Cột 2: account_id (STRING)
            "interface_id": parts[2],            # Cột 3: eni-...
            "srcaddr": parts[3],
            "dstaddr": parts[4],
            "srcport": safe_int(parts[5]),
            "dstport": safe_int(parts[6]),
            "protocol": safe_int(parts[7]),
            "packets": safe_int(parts[8]),
            "bytes": safe_int(parts[9]),
            "start_time": start_timestamp,       # Cột 11
            "end_time": safe_int(parts[11]),
            "action": parts[12],
            "log_status": parts[13],
            "timestamp_str": time_str
        }
        return record
    except Exception as e:
        print(f"Error parsing line: {e}")
        return None

def lambda_handler(event, context):
    print(f"Received S3 Event. Records: {len(event.get('Records', []))}")
    firehose_records = []

    # Duyệt qua các file S3 gửi về
    for record in event.get("Records", []):
        if "s3" not in record: continue

        bucket = record["s3"]["bucket"]["name"]
        key = record["s3"]["object"]["key"]

        # Chỉ xử lý file .gz
        if not key.endswith(".gz"):
            print(f"Skipping non-gz: {key}")
            continue

        print(f"Processing: {key}")
        
        # Đọc nội dung
        content = read_gz(bucket, key)
        if not content: continue

        # Parse từng dòng log
        for line in content.splitlines():
            rec = parse_flow_log_line(line)
            if not rec: continue

            # Chuyển thành JSON string và thêm xuống dòng (\n)
            json_row = json.dumps(rec) + "\n"
            
            firehose_records.append({'Data': json_row})

    # Đẩy sang Firehose (Batching 500 dòng)
    if firehose_records:
        total = len(firehose_records)
        print(f"Flushing {total} records to Firehose...")
        
        batch_size = 500
        for i in range(0, total, batch_size):
            batch = firehose_records[i:i + batch_size]
            try:
                response = firehose.put_record_batch(
                    DeliveryStreamName=FIREHOSE_STREAM_NAME,
                    Records=batch
                )
                if response['FailedPutCount'] > 0:
                    print(f"Warning: {response['FailedPutCount']} records failed.")
            except Exception as e:
                print(f"Firehose API Error: {e}")

    return {"status": "ok", "count": len(firehose_records)}