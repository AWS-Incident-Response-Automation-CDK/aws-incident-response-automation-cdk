import json
import boto3
import gzip
import os
from datetime import datetime

s3 = boto3.client("s3")
glue = boto3.client("glue")

# --------------------------------------------------
# CONFIGURATION
# --------------------------------------------------

DEST_BUCKET = os.environ.get("DEST_BUCKET") 
DATABASE_NAME = os.environ.get("DATABASE_NAME")
TABLE_NAME = os.environ.get("TABLE_NAME")

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


def ensure_partition(partition_value):
    try:
        glue.get_partition(
            DatabaseName=DATABASE_NAME, 
            TableName=TABLE_NAME, 
            PartitionValues=[partition_value]
        )
        return
    except glue.exceptions.EntityNotFoundException:
        pass

    glue.create_partition(
        DatabaseName=DATABASE_NAME,
        TableName=TABLE_NAME,
        PartitionInput={
            "Values": [partition_value],
            "StorageDescriptor": {
                "Location": f"s3://{DEST_BUCKET}/eni-flow-logs/partition_date={partition_value}/",
                "InputFormat": "org.apache.hadoop.mapred.TextInputFormat",
                "OutputFormat": "org.apache.hadoop.hive.ql.io.IgnoreKeyTextOutputFormat",
                "SerdeInfo": {"SerializationLibrary": "org.openx.data.jsonserde.JsonSerDe"},
            }
        }
    )
    print("Created partition:", partition_value)

# -------------------------- PARSE LOGIC (ĐÃ SỬA) --------------------------

def parse_flow_log_line(line):
    parts = line.strip().split(' ')
    
    # Flow Log V2 tiêu chuẩn thường có 14 trường
    if len(parts) < 14:
        return None

    try:
        # [REVIEW]: Lấy Start Time (cột index 10) để tính ra ngày Partition
        start_timestamp = safe_int(parts[10])
        
        if start_timestamp:
            dt_object = datetime.fromtimestamp(start_timestamp)
            time_str = dt_object.strftime('%Y-%m-%d %H:%M:%S')
            date_part = dt_object.strftime('%Y-%m-%d') # Ví dụ: 2025-10-20
        else:
            time_str = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
            date_part = datetime.utcnow().strftime('%Y-%m-%d')

        record = {
            # [REVIEW]: MAP CHÍNH XÁC VỊ TRÍ CỘT
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
            "timestamp_str": time_str,
            "partition_date_value": date_part    # Trường tạm để tạo partition folder
        }
        return record
    except Exception as e:
        print(f"Error parsing line: {e}")
        return None

# ----------------------------- MAIN LAMBDA -----------------------------

def lambda_handler(event, context):
    print("Event received")
    
    if "Records" not in event:
        return {"statusCode": 400, "body": "Invalid event"}

    processed_count = 0
    
    for record in event["Records"]:
        bucket = record["s3"]["bucket"]["name"]
        key = record["s3"]["object"]["key"]

        # Chỉ xử lý file .gz
        if key.endswith(".gz"): 
            print(f"Processing file: {key}")
            original_filename = os.path.basename(key)
            new_filename = f"eni-{original_filename.replace('.gz', '.jsonl.gz')}"

            # 1. Đọc dữ liệu
            text_content = read_gz(bucket, key)
            
            # 2. Parse từng dòng
            parsed_records = []
            partition_date = None

            for line in text_content.splitlines():
                rec = parse_flow_log_line(line)
                if rec:
                    # Lấy ngày của bản ghi đầu tiên làm ngày cho partition của file này
                    if partition_date is None:
                        partition_date = rec["partition_date_value"]
                    
                    # Xóa trường tạm trước khi lưu vào JSON
                    del rec["partition_date_value"]
                    parsed_records.append(rec)
            
            if not parsed_records:
                print(f"No valid records in {key}")
                continue

            # Fallback nếu không parse được ngày
            if not partition_date:
                partition_date = datetime.utcnow().strftime('%Y-%m-%d')
            
            # 3. Upload file kết quả vào đúng partition
            # JSON Lines format
            json_body = "\n".join(json.dumps(r) for r in parsed_records)
            compressed_body = gzip.compress(json_body.encode("utf-8"))
            
            # [REVIEW]: Folder đích sẽ là: partition_date=2025-10-20/...
            dest_key = f"eni-flow-logs/partition_date={partition_date}/{new_filename}"
            
            s3.put_object(
                Bucket=DEST_BUCKET,
                Key=dest_key,
                Body=compressed_body,
                ContentType="application/x-ndjson",
                ContentEncoding="gzip"
            )
            print(f"--> Uploaded: {dest_key}")

            # 4. Cập nhật Glue Catalog
            ensure_partition(partition_date)
            
            processed_count += 1
        else:
            print(f"Skipping file: {key}")

    return {
        "statusCode": 200,
        "body": json.dumps(f"Processed {processed_count} files.")
    }