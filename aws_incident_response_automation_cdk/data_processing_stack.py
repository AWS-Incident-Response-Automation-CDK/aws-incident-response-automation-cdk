from aws_cdk import (
    Stack,
    Duration,
    aws_glue as glue,
    aws_iam as iam,
    aws_kinesisfirehose as firehose,
    aws_lambda as _lambda,
    aws_logs as logs,
    aws_s3 as s3,
    aws_s3_notifications as s3n,
)
from constructs import Construct

class DataProcessingStack(Stack):

    def __init__(self, scope: Construct, construct_id: str,
                 log_list_bucket,
                 processed_cloudtrail_bucket_name: str,
                 processed_cloudwatch_bucket_name: str,
                 processed_guardduty_bucket_name: str,
                 kms_key_arn: str,
                 ir_log_group_name: str,
                 **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        
        self.log_list_bucket = log_list_bucket
        self.log_list_bucket_name = log_list_bucket.bucket_name
        self.processed_cloudtrail_bucket_name = processed_cloudtrail_bucket_name
        self.processed_cloudwatch_bucket_name = processed_cloudwatch_bucket_name
        self.processed_guardduty_bucket_name = processed_guardduty_bucket_name
        self.kms_key_arn = kms_key_arn
        self.ir_log_group_name = ir_log_group_name

        self._create_glue_database()
        self._create_glue_tables()
        self._create_firehose_streams()
        self._create_etl_functions()
        self._create_cloudwatch_export_lambda()
        self._create_subscription_filter()

    def _create_glue_database(self):
        self.glue_database = glue.CfnDatabase(
            self, "SecurityLogsDatabase",
            catalog_id=self.account,
            database_input=glue.CfnDatabase.DatabaseInputProperty(
                name="security_logs"
            )
        )

    def _create_glue_tables(self):
        # CloudTrail Table
        glue.CfnTable(
            self, "ProcessedCloudTrailTable",
            catalog_id=self.account,
            database_name="security_logs",
            table_input=glue.CfnTable.TableInputProperty(
                name="processed_cloudtrail",
                table_type="EXTERNAL_TABLE",
                parameters={
                    "classification": "json",
                    "compressionType": "gzip",
                    "projection.enabled": "true",
                    "projection.date.type": "date",
                    "projection.date.range": "2025-01-01,NOW",
                    "projection.date.format": "yyyy-MM-dd",
                    "projection.date.interval": "1",
                    "projection.date.interval.unit": "DAYS",
                    "storage.location.template": f"s3://{self.processed_cloudtrail_bucket_name}/processed-cloudtrail/date=${{date}}/"
                },
                storage_descriptor=glue.CfnTable.StorageDescriptorProperty(
                    columns=[
                        glue.CfnTable.ColumnProperty(name="eventTime", type="string"),
                        glue.CfnTable.ColumnProperty(name="eventName", type="string"),
                        glue.CfnTable.ColumnProperty(name="eventSource", type="string"),
                        glue.CfnTable.ColumnProperty(name="awsRegion", type="string"),
                        glue.CfnTable.ColumnProperty(name="sourceIPAddress", type="string"),
                        glue.CfnTable.ColumnProperty(name="userAgent", type="string"),
                        glue.CfnTable.ColumnProperty(name="userIdentity", type="struct<type:string,invokedby:string,principalid:string,arn:string,accountid:string,accesskeyid:string,username:string,sessioncontext:struct<attributes:map<string,string>,sessionissuer:struct<type:string,principalid:string,arn:string,accountid:string,username:string>>>"),
                        glue.CfnTable.ColumnProperty(name="requestParameters", type="string"),
                        glue.CfnTable.ColumnProperty(name="responseElements", type="string"),
                        glue.CfnTable.ColumnProperty(name="resources", type="array<struct<arn:string,type:string>>"),
                        glue.CfnTable.ColumnProperty(name="recipientAccountId", type="string"),
                        glue.CfnTable.ColumnProperty(name="errorCode", type="string"),
                        glue.CfnTable.ColumnProperty(name="errorMessage", type="string"),
                        glue.CfnTable.ColumnProperty(name="hour", type="string"),
                        glue.CfnTable.ColumnProperty(name="userType", type="string"),
                        glue.CfnTable.ColumnProperty(name="userName", type="string"),
                        glue.CfnTable.ColumnProperty(name="isConsoleLogin", type="boolean"),
                        glue.CfnTable.ColumnProperty(name="isFailedLogin", type="boolean"),
                        glue.CfnTable.ColumnProperty(name="isRootUser", type="boolean"),
                        glue.CfnTable.ColumnProperty(name="isAssumedRole", type="boolean"),
                        glue.CfnTable.ColumnProperty(name="isHighRiskEvent", type="boolean"),
                        glue.CfnTable.ColumnProperty(name="isPrivilegedAction", type="boolean"),
                        glue.CfnTable.ColumnProperty(name="isDataAccess", type="boolean"),
                        glue.CfnTable.ColumnProperty(name="target_bucket", type="string"),
                        glue.CfnTable.ColumnProperty(name="target_key", type="string"),
                        glue.CfnTable.ColumnProperty(name="target_username", type="string"),
                        glue.CfnTable.ColumnProperty(name="target_rolename", type="string"),
                        glue.CfnTable.ColumnProperty(name="target_policyname", type="string"),
                        glue.CfnTable.ColumnProperty(name="new_access_key", type="string"),
                        glue.CfnTable.ColumnProperty(name="new_instance_id", type="string"),
                        glue.CfnTable.ColumnProperty(name="target_group_id", type="string"),
                        glue.CfnTable.ColumnProperty(name="identity_principalid", type="string"),
                    ],
                    location=f"s3://{self.processed_cloudtrail_bucket_name}/processed-cloudtrail/",
                    input_format="org.apache.hadoop.mapred.TextInputFormat",
                    output_format="org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
                    serde_info=glue.CfnTable.SerdeInfoProperty(
                        serialization_library="org.openx.data.jsonserde.JsonSerDe",
                        parameters={"serialization.format": "1"}
                    )
                ),
                partition_keys=[
                    glue.CfnTable.ColumnProperty(name="date", type="string"),
                ]
            )
        )

        # GuardDuty Table
        glue.CfnTable(
            self, "GuardDutyFindingsTable",
            catalog_id=self.account,
            database_name="security_logs",
            table_input=glue.CfnTable.TableInputProperty(
                name="processed_guardduty",
                table_type="EXTERNAL_TABLE",
                parameters={
                    "classification": "json",
                    "compressionType": "gzip",
                    "projection.enabled": "true",
                    "projection.date.type": "date",
                    "projection.date.range": "2025-01-01,NOW",
                    "projection.date.format": "yyyy-MM-dd",
                    "projection.date.interval": "1",
                    "projection.date.interval.unit": "DAYS",
                    "storage.location.template": f"s3://{self.processed_guardduty_bucket_name}/processed-guardduty/date=${{date}}/"
                },
                storage_descriptor=glue.CfnTable.StorageDescriptorProperty(
                    columns=[
                        glue.CfnTable.ColumnProperty(name="finding_id", type="string"),
                        glue.CfnTable.ColumnProperty(name="finding_type", type="string"),
                        glue.CfnTable.ColumnProperty(name="title", type="string"),
                        glue.CfnTable.ColumnProperty(name="severity", type="double"),
                        glue.CfnTable.ColumnProperty(name="account_id", type="string"),
                        glue.CfnTable.ColumnProperty(name="region", type="string"),
                        glue.CfnTable.ColumnProperty(name="created_at", type="string"),
                        glue.CfnTable.ColumnProperty(name="event_last_seen", type="string"),
                        glue.CfnTable.ColumnProperty(name="remote_ip", type="string"),
                        glue.CfnTable.ColumnProperty(name="remote_port", type="int"),
                        glue.CfnTable.ColumnProperty(name="connection_direction", type="string"),
                        glue.CfnTable.ColumnProperty(name="protocol", type="string"),
                        glue.CfnTable.ColumnProperty(name="dns_domain", type="string"),
                        glue.CfnTable.ColumnProperty(name="dns_protocol", type="string"),
                        glue.CfnTable.ColumnProperty(name="scanned_ip", type="string"),
                        glue.CfnTable.ColumnProperty(name="scanned_port", type="int"),
                        glue.CfnTable.ColumnProperty(name="aws_api_service", type="string"),
                        glue.CfnTable.ColumnProperty(name="aws_api_name", type="string"),
                        glue.CfnTable.ColumnProperty(name="aws_api_caller_type", type="string"),
                        glue.CfnTable.ColumnProperty(name="aws_api_error", type="string"),
                        glue.CfnTable.ColumnProperty(name="aws_api_remote_ip", type="string"),
                        glue.CfnTable.ColumnProperty(name="target_resource_arn", type="string"),
                        glue.CfnTable.ColumnProperty(name="instance_id", type="string"),
                        glue.CfnTable.ColumnProperty(name="instance_type", type="string"),
                        glue.CfnTable.ColumnProperty(name="image_id", type="string"),
                        glue.CfnTable.ColumnProperty(name="instance_tags", type="string"),
                        glue.CfnTable.ColumnProperty(name="resource_region", type="string"),
                        glue.CfnTable.ColumnProperty(name="access_key_id", type="string"),
                        glue.CfnTable.ColumnProperty(name="principal_id", type="string"),
                        glue.CfnTable.ColumnProperty(name="user_name", type="string"),
                        glue.CfnTable.ColumnProperty(name="s3_bucket_name", type="string"),
                        glue.CfnTable.ColumnProperty(name="service_raw", type="string"),
                        glue.CfnTable.ColumnProperty(name="resource_raw", type="string"),
                        glue.CfnTable.ColumnProperty(name="metadata_raw", type="string"),
                    ],
                    location=f"s3://{self.processed_guardduty_bucket_name}/processed-guardduty/",
                    input_format="org.apache.hadoop.mapred.TextInputFormat",
                    output_format="org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
                    serde_info=glue.CfnTable.SerdeInfoProperty(
                        serialization_library="org.openx.data.jsonserde.JsonSerDe",
                        parameters={"serialization.format": "1"}
                    )
                ),
                partition_keys=[
                    glue.CfnTable.ColumnProperty(name="date", type="string")
                ]
            )
        )

        # VPC DNS Logs Table
        glue.CfnTable(
            self, "CloudWatchVPCLogsTable",
            catalog_id=self.account,
            database_name="security_logs",
            table_input=glue.CfnTable.TableInputProperty(
                name="vpc_logs",
                table_type="EXTERNAL_TABLE",
                parameters={
                    "classification": "json",
                    "compressionType": "gzip",
                    "projection.enabled": "true",
                    "projection.date.type": "date",
                    "projection.date.range": "2025-01-01,NOW",
                    "projection.date.format": "yyyy-MM-dd",
                    "projection.date.interval": "1",
                    "projection.date.interval.unit": "DAYS",
                    "storage.location.template": f"s3://{self.processed_cloudwatch_bucket_name}/vpc-logs/date=${{date}}/"
                },
                storage_descriptor=glue.CfnTable.StorageDescriptorProperty(
                    columns=[
                        glue.CfnTable.ColumnProperty(name="version", type="string"),
                        glue.CfnTable.ColumnProperty(name="account_id", type="string"),
                        glue.CfnTable.ColumnProperty(name="region", type="string"),
                        glue.CfnTable.ColumnProperty(name="vpc_id", type="string"),
                        glue.CfnTable.ColumnProperty(name="query_timestamp", type="string"),
                        glue.CfnTable.ColumnProperty(name="query_name", type="string"),
                        glue.CfnTable.ColumnProperty(name="query_type", type="string"),
                        glue.CfnTable.ColumnProperty(name="query_class", type="string"),
                        glue.CfnTable.ColumnProperty(name="rcode", type="string"),
                        glue.CfnTable.ColumnProperty(name="answers", type="string"),
                        glue.CfnTable.ColumnProperty(name="srcaddr", type="string"),
                        glue.CfnTable.ColumnProperty(name="srcport", type="int"),
                        glue.CfnTable.ColumnProperty(name="transport", type="string"),
                        glue.CfnTable.ColumnProperty(name="srcids_instance", type="string"),
                        glue.CfnTable.ColumnProperty(name="timestamp", type="string"),
                    ],
                    location=f"s3://{self.processed_cloudwatch_bucket_name}/vpc-logs/",
                    input_format="org.apache.hadoop.mapred.TextInputFormat",
                    output_format="org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
                    serde_info=glue.CfnTable.SerdeInfoProperty(
                        serialization_library="org.openx.data.jsonserde.JsonSerDe",
                        parameters={"serialization.format": "1"}
                    )
                ),
                partition_keys=[
                    glue.CfnTable.ColumnProperty(name="date", type="string")
                ]
            )
        )

        # ENI Flow Logs Table
        glue.CfnTable(
            self, "ENIFlowLogsTable",
            catalog_id=self.account,
            database_name="security_logs",
            table_input=glue.CfnTable.TableInputProperty(
                name="eni_flow_logs",
                table_type="EXTERNAL_TABLE",
                parameters={
                    "classification": "json",
                    "compressionType": "gzip",
                    "projection.enabled": "true",
                    "projection.date.type": "date",
                    "projection.date.range": "2025-01-01,NOW",
                    "projection.date.format": "yyyy-MM-dd",
                    "projection.date.interval": "1",
                    "projection.date.interval.unit": "DAYS",
                    "storage.location.template": f"s3://{self.processed_cloudwatch_bucket_name}/eni-flow-logs/date=${{date}}/"
                },
                storage_descriptor=glue.CfnTable.StorageDescriptorProperty(
                    columns=[
                        glue.CfnTable.ColumnProperty(name="version", type="int"),
                        glue.CfnTable.ColumnProperty(name="account_id", type="string"),
                        glue.CfnTable.ColumnProperty(name="interface_id", type="string"),
                        glue.CfnTable.ColumnProperty(name="srcaddr", type="string"),
                        glue.CfnTable.ColumnProperty(name="dstaddr", type="string"),
                        glue.CfnTable.ColumnProperty(name="srcport", type="int"),
                        glue.CfnTable.ColumnProperty(name="dstport", type="int"),
                        glue.CfnTable.ColumnProperty(name="protocol", type="int"),
                        glue.CfnTable.ColumnProperty(name="packets", type="bigint"),
                        glue.CfnTable.ColumnProperty(name="bytes", type="bigint"),
                        glue.CfnTable.ColumnProperty(name="start_time", type="bigint"),
                        glue.CfnTable.ColumnProperty(name="end_time", type="bigint"),
                        glue.CfnTable.ColumnProperty(name="action", type="string"),
                        glue.CfnTable.ColumnProperty(name="log_status", type="string"),
                        glue.CfnTable.ColumnProperty(name="timestamp_str", type="string"),
                    ],
                    location=f"s3://{self.processed_cloudwatch_bucket_name}/eni-flow-logs/",
                    input_format="org.apache.hadoop.mapred.TextInputFormat",
                    output_format="org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
                    serde_info=glue.CfnTable.SerdeInfoProperty(
                        serialization_library="org.openx.data.jsonserde.JsonSerDe",
                        parameters={"serialization.format": "1"}
                    )
                ),
                partition_keys=[
                    glue.CfnTable.ColumnProperty(name="date", type="string")
                ]
            )
        )

    def _create_firehose_streams(self):
        # Firehose IAM Role
        firehose_role = iam.Role(
            self, "FirehoseRole",
            assumed_by=iam.ServicePrincipal("firehose.amazonaws.com"),
            inline_policies={
                "FirehosePolicy": iam.PolicyDocument(
                    statements=[
                        iam.PolicyStatement(
                            actions=["s3:PutObject", "s3:GetBucketLocation", "s3:ListBucket"],
                            resources=[
                                f"arn:aws:s3:::{self.processed_cloudtrail_bucket_name}",
                                f"arn:aws:s3:::{self.processed_cloudtrail_bucket_name}/*",
                                f"arn:aws:s3:::{self.processed_cloudwatch_bucket_name}",
                                f"arn:aws:s3:::{self.processed_cloudwatch_bucket_name}/*"
                            ]
                        )
                    ]
                )
            }
        )

        # CloudTrail Firehose
        self.cloudtrail_firehose_stream = firehose.CfnDeliveryStream(
            self, "CloudTrailFirehoseStream",
            delivery_stream_name="cloudtrail-firehose-stream",
            delivery_stream_type="DirectPut",
            extended_s3_destination_configuration=firehose.CfnDeliveryStream.ExtendedS3DestinationConfigurationProperty(
                bucket_arn=f"arn:aws:s3:::{self.processed_cloudtrail_bucket_name}",
                role_arn=firehose_role.role_arn,
                prefix="processed-cloudtrail/date=!{timestamp:yyyy-MM-dd}/",
                error_output_prefix="processed-cloudtrail/errors/date=!{timestamp:yyyy-MM-dd}/error-type=!{firehose:error-output-type}/",
                buffering_hints=firehose.CfnDeliveryStream.BufferingHintsProperty(
                    size_in_m_bs=10,
                    interval_in_seconds=300
                ),
                compression_format="GZIP",
            )
        )

        # VPC DNS Firehose
        self.vpc_dns_firehose_stream = firehose.CfnDeliveryStream(
            self, "VpcDnsFirehoseStream",
            delivery_stream_name="vpc-dns-firehose-stream",
            delivery_stream_type="DirectPut",
            extended_s3_destination_configuration=firehose.CfnDeliveryStream.ExtendedS3DestinationConfigurationProperty(
                bucket_arn=f"arn:aws:s3:::{self.processed_cloudwatch_bucket_name}",
                role_arn=firehose_role.role_arn,
                prefix="vpc-logs/date=!{timestamp:yyyy-MM-dd}/",
                error_output_prefix="vpc-logs/errors/date=!{timestamp:yyyy-MM-dd}/error-type=!{firehose:error-output-type}/",
                buffering_hints=firehose.CfnDeliveryStream.BufferingHintsProperty(
                    size_in_m_bs=10,
                    interval_in_seconds=300
                ),
                compression_format="GZIP",
            )
        )

        # VPC Flow Logs (ENI) Firehose
        self.vpc_flow_firehose_stream = firehose.CfnDeliveryStream(
            self, "VpcFlowFirehoseStream",
            delivery_stream_name="vpc-flow-firehose-stream",
            delivery_stream_type="DirectPut",
            extended_s3_destination_configuration=firehose.CfnDeliveryStream.ExtendedS3DestinationConfigurationProperty(
                bucket_arn=f"arn:aws:s3:::{self.processed_cloudwatch_bucket_name}",
                role_arn=firehose_role.role_arn,
                prefix="eni-flow-logs/date=!{timestamp:yyyy-MM-dd}/",
                error_output_prefix="eni-flow-logs/errors/date=!{timestamp:yyyy-MM-dd}/error-type=!{firehose:error-output-type}/",
                buffering_hints=firehose.CfnDeliveryStream.BufferingHintsProperty(
                    size_in_m_bs=10,
                    interval_in_seconds=300
                ),
                compression_format="GZIP",
            )
        )

    def _create_etl_functions(self):
        # CloudTrail ETL
        self.cloudtrail_etl_function = _lambda.Function(
            self, "CloudTrailETLLambda",
            function_name="incident-response-cloudtrail-etl",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="CloudTrailETL.lambda_handler",
            code=_lambda.Code.from_asset("lambda/cloudtrail_etl"),
            timeout=Duration.minutes(5),
            environment={
                "FIREHOSE_STREAM_NAME": self.cloudtrail_firehose_stream.delivery_stream_name,
            }
        )

        self.cloudtrail_etl_function.add_to_role_policy(
            iam.PolicyStatement(
                actions=["s3:GetObject", "firehose:PutRecord", "firehose:PutRecordBatch"],
                resources=[
                    f"arn:aws:s3:::{self.log_list_bucket_name}/*",
                    self.cloudtrail_firehose_stream.attr_arn
                ]
            )
        )

        self.log_list_bucket.add_event_notification(
            s3.EventType.OBJECT_CREATED,
            s3n.LambdaDestination(self.cloudtrail_etl_function),
            s3.NotificationKeyFilter(prefix=f"AWSLogs/{self.account}/CloudTrail/")
        )

        # GuardDuty ETL
        self.guardduty_etl_function = _lambda.Function(
            self, "GuardDutyETLLambda",
            function_name="incident-response-guardduty-etl",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="guardduty_etl.lambda_handler",
            code=_lambda.Code.from_asset("lambda/guardduty_etl"),
            timeout=Duration.minutes(5),
            environment={
                "DESTINATION_BUCKET": self.processed_guardduty_bucket_name,
                "DATABASE_NAME": "security_logs",
                "TABLE_NAME_GUARDDUTY": "processed_guardduty",
            }
        )

        self.guardduty_etl_function.add_to_role_policy(
            iam.PolicyStatement(
                actions=["s3:GetObject", "s3:PutObject", "kms:Decrypt", "glue:CreatePartition", "glue:GetPartition"],
                resources=[
                    f"arn:aws:s3:::{self.log_list_bucket_name}/*",
                    f"arn:aws:s3:::{self.processed_guardduty_bucket_name}/*",
                    self.kms_key_arn,
                    f"arn:aws:glue:{self.region}:{self.account}:*"
                ]
            )
        )

        self.log_list_bucket.add_event_notification(
            s3.EventType.OBJECT_CREATED,
            s3n.LambdaDestination(self.guardduty_etl_function),
            s3.NotificationKeyFilter(prefix=f"AWSLogs/{self.account}/GuardDuty/")
        )

        # CloudWatch VPC DNS ETL
        self.cloudwatch_etl_function = _lambda.Function(
            self, "CloudWatchETLLambda",
            function_name="cloudwatch-etl-lambda",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="cloudwatch_etl.lambda_handler",
            code=_lambda.Code.from_asset("lambda/cloudwatch_etl"),
            timeout=Duration.minutes(5),
            environment={
                "FIREHOSE_STREAM_NAME": self.vpc_dns_firehose_stream.delivery_stream_name,
            }
        )

        self.cloudwatch_etl_function.add_to_role_policy(
            iam.PolicyStatement(
                actions=["s3:GetObject", "firehose:PutRecord", "firehose:PutRecordBatch"],
                resources=[
                    f"arn:aws:s3:::{self.log_list_bucket_name}/*",
                    self.vpc_dns_firehose_stream.attr_arn
                ]
            )
        )

        self.log_list_bucket.add_event_notification(
            s3.EventType.OBJECT_CREATED,
            s3n.LambdaDestination(self.cloudwatch_etl_function),
            s3.NotificationKeyFilter(prefix="exportedlogs/vpc-dns-logs/")
        )

        # CloudWatch ENI ETL
        self.cloudwatch_eni_etl_function = _lambda.Function(
            self, "CloudWatchENIETLLambda",
            function_name="cloudwatch-eni-etl-lambda",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="cloudwatch_eni_etl.lambda_handler",
            code=_lambda.Code.from_asset("lambda/cloudwatch_eni_etl"),
            timeout=Duration.minutes(5),
            environment={
                "FIREHOSE_STREAM_NAME": self.vpc_flow_firehose_stream.delivery_stream_name,
            }
        )

        self.cloudwatch_eni_etl_function.add_to_role_policy(
            iam.PolicyStatement(
                actions=["s3:GetObject", "firehose:PutRecord", "firehose:PutRecordBatch"],
                resources=[
                    f"arn:aws:s3:::{self.log_list_bucket_name}/*",
                    self.vpc_flow_firehose_stream.attr_arn
                ]
            )
        )

        self.log_list_bucket.add_event_notification(
            s3.EventType.OBJECT_CREATED,
            s3n.LambdaDestination(self.cloudwatch_eni_etl_function),
            s3.NotificationKeyFilter(prefix="exportedlogs/vpc-flow-logs/")
        )

    def _create_cloudwatch_export_lambda(self):
        self.cloudwatch_export_function = _lambda.Function(
            self, "CloudWatchExportLambda",
            function_name="cloudwatch-export-lambda",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="cloudwatch_autoexport.lambda_handler",
            code=_lambda.Code.from_asset("lambda/cloudwatch_autoexport"),
            timeout=Duration.minutes(5),
            environment={
                "DESTINATION_BUCKET": self.log_list_bucket_name
            }
        )

        self.cloudwatch_export_function.add_to_role_policy(
            iam.PolicyStatement(
                actions=["s3:PutObject", "logs:CreateExportTask", "logs:DescribeExportTasks"],
                resources=[
                    f"arn:aws:s3:::{self.log_list_bucket_name}/*",
                    f"arn:aws:logs:{self.region}:{self.account}:log-group:*"
                ]
            )
        )

    def _create_subscription_filter(self):
        permission_resource = _lambda.CfnPermission(
            self, "CloudWatchLogsLambdaPermission",
            action="lambda:InvokeFunction",
            function_name=self.cloudwatch_export_function.function_name,
            principal=f"logs.{self.region}.amazonaws.com",
            source_arn=f"arn:aws:logs:{self.region}:{self.account}:log-group:{self.ir_log_group_name}:*"
        )

        subscription_filter = logs.CfnSubscriptionFilter(
            self, "IRLogGroupSubscriptionFilter",
            log_group_name=self.ir_log_group_name,
            filter_pattern="",
            destination_arn=self.cloudwatch_export_function.function_arn
        )
        subscription_filter.add_dependency(permission_resource)