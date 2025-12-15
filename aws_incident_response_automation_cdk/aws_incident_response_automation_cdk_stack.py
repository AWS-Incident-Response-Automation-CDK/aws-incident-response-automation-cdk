import json
from aws_cdk import (
    Stack,
    aws_s3 as s3,
    aws_guardduty as guardduty,
    aws_cloudtrail as cloudtrail,
    aws_logs as logs,
    aws_iam as iam,
    aws_glue as glue,
    aws_s3_notifications as s3n,
    aws_lambda as _lambda,
    aws_ec2 as ec2,
    aws_route53resolver as route53resolver,
    aws_kms as kms,
    aws_events as events,
    aws_events_targets as targets,
    aws_sns as sns,  
    aws_sns_subscriptions as sns_subscriptions,
    aws_kinesisfirehose as firehose,
    aws_stepfunctions as sfn,
    Duration,
    RemovalPolicy,
)
from constructs import Construct

class AwsIncidentResponseAutomationCdkStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        vpc_ids = self.node.try_get_context("vpc_ids") or []

        self._create_storage_infrastructure()
        self._create_log_group()
        self._create_kms_key()
        self._enable_guardduty()
        self._create_cloudtrail()
        self._add_bucket_policies()
        self._create_glue_table()
        self._create_firehose_log_stream()
        self._create_cloudwatch_export_lambda()
        self._create_cloudtrail_etl()
        self._create_subscription_filter()
        self._create_cloudwatch_etl()
        self._create_cloudwatch_eni_etl()
        self._create_guardduty_etl()
        self._create_sns_topic()
        self._create_alert_dispatch()
        self._create_security_group()
        self._create_isolate_ec2_lambda()
        self._create_parse_findings_lambda()
        self._create_quarantine_iam_lambda()
        self._create_incident_response_step_functions()
        self._create_event_bridge_rules()
        
        if vpc_ids:
            self._create_flow_log_iam_role()
            self._create_vpc_flow_logs(vpc_ids)
            self._create_dns_query_logging(vpc_ids)


    def _create_storage_infrastructure(self):

        
        self.log_list_bucket = s3.Bucket(
            self, "LogListBucket",
            bucket_name=f"incident-response-log-list-bucket-{self.account}-{self.region}",
            encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            versioned=True,
            removal_policy=RemovalPolicy.RETAIN
        )

        self.processed_cloudtrail_logs_bucket = s3.Bucket(
            self, "ProcessedCloudTrailLogsBucket",
            bucket_name=f"processed-cloudtrail-logs-{self.account}-{self.region}",
            encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            versioned=True,
            enforce_ssl=True,
            removal_policy=RemovalPolicy.RETAIN
        )

        self.athena_query_results_bucket = s3.Bucket(
            self, "AthenaQueryResultsBucket",
            bucket_name=f"athena-query-results-{self.account}-{self.region}",
            encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            versioned=True,
            enforce_ssl=True,
            removal_policy=RemovalPolicy.RETAIN
        )

        self.processed_cloudwatch_logs_bucket = s3.Bucket(
            self, "ProcessedCloudWatchLogsBucket",
            bucket_name=f"processed-cloudwatch-logs-{self.account}-{self.region}",
            encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            versioned=True,
            enforce_ssl=True,
            removal_policy=RemovalPolicy.RETAIN
        )

        self.processed_guardduty_findings_bucket = s3.Bucket(
            self, "ProcessedGuardDutyFindingsBucket",
            bucket_name=f"processed-guardduty-findings-{self.account}-{self.region}",
            encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            versioned=True,
            enforce_ssl=True,
            removal_policy=RemovalPolicy.RETAIN
        )

    def _create_kms_key(self):
        self.kms_key = kms.Key(
            self, "GuardDutyKMSKey",
            description="KMS Key for GuardDuty findings encryption",
            enable_key_rotation=True,
            removal_policy=RemovalPolicy.RETAIN
        )

        self.kms_key.add_to_resource_policy(
            iam.PolicyStatement(
                sid="AllowGuardDutyEncryptFindings",
                principals=[iam.ServicePrincipal("guardduty.amazonaws.com")],
                actions=["kms:GenerateDataKey", "kms:Encrypt", "kms:Decrypt", "kms:CreateGrant"],
                resources=["*"],
                conditions={
                    "StringEquals": {
                        "aws:SourceAccount": self.account,
                    }
                }
            )
        )
  
    def _add_bucket_policies(self):

        GD_DETECTOR_ID = self.guardduty_detector.ref
        
        GD_ARN = f"arn:aws:guardduty:{self.region}:{self.account}:detector/{GD_DETECTOR_ID}"

        bucket_arn = self.log_list_bucket.bucket_arn
        bucket_objects_arn = self.log_list_bucket.arn_for_objects("*")

        self.log_list_bucket.add_to_resource_policy(
            iam.PolicyStatement(
                sid="AllowGuardDutyPutObject",
                effect=iam.Effect.ALLOW,
                principals=[iam.ServicePrincipal("guardduty.amazonaws.com")],
                actions=["s3:PutObject"],
                resources=[bucket_objects_arn],
                conditions={
                    "StringEquals": {"aws:SourceAccount": f"{self.account}"},
                    "ArnLike": {"aws:SourceArn": GD_ARN}
                }
            )
        )
        self.log_list_bucket.add_to_resource_policy(
            iam.PolicyStatement(
                sid="AllowGuardDutyGetBucketLocation",
                effect=iam.Effect.ALLOW,
                principals=[iam.ServicePrincipal("guardduty.amazonaws.com")],
                actions=["s3:GetBucketLocation"],
                resources=[bucket_arn],
                conditions={
                    "StringEquals": {"aws:SourceAccount": self.account},
                    "ArnLike": {"aws:SourceArn": GD_ARN}
                }
            )
        )
        CW_LOGS_PRINCIPAL = iam.ServicePrincipal(f"logs.{self.region}.amazonaws.com")
        CW_LOGS_ARN = f"arn:aws:logs:{self.region}:{self.account}:log-group:*"
        
        self.log_list_bucket.add_to_resource_policy(
            iam.PolicyStatement(
                sid="AllowCloudWatchLogsGetBucketAcl",
                effect=iam.Effect.ALLOW,
                principals=[CW_LOGS_PRINCIPAL],
                actions=["s3:GetBucketAcl"],
                resources=[bucket_arn],
                conditions={
                    "StringEquals": {"aws:SourceAccount": self.account},
                    "ArnLike": {"aws:SourceArn": CW_LOGS_ARN}
                }
            )
        )

        self.log_list_bucket.add_to_resource_policy(
            iam.PolicyStatement(
                sid="AllowCloudWatchLogsPutObject",
                effect=iam.Effect.ALLOW,
                principals=[CW_LOGS_PRINCIPAL],
                actions=["s3:PutObject"],
                resources=[bucket_objects_arn],
                conditions={
                    "StringEquals": {"aws:SourceAccount": self.account},
                    "ArnLike": {"aws:SourceArn": CW_LOGS_ARN}
                }
            )
        )
        
        CT_PRINCIPAL = iam.ServicePrincipal("cloudtrail.amazonaws.com")
        CT_ARN = f"arn:aws:cloudtrail:{self.region}:{self.account}:trail/*"

        self.log_list_bucket.add_to_resource_policy(
            iam.PolicyStatement(
                sid="AllowCloudTrailAclCheck",
                effect=iam.Effect.ALLOW,
                principals=[CT_PRINCIPAL],
                actions=["s3:GetBucketAcl"],
                resources=[bucket_arn],
                conditions={"StringEquals": {
                    "aws:SourceAccount": self.account
                    },
                    "ArnLike": {
                        "aws:SourceArn": CT_ARN
                    }
                }
            )
        )

        self.log_list_bucket.add_to_resource_policy(
            iam.PolicyStatement(
                sid="AllowCloudTrailWrite",
                effect=iam.Effect.ALLOW,
                principals=[CT_PRINCIPAL],
                actions=["s3:PutObject"],
                resources=[
                    self.log_list_bucket.arn_for_objects(f"AWSLogs/{self.account}/*")
                ],
                conditions={
                    "StringEquals": {
                        "s3:x-amz-acl": "bucket-owner-full-control",
                        "aws:SourceAccount": self.account
                    },
                    "ArnLike": {"aws:SourceArn": CT_ARN}
                }
            )
        )

    def _enable_guardduty(self):
        self.guardduty_detector = guardduty.CfnDetector(
            self, "GuardDutyDetector",
            enable=True,
            finding_publishing_frequency="FIFTEEN_MINUTES"
        )

        self.guardduty_publishing_destination = guardduty.CfnPublishingDestination(
            self, "GuardDutyS3Publishing",
            detector_id=self.guardduty_detector.ref,
            destination_type="S3",
            destination_properties=guardduty.CfnPublishingDestination.CFNDestinationPropertiesProperty(
                destination_arn=self.log_list_bucket.bucket_arn,
                kms_key_arn=self.kms_key.key_arn
            )
        )

    def _create_log_group(self):
        self.ir_log_group = logs.LogGroup(
            self, "IRLogGroup",
            log_group_name="/aws/incident-response/centralized-logs",
            retention=logs.RetentionDays.ONE_MONTH,
            removal_policy=RemovalPolicy.DESTROY
        )
        
    def _create_cloudtrail(self):
        
        self.cloudtrail= cloudtrail.CfnTrail(
            self, "CloudTrail",
            is_multi_region_trail=True,
            include_global_service_events=True,
            s3_bucket_name=self.log_list_bucket.bucket_name,
            trail_name=f"incident-responses-cloudtrail-{self.account}-{self.region}",
            enable_log_file_validation=True,
            is_logging=True,
            advanced_event_selectors=[
                cloudtrail.CfnTrail.AdvancedEventSelectorProperty(
                    name="Security Management Events",
                    field_selectors=[
                        cloudtrail.CfnTrail.AdvancedFieldSelectorProperty(
                            field="eventCategory",
                            equal_to=["Management"]
                        ),
                    ]
                ),

                cloudtrail.CfnTrail.AdvancedEventSelectorProperty(
                    name="Exclude IR Log Events",
                    field_selectors=[
                        cloudtrail.CfnTrail.AdvancedFieldSelectorProperty(
                            field="eventCategory",
                            equal_to=["Data"]
                        ),

                        cloudtrail.CfnTrail.AdvancedFieldSelectorProperty(
                            field="resources.type",
                            equal_to=["AWS::S3::Object"]
                        ),

                        cloudtrail.CfnTrail.AdvancedFieldSelectorProperty(
                            field="resources.ARN",
                            not_starts_with=[
                                f"{self.log_list_bucket.bucket_arn}/",
                                f"{self.processed_cloudtrail_logs_bucket.bucket_arn}/",
                                f"{self.processed_cloudwatch_logs_bucket.bucket_arn}/",
                                f"{self.processed_guardduty_findings_bucket.bucket_arn}/",
                                f"{self.athena_query_results_bucket.bucket_arn}/"
                            ]  
                        ),    
                    ]
                )
            ]
        )   
        
    def _create_glue_table(self):
        self.glue_database = glue.CfnDatabase(
            self, "SecurityLogsDatabase",
            catalog_id=self.account,
            database_input=glue.CfnDatabase.DatabaseInputProperty(
                name="security_logs"
            )
        )
        # CloudTrail Glue Table
        self.glue_table = glue.CfnTable(
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
                    "storage.location.template": f"s3://{self.processed_cloudtrail_logs_bucket.bucket_name}/processed-cloudtrail/date=${{date}}/"
                },
                storage_descriptor=glue.CfnTable.StorageDescriptorProperty(
                    columns=[
                        glue.CfnTable.ColumnProperty(name="eventTime", type="string"),
                        glue.CfnTable.ColumnProperty(name="eventName", type="string"),
                        glue.CfnTable.ColumnProperty(name="eventSource", type="string"),
                        glue.CfnTable.ColumnProperty(name="awsRegion", type="string"),
                        glue.CfnTable.ColumnProperty(name="sourceIPAddress", type="string"),
                        glue.CfnTable.ColumnProperty(name="userAgent", type="string"),
                        glue.CfnTable.ColumnProperty(name="userIdentity", type="struct<type:string,invokedby:string,principalid:string,arn:string,accountid:string,accesskeyid:string,username:string,sessioncontext:struct<attributes:map<string,string>,sessionissuer:struct<type:string,principalid:string,arn:string,accountid:string,username:string>>,inscopeof:struct<issuertype:string,credentialsissuedto:string>>"),
                        glue.CfnTable.ColumnProperty(name="requestParameters", type="string"),
                        glue.CfnTable.ColumnProperty(name="responseElements", type="string"),
                        glue.CfnTable.ColumnProperty(name="resources", type="array<struct<arn:string,type:string>>"),
                        glue.CfnTable.ColumnProperty(name="recipientAccountId", type="string"),
                        glue.CfnTable.ColumnProperty(name="serviceEventDetails", type="string"),
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
                        glue.CfnTable.ColumnProperty(name="identity_principalid", type="string")
                    ],
                    location=f"s3://{self.processed_cloudtrail_logs_bucket.bucket_name}/processed-cloudtrail/",
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

        # CloudWatch Glue Table
        self.glue_cloudwatch_vpc_logs_table = glue.CfnTable(
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
                    "storage.location.template": f"s3://{self.processed_cloudwatch_logs_bucket.bucket_name}/vpc-logs/date=${{date}}/"
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
                        glue.CfnTable.ColumnProperty(name="timestamp", type="string")
                    ],
                    location=f"s3://{self.processed_cloudwatch_logs_bucket.bucket_name}/vpc-logs/",
                    input_format="org.apache.hadoop.mapred.TextInputFormat",
                    output_format="org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
                    serde_info=glue.CfnTable.SerdeInfoProperty(
                        serialization_library="org.openx.data.jsonserde.JsonSerDe",
                        parameters={
                            "serialization.format": "1",
                            "ignore.malformed.json": "true"}
                    )
                ),
                partition_keys=[
                    glue.CfnTable.ColumnProperty(name="date", type="string")
                ]
            )
        )

        # GuardDuty Glue Table
        self.glue_guardduty_findings_table = glue.CfnTable(
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
                    "storage.location.template": f"s3://{self.processed_guardduty_findings_bucket.bucket_name}/processed-guardduty/date=${{date}}/"
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
                        glue.CfnTable.ColumnProperty(name="metadata_raw", type="string")
                    ],
                    location=f"s3://{self.processed_guardduty_findings_bucket.bucket_name}/processed-guardduty/",
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

        # ENI Flow Logs Glue Table
        self.glue_eni_flow_logs_table = glue.CfnTable(
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
                    "storage.location.template": f"s3://{self.processed_cloudwatch_logs_bucket.bucket_name}/eni-flow-logs/date=${{date}}/"
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
                        glue.CfnTable.ColumnProperty(name="timestamp_str", type="string")
                    ],
                    location=f"s3://{self.processed_cloudwatch_logs_bucket.bucket_name}/eni-flow-logs/",
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

    def _create_firehose_log_stream(self):

        self.cloudwatch_firehose_role = iam.Role(
            self, "CloudWatchFirehoseRole",
            assumed_by=iam.ServicePrincipal("firehose.amazonaws.com"),
            inline_policies={
                "FirehosePolicy": iam.PolicyDocument(
                    statements=[
                        iam.PolicyStatement(
                            actions=["s3:PutObject", "s3:GetBucketLocation", "s3:ListBucket"],
                            resources=[
                                self.processed_cloudwatch_logs_bucket.bucket_arn,
                                self.processed_cloudwatch_logs_bucket.arn_for_objects("*")
                            ]
                        )
                    ]
                )
            }
        )

        self.cloudtrail_firehose_role = iam.Role(
            self, "CloudTrailFirehoseRole",
            assumed_by=iam.ServicePrincipal("firehose.amazonaws.com"),
            inline_policies={
                "FirehosePolicy": iam.PolicyDocument(
                    statements=[
                        iam.PolicyStatement(
                            actions=["s3:PutObject", "s3:GetBucketLocation", "s3:ListBucket"],
                            resources=[
                                self.processed_cloudtrail_logs_bucket.bucket_arn,
                                self.processed_cloudtrail_logs_bucket.arn_for_objects("*")
                            ]
                        )
                    ]
                )
            }
        )

        self.vpc_dns_firehose_stream= firehose.CfnDeliveryStream(
            self, "VpcDnsFirehoseStream",
            delivery_stream_name="vpc-dns-firehose-stream",
            delivery_stream_type="DirectPut",
            delivery_stream_encryption_configuration_input=firehose.CfnDeliveryStream.DeliveryStreamEncryptionConfigurationInputProperty(
                key_type="AWS_OWNED_CMK"
            ),
            extended_s3_destination_configuration=firehose.CfnDeliveryStream.ExtendedS3DestinationConfigurationProperty(
                bucket_arn=self.processed_cloudwatch_logs_bucket.bucket_arn,
                role_arn=self.cloudwatch_firehose_role.role_arn,
                prefix="vpc-logs/date=!{timestamp:yyyy-MM-dd}/",
                error_output_prefix="vpc-logs/errors/date=!{timestamp:yyyy-MM-dd}/error-type=!{firehose:error-output-type}/",
                buffering_hints=firehose.CfnDeliveryStream.BufferingHintsProperty(
                    size_in_m_bs=10,
                    interval_in_seconds=300
                ),
                compression_format="GZIP",
            )
        )

        self.vpc_flow_firehose_stream= firehose.CfnDeliveryStream(
            self, "VpcFlowFirehoseStream",
            delivery_stream_name="vpc-flow-firehose-stream",
            delivery_stream_type="DirectPut",
            delivery_stream_encryption_configuration_input=firehose.CfnDeliveryStream.DeliveryStreamEncryptionConfigurationInputProperty(
                key_type="AWS_OWNED_CMK"
            ),
            extended_s3_destination_configuration=firehose.CfnDeliveryStream.ExtendedS3DestinationConfigurationProperty(
                bucket_arn=self.processed_cloudwatch_logs_bucket.bucket_arn,
                role_arn=self.cloudwatch_firehose_role.role_arn,
                prefix="eni-flow-logs/date=!{timestamp:yyyy-MM-dd}/",
                error_output_prefix="eni-flow-logs/errors/date=!{timestamp:yyyy-MM-dd}/error-type=!{firehose:error-output-type}/",
                buffering_hints=firehose.CfnDeliveryStream.BufferingHintsProperty(
                    size_in_m_bs=10,
                    interval_in_seconds=300
                ),
                compression_format="GZIP",
            )
        )

        self.cloudtrail_firehose_stream= firehose.CfnDeliveryStream(
            self, "CloudTrailFirehoseStream",
            delivery_stream_name="cloudtrail-firehose-stream",
            delivery_stream_type="DirectPut",
            delivery_stream_encryption_configuration_input=firehose.CfnDeliveryStream.DeliveryStreamEncryptionConfigurationInputProperty(
                key_type="AWS_OWNED_CMK"
            ),
            extended_s3_destination_configuration=firehose.CfnDeliveryStream.ExtendedS3DestinationConfigurationProperty(
                bucket_arn=self.processed_cloudtrail_logs_bucket.bucket_arn,
                role_arn=self.cloudtrail_firehose_role.role_arn,
                prefix="processed-cloudtrail/date=!{timestamp:yyyy-MM-dd}/",
                error_output_prefix="processed-cloudtrail/errors/date=!{timestamp:yyyy-MM-dd}/error-type=!{firehose:error-output-type}/",
                buffering_hints=firehose.CfnDeliveryStream.BufferingHintsProperty(
                    size_in_m_bs=10,
                    interval_in_seconds=300
                ),
                compression_format="GZIP",
            )
        )

    def _create_cloudtrail_etl(self):
        self.cloudtrail_etl_function = _lambda.Function(
            self, "CloudTrailETLLambda",
            function_name=f"incident-response-cloudtrail-etl",
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
                actions=["s3:GetObject"],
                resources=[
                    self.log_list_bucket.arn_for_objects("*"),
                ]
            )
        )

        self.cloudtrail_etl_function.add_to_role_policy(
            iam.PolicyStatement(
                actions=["firehose:PutRecord", "firehose:PutRecordBatch"],
                resources=[
                    self.cloudtrail_firehose_stream.attr_arn
                ]
            )
        )

        self.log_list_bucket.add_event_notification(
            s3.EventType.OBJECT_CREATED,
            s3n.LambdaDestination(self.cloudtrail_etl_function),
            s3.NotificationKeyFilter(prefix=f"AWSLogs/{self.account}/CloudTrail/")
        )

    def _create_flow_log_iam_role(self):
        self.flow_logs_role = iam.Role(
            self, "FlowLogsIAMRole",
            assumed_by=iam.ServicePrincipal("vpc-flow-logs.amazonaws.com"),
            inline_policies={
                "FlowLogsPolicy": iam.PolicyDocument(
                    statements=[
                        iam.PolicyStatement(
                            actions=[
                                "logs:CreateLogGroup",
                                "logs:CreateLogStream",
                                "logs:PutLogEvents",
                                "logs:DescribeLogGroups",
                                "logs:DescribeLogStreams"
                            ],
                            resources=["*"]
                        )
                    ]
                )
            }
        )

    def _create_vpc_flow_logs(self, vpc_ids):
        for i, vpc_id in enumerate(vpc_ids):
            ec2.CfnFlowLog(
                self, f"VPCFlowLog{i}",
                resource_id=vpc_id,
                resource_type="VPC",
                traffic_type="ALL",
                log_destination_type="cloud-watch-logs",
                log_group_name=self.ir_log_group.log_group_name,
                deliver_logs_permission_arn=self.flow_logs_role.role_arn
            )  
  
    def _create_dns_query_logging(self, vpc_ids):

        resolver_query_logging_config = route53resolver.CfnResolverQueryLoggingConfig(
            self, "ResolverQueryLoggingConfig",
            destination_arn=self.ir_log_group.log_group_arn,
        )

        for i, vpc_id in enumerate(vpc_ids):
            route53resolver.CfnResolverQueryLoggingConfigAssociation(
                self, f"ResolverQueryLoggingConfigAssociation{i}",
                resolver_query_log_config_id=resolver_query_logging_config.ref,
                resource_id=vpc_id
            ) 

    def _create_cloudwatch_export_lambda(self):
        self.cloudwatch_export_function = _lambda.Function(
            self, "CloudWatchExportLambda",
            function_name=f"cloudwatch-export-lambda",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="cloudwatch_autoexport.lambda_handler",
            code=_lambda.Code.from_asset("lambda/cloudwatch_autoexport"),
            timeout=Duration.minutes(5),
            environment={
                "DESTINATION_BUCKET": self.log_list_bucket.bucket_name
            }
        )

        self.cloudwatch_export_function.add_to_role_policy(
            iam.PolicyStatement(
                actions=["s3:PutObject",
                         "logs:CreateExportTask",
                         "logs:DescribeExportTasks",
                         ],
                resources=[
                    self.log_list_bucket.arn_for_objects("*"),
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
            source_arn=f"arn:aws:logs:{self.region}:{self.account}:log-group:/aws/incident-response/centralized-logs:*"
        )

        subscription_filter = logs.CfnSubscriptionFilter(
            self, "IRLogGroupSubscriptionFilter",
            log_group_name=self.ir_log_group.log_group_name,
            filter_pattern="",
            destination_arn=self.cloudwatch_export_function.function_arn
        )
        subscription_filter.add_dependency(permission_resource)

    def _create_cloudwatch_etl(self):
        self.cloudwatch_etl_function = _lambda.Function(
            self, "CloudWatchETLLambda",
            function_name=f"cloudwatch-etl-lambda",
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
                actions=["s3:GetObject"],
                resources=[
                    self.log_list_bucket.arn_for_objects("*"),
                ]
            )
        )

        self.cloudwatch_etl_function.add_to_role_policy(
            iam.PolicyStatement(
                actions=["firehose:PutRecord", "firehose:PutRecordBatch"],
                resources=[
                    self.vpc_dns_firehose_stream.attr_arn
                ]
            )
        )

        self.log_list_bucket.add_event_notification(
            s3.EventType.OBJECT_CREATED,
            s3n.LambdaDestination(self.cloudwatch_etl_function),
            s3.NotificationKeyFilter(prefix="exportedlogs/vpc-dns-logs/")
        )
    
    def _create_cloudwatch_eni_etl(self):
        self.cloudwatch_eni_etl_function = _lambda.Function(
            self, "CloudWatchENIETLLambda",
            function_name=f"cloudwatch-eni-etl-lambda",
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
                actions=["s3:GetObject"],
                resources=[
                    self.log_list_bucket.arn_for_objects("*"),
                ]
            )
        )

        self.cloudwatch_eni_etl_function.add_to_role_policy(
            iam.PolicyStatement(
                actions=["firehose:PutRecord", "firehose:PutRecordBatch"],
                resources=[
                    self.vpc_flow_firehose_stream.attr_arn
                ]
            )
        )

        self.log_list_bucket.add_event_notification(
            s3.EventType.OBJECT_CREATED,
            s3n.LambdaDestination(self.cloudwatch_eni_etl_function),
            s3.NotificationKeyFilter(prefix="exportedlogs/vpc-flow-logs/")
        )

    def _create_guardduty_etl(self):
        self.guardduty_etl_function = _lambda.Function(
            self, "GuardDutyETLLambda",
            function_name="incident-response-guardduty-etl",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="guardduty_etl.lambda_handler",
            code=_lambda.Code.from_asset("lambda/guardduty_etl"),
            timeout=Duration.minutes(5),
            environment={
                "DESTINATION_BUCKET": self.processed_guardduty_findings_bucket.bucket_name,
                "DATABASE_NAME": "security_logs",
                "TABLE_NAME_GUARDDUTY": "processed_guardduty",
                "S3_LOCATION_GUARDDUTY": f"s3://{self.processed_guardduty_findings_bucket.bucket_name}/processed-guardduty/"
            }
        )
    
        self.guardduty_etl_function.add_to_role_policy(
            iam.PolicyStatement(
                actions=["s3:GetObject", "s3:PutObject"],
                resources=[
                    self.log_list_bucket.arn_for_objects("*"),
                    self.processed_guardduty_findings_bucket.arn_for_objects("*")
                ]
            )
        )
    
        self.guardduty_etl_function.add_to_role_policy(
            iam.PolicyStatement(
                actions=["kms:Decrypt"],
                resources=[self.kms_key.key_arn]
            )
        )
    
        self.guardduty_etl_function.add_to_role_policy(
            iam.PolicyStatement(
                actions=["glue:CreatePartition", "glue:GetPartition"],
                resources=[
                    f"arn:aws:glue:{self.region}:{self.account}:catalog",
                    f"arn:aws:glue:{self.region}:{self.account}:database/security_logs",
                    f"arn:aws:glue:{self.region}:{self.account}:table/security_logs/processed_guardduty"
                ]
            )
        )
    
        self.log_list_bucket.add_event_notification(
            s3.EventType.OBJECT_CREATED,
            s3n.LambdaDestination(self.guardduty_etl_function),
            s3.NotificationKeyFilter(prefix=f"AWSLogs/{self.account}/GuardDuty/")
        )

    def _create_sns_topic(self):
        self.ir_alert_topic = sns.Topic(
            self, "IRAlertTopic",
            topic_name="IncidentResponseAlerts",
        )
     
    def _create_event_bridge_rules(self):
        self.guardduty_findings_rule = events.Rule(
            self, "GuardDutyFindingsRule",
            rule_name="IncidentResponseAlert",
            event_pattern=events.EventPattern(
                source=["aws.guardduty"],
                detail_type=["GuardDuty Finding"]
            )
        )
        self.guardduty_findings_rule.add_target(
            targets.SnsTopic(self.ir_alert_topic)
        )

        self.guardduty_findings_rule.add_target(
            targets.SfnStateMachine(self.incident_response_step_functions)
        )

    def _create_alert_dispatch(self):
        alert_emails= self.node.try_get_context("alert_email") or []

        self.alert_dispatch_function = _lambda.Function(
            self, "AlertDispatchLambda",
            function_name="ir-alert-dispatch",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="alert_dispatch.lambda_handler",
            code=_lambda.Code.from_asset("lambda/alert_dispatch"),
            timeout=Duration.minutes(5),
            environment={
                "RECIPIENT_EMAIL": ",".join(alert_emails),
                "SENDER_EMAIL": self.node.try_get_context("sender_email") or "",
                "SLACK_WEBHOOK_URL": self.node.try_get_context("slack_webhook_url") or ""
            }
        )

        self.alert_dispatch_function.add_to_role_policy(
            iam.PolicyStatement(
                actions=["sns:Publish"],
                resources=[self.ir_alert_topic.topic_arn]
            )
        )

        self.alert_dispatch_function.add_to_role_policy(
            iam.PolicyStatement(
                actions=["ses:SendEmail", "ses:SendRawEmail"],
                resources=["*"]
            )
        )

        self.ir_alert_topic.add_subscription(
            sns_subscriptions.LambdaSubscription(self.alert_dispatch_function)
        )

    def _create_security_group(self):
        vpc_ids = self.node.try_get_context("vpc_ids") or []
        self.quarantine_sg_map={}

        for i, vpc_id in enumerate(vpc_ids):
            vpc = ec2.Vpc.from_lookup(
                self, f"VPC{i}",
                vpc_id=vpc_id
            )

            quarantine_sg = ec2.SecurityGroup(
                self, f"QuarantineSG{i}",
                vpc=vpc,
                security_group_name=f"ir-quarantine-sg-{vpc_id}",
                description="Security Group for isolating EC2 instances during incident response",
                allow_all_outbound=False
            )

            self.quarantine_sg_map[vpc_id] = quarantine_sg.security_group_id
          
    def _create_isolate_ec2_lambda(self):
        self.isolate_ec2_function = _lambda.Function(
            self, "IsolateEC2Lambda",
            function_name="ir-isolate-ec2-lambda",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="isolate_ec2.lambda_handler",
            code=_lambda.Code.from_asset("lambda/isolate_ec2"),
            timeout=Duration.minutes(5),
            environment={
                "QUARANTINE_SG_MAP": json.dumps(self.quarantine_sg_map)
            }
        )

        self.isolate_ec2_function.add_to_role_policy(
            iam.PolicyStatement(
                actions=["ec2:ModifyInstanceAttribute", "ec2:DescribeInstances"],
                resources=["*"]
            )
        )

    def _create_parse_findings_lambda(self):
        self.parse_findings_function = _lambda.Function(
            self, "ParseFindingsLambda",
            function_name="ir-parse-findings-lambda",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="parse_findings.lambda_handler",
            code=_lambda.Code.from_asset("lambda/parse_findings"),
            timeout=Duration.minutes(5)
        )
    
    def _create_quarantine_iam_lambda(self):
         
        self.quarantine_policy = iam.ManagedPolicy(
            self, "QuarantineIAMPolicy",
            managed_policy_name="IrQuarantineIAMPolicy",
            statements=[
                iam.PolicyStatement(
                    effect=iam.Effect.DENY,
                    actions=["*"],
                   resources=["*"]
                )
            ]
        )

        self.quarantine_iam_function = _lambda.Function(
            self, "QuarantineIAMLambda",
            function_name="ir-quarantine-iam-lambda",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="quarantine_iam.lambda_handler",
            code=_lambda.Code.from_asset("lambda/quarantine_iam"),
            timeout=Duration.minutes(5),
            environment={
                "QUARANTINE_POLICY_ARN": self.quarantine_policy.managed_policy_arn
            }
        )

       
        self.quarantine_iam_function.add_to_role_policy(
            iam.PolicyStatement(
                actions=[
                    "iam:AttachUserPolicy",
                    "iam:ListAttachedUserPolicies",
                ],
                resources=[
                    f"arn:aws:iam::{self.account}:user/*",
                    self.quarantine_policy.managed_policy_arn
                ]
            )
        )

    def _create_incident_response_step_functions(self):
        
        self.step_functions_role = iam.Role(
            self, "StepFunctionsRole",
            assumed_by=iam.ServicePrincipal("states.amazonaws.com"),
            inline_policies={
                "LambdaInvokePolicy": iam.PolicyDocument(
                    statements=[
                        iam.PolicyStatement(
                            actions=["lambda:InvokeFunction"],
                            resources=[
                                self.parse_findings_function.function_arn,
                                self.isolate_ec2_function.function_arn,
                                self.quarantine_iam_function.function_arn
                            ]
                        )
                    ]
                ),
                "EC2AutoScalingPolicy": iam.PolicyDocument(
                    statements=[
                        iam.PolicyStatement(
                            actions=[
                                "ec2:ModifyInstanceAttribute",
                                "ec2:CreateTags",
                                "ec2:DescribeVolumes",
                                "ec2:CreateSnapshot",
                                "autoscaling:DescribeAutoScalingInstances",
                                "autoscaling:UpdateAutoScalingGroup",
                                "autoscaling:DetachInstances"
                            ],
                            resources=["*"]
                        )
                    ]
                )
            }
        )
        with open("stepfunctions/incident_response_stepfunctions.asl.json") as f:
            definition = f.read()

        definition = definition.replace("${IsolateEC2LambdaARN}", self.isolate_ec2_function.function_arn)
        definition = definition.replace("${ParseFindingsLambdaARN}", self.parse_findings_function.function_arn)
        definition = definition.replace("${QuarantineIAMLambdaARN}", self.quarantine_iam_function.function_arn)


        self.incident_response_step_functions = sfn.StateMachine(
            self, "IncidentResponseStepFunctions",
            state_machine_name="IncidentResponseStepFunctions",
            definition_body=sfn.DefinitionBody.from_string(definition),
            role=self.step_functions_role
        )