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
    Duration,
    RemovalPolicy,
)
from constructs import Construct

class AwsIncidentResponseAutomationCdkStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        self._create_storage_infrastructure()
        self._enable_guardduty()
        self._create_cloudtrail()
        self._add_bucket_policies()
        self._create_glue_table()
        self._create_cloudtrail_etl()


    def _create_storage_infrastructure(self):

        
        self.log_list_bucket = s3.Bucket(
            self, "LogListBucket",
            bucket_name=f"incident-response-log-list-bucket-{self.account}-{self.region}",
            encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            versioned=True,
            removal_policy=RemovalPolicy.DESTROY
        )

        self.processed_cloudtrail_logs_bucket = s3.Bucket(
            self, "ProcessedCloudTrailLogsBucket",
            bucket_name=f"processed-cloudtrail-logs-{self.account}-{self.region}",
            encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            versioned=True,
            removal_policy=RemovalPolicy.DESTROY
        )

        self.athena_query_results_bucket = s3.Bucket(
            self, "AthenaQueryResultsBucket",
            bucket_name=f"athena-query-results-{self.account}-{self.region}",
            encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            versioned=True,
            removal_policy=RemovalPolicy.DESTROY
        )

    def _add_bucket_policies(self):

        GD_DETECTOR_ID = self.guardduty_detector.ref
        
        GD_ARN = f"arn:aws:guardduty:{self.region}:{self.account}:detector/{GD_DETECTOR_ID}"

        # CT_ARN = self.cloudtrail.attr_arn


        bucket_arn = self.log_list_bucket.bucket_arn
        bucket_objects_arn = self.log_list_bucket.arn_for_objects("*")

        self.log_list_bucket.add_to_resource_policy(
            iam.PolicyStatement(
                sid="DenyNonHTTPSAccess",
                effect=iam.Effect.DENY,
                principals=[iam.AnyPrincipal()], 
                actions=["s3:*"],
                resources=[bucket_arn, bucket_objects_arn],
                conditions={"Bool": {"aws:SecureTransport": "false"}}
            )
        )

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
        
        # CT_PRINCIPAL = iam.ServicePrincipal("cloudtrail.amazonaws.com")
        
        # self.log_list_bucket.add_to_resource_policy(
        #     iam.PolicyStatement(
        #         sid="AllowCloudTrailAclCheck",
        #         effect=iam.Effect.ALLOW,
        #         principals=[CT_PRINCIPAL],
        #         actions=["s3:GetBucketAcl"],
        #         resources=[bucket_arn],
        #         conditions={"StringEquals": {"AWS:SourceArn": CT_ARN}}
        #     )
        # )

        # self.log_list_bucket.add_to_resource_policy(
        #     iam.PolicyStatement(
        #         sid="AllowCloudTrailWrite",
        #         effect=iam.Effect.ALLOW,
        #         principals=[CT_PRINCIPAL],
        #         actions=["s3:PutObject"],
        #         resources=[
        #             self.log_list_bucket.arn_for_objects(f"AWSLogs/{self.account}/*")
        #         ],
        #         conditions={
        #             "StringEquals": {
        #                 "s3:x-amz-acl": "bucket-owner-full-control",
        #                 "AWS:SourceArn": CT_ARN
        #             }
        #         }
        #     )
        # )

    def _enable_guardduty(self):
        self.guardduty_detector = guardduty.CfnDetector(
            self, "GuardDutyDetector",
            enable=True,
            finding_publishing_frequency="ONE_HOUR"
        )

        # self.guardduty_publishing_destination = guardduty.CfnPublishingDestination(
        #     self, "GuardDutyS3Publishing",
        #     detector_id=self.guardduty_detector.ref,
        #     destination_type="S3",
        #     destination_properties=guardduty.CfnPublishingDestination.CFNDestinationPropertiesProperty(
        #         destination_arn=self.log_list_bucket.bucket_arn,
        #         kms_key_arn=None
        #     )
        # )
  
    def _create_cloudtrail(self):
        self.cloudtrail_cloudwatch_log_group = logs.LogGroup(
            self, "CloudTrailCloudWatchLogGroup",
            log_group_name=f"incident-response-cloudtrail-log-group-{self.account}-{self.region}",
            retention=logs.RetentionDays.THREE_MONTHS,
            removal_policy=RemovalPolicy.DESTROY
        )

        self.cloudtrail = cloudtrail.Trail( 
            self, "CloudTrail",
            trail_name=f"incident-response-cloudtrail-{self.account}-{self.region}",
            is_multi_region_trail=True,
            bucket=self.log_list_bucket,            
            enable_file_validation=True,
            cloud_watch_log_group=self.cloudtrail_cloudwatch_log_group,
            management_events=cloudtrail.ReadWriteType.WRITE_ONLY,
        )

    def _create_glue_table(self):
        self.glue_database = glue.CfnDatabase(
            self, "SecurityLogsDatabase",
            catalog_id=self.account,
            database_input=glue.CfnDatabase.DatabaseInputProperty(
                name="security_logs"
            )
        )

        self.glue_table = glue.CfnTable(
            self, "ProcessedCloudTrailTable",
            catalog_id=self.account,
            database_name="security_logs",
            table_input=glue.CfnTable.TableInputProperty(
                name="processed_cloudtrail",
                table_type="EXTERNAL_TABLE",
                parameters={
                    "classification": "json",
                    "compressionType": "gzip"
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
                        glue.CfnTable.ColumnProperty(name="date", type="string"),
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
                    glue.CfnTable.ColumnProperty(name="year", type="string"),
                    glue.CfnTable.ColumnProperty(name="month", type="string"),
                    glue.CfnTable.ColumnProperty(name="day", type="string")
                ]
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
                "DESTINATION_BUCKET": self.processed_cloudtrail_logs_bucket.bucket_name,
                "DATABASE_NAME": "security_logs",
                "TABLE_NAME": "processed_cloudtrail",
                "S3_LOCATION": f"s3://{self.processed_cloudtrail_logs_bucket.bucket_name}/processed-cloudtrail/"
            }
        )
        self.cloudtrail_etl_function.add_to_role_policy(
            iam.PolicyStatement(
                actions=["s3:GetObject", "s3:PutObject"],
                resources=[
                    self.log_list_bucket.arn_for_objects("*"),
                    self.processed_cloudtrail_logs_bucket.arn_for_objects("*")
                ]
            )
        )

        self.cloudtrail_etl_function.add_to_role_policy(
            iam.PolicyStatement(
                actions=["glue:CreatePartition", "glue:GetPartition"],
                resources=[
                    f"arn:aws:glue:{self.region}:{self.account}:catalog",
                    f"arn:aws:glue:{self.region}:{self.account}:database/security_logs",
                    f"arn:aws:glue:{self.region}:{self.account}:table/security_logs/processed_cloudtrail"
                ]
            )
        )

        self.log_list_bucket.add_event_notification(
            s3.EventType.OBJECT_CREATED,
            s3n.LambdaDestination(self.cloudtrail_etl_function),
            s3.NotificationKeyFilter(prefix=f"AWSLogs/{self.account}/CloudTrail/")
        )

        