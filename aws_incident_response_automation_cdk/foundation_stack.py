from aws_cdk import (
    Stack,
    CfnOutput,
    aws_s3 as s3,
    aws_logs as logs,
    aws_kms as kms,
    aws_iam as iam,
    aws_guardduty as guardduty,
    RemovalPolicy,
)
from constructs import Construct

class FoundationStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        self._create_storage_infrastructure()
        self._create_log_group()
        self._create_kms_key()
        self._enable_guardduty()
        self._create_outputs()

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

        self.processed_cloudwatch_logs_bucket = s3.Bucket(
            self, "ProcessedCloudWatchLogsBucket",
            bucket_name=f"processed-cloudwatch-logs-{self.account}-{self.region}",
            encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            versioned=True,
            removal_policy=RemovalPolicy.DESTROY
        )

        self.processed_guardduty_findings_bucket = s3.Bucket(
            self, "ProcessedGuardDutyFindingsBucket",
            bucket_name=f"processed-guardduty-findings-{self.account}-{self.region}",
            encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            versioned=True,
            removal_policy=RemovalPolicy.DESTROY
        )

    def _create_kms_key(self):
        self.kms_key = kms.Key(
            self, "GuardDutyKMSKey",
            description="KMS Key for GuardDuty findings encryption",
            enable_key_rotation=True,
            removal_policy=RemovalPolicy.DESTROY
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
                destination_arn=f"arn:aws:s3:::{self.log_list_bucket.bucket_name}",
                kms_key_arn=self.kms_key.key_arn
            )
        )
        self.log_list_bucket.add_to_resource_policy(
        iam.PolicyStatement(
            sid="AllowGuardDutyPutObject",
            effect=iam.Effect.ALLOW,
            principals=[iam.ServicePrincipal("guardduty.amazonaws.com")],
            actions=["s3:PutObject"],
            resources=[f"{self.log_list_bucket.bucket_arn}/*"],
            conditions={"StringEquals": {"aws:SourceAccount": self.account}}
        )
    )

        self.log_list_bucket.add_to_resource_policy(
        iam.PolicyStatement(
            sid="AllowGuardDutyGetBucketLocation",
            effect=iam.Effect.ALLOW,
            principals=[iam.ServicePrincipal("guardduty.amazonaws.com")],
            actions=["s3:GetBucketLocation"],
            resources=[self.log_list_bucket.bucket_arn],
            conditions={"StringEquals": {"aws:SourceAccount": self.account}}
        )
    )
    def _create_log_group(self):
        self.ir_log_group = logs.LogGroup(
            self, "IRLogGroup",
            log_group_name="/aws/incident-response/centralized-logs",
            retention=logs.RetentionDays.ONE_MONTH,
            removal_policy=RemovalPolicy.DESTROY
        )


    def _create_outputs(self):
        CfnOutput(self, "LogListBucketName", value=self.log_list_bucket.bucket_name)
        CfnOutput(self, "ProcessedCloudTrailBucketName", value=self.processed_cloudtrail_logs_bucket.bucket_name)
        CfnOutput(self, "ProcessedCloudWatchBucketName", value=self.processed_cloudwatch_logs_bucket.bucket_name)
        CfnOutput(self, "ProcessedGuardDutyBucketName", value=self.processed_guardduty_findings_bucket.bucket_name)
        CfnOutput(self, "AthenaQueryResultsBucketName", value=self.athena_query_results_bucket.bucket_name)
        CfnOutput(self, "KMSKeyArn", value=self.kms_key.key_arn)
        CfnOutput(self, "IRLogGroupName", value=self.ir_log_group.log_group_name)