from aws_cdk import (
    Stack,
    aws_s3 as s3,
    aws_guardduty as guardduty,
    aws_cloudtrail as cloudtrail,
    aws_logs as logs,
    aws_iam as iam,
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


    def _create_storage_infrastructure(self):

        
        self.log_list_bucket = s3.Bucket(
            self, "LogListBucket",
            bucket_name=f"incident-response-log-list-bucket-{self.account}-{self.region}",
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
        )
   
        