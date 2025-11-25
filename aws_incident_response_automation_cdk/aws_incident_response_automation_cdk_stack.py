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

    def _create_storage_infrastructure(self):
        self.log_list_bucket = s3.Bucket(
            self, "LogListBucket",
            bucket_name=f"incident-response-log-list-bucket-{self.account}-{self.region}",
            removal_policy=RemovalPolicy.RETAIN
        )
    def _enable_guardduty(self):
        self.guardduty_detector = guardduty.CfnDetector(
            self, "GuardDutyDetector",
            enable=True,
            finding_publishing_frequency="ONE_HOUR"
        )    
    def _create_cloudtrail(self):
        self.cloudtrail_cloudwatch_log_group = logs.LogGroup(
            self, "CloudTrailCloudWatchLogGroup",
            log_group_name=f"incident-response-cloudtrail-log-group-{self.account}-{self.region}",
            retention=logs.RetentionDays.ONE_DAY,
            removal_policy=RemovalPolicy.RETAIN
        )

        self.cloudtrail_cloudwatch_log_group.grant_write(iam.ServicePrincipal("cloudtrail.amazonaws.com"))

        self.cloudtrail = cloudtrail.Trail(
            self, "CloudTrail",
            trail_name=f"incident-response-cloudtrail-{self.account}-{self.region}",
            is_multi_region_trail=True,
            send_to_cloud_watch_logs=True,
            bucket=self.log_list_bucket,  
            s3_key_prefix="cloudtrail-logs/", 
            cloud_watch_log_group=self.cloudtrail_cloudwatch_log_group
        )
        