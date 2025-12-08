from aws_cdk import (
    Stack,
    CfnOutput,
    aws_guardduty as guardduty,
    aws_cloudtrail as cloudtrail,
    aws_iam as iam,
    aws_ec2 as ec2,
    aws_route53resolver as route53resolver,
)
from constructs import Construct

class SecurityNetworkingStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, 
                 log_list_bucket,
                 processed_cloudtrail_bucket_name: str,
                 processed_cloudwatch_bucket_name: str,
                 processed_guardduty_bucket_name: str,
                 athena_query_results_bucket_name: str,
                 kms_key_arn: str,
                 ir_log_group_name: str,
                 **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        
        self.log_list_bucket = log_list_bucket
        self.log_list_bucket_name = log_list_bucket.bucket_name
        self.processed_cloudtrail_bucket_name = processed_cloudtrail_bucket_name
        self.processed_cloudwatch_bucket_name = processed_cloudwatch_bucket_name
        self.processed_guardduty_bucket_name = processed_guardduty_bucket_name
        self.athena_query_results_bucket_name = athena_query_results_bucket_name
        self.kms_key_arn = kms_key_arn
        self.ir_log_group_name = ir_log_group_name
        
        vpc_ids = self.node.try_get_context("vpc_ids") or []

        self._create_cloudtrail()
        self._add_bucket_policies()
        self._create_security_group()
        
        if vpc_ids:
            self._create_flow_log_iam_role()
            self._create_vpc_flow_logs(vpc_ids)
            self._create_dns_query_logging(vpc_ids)


    def _create_cloudtrail(self):
        self.cloudtrail = cloudtrail.CfnTrail(
            self, "CloudTrail",
            is_multi_region_trail=True,
            include_global_service_events=True,
            s3_bucket_name=self.log_list_bucket_name,
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
                                f"arn:aws:s3:::{self.log_list_bucket_name}/",
                                f"arn:aws:s3:::{self.processed_cloudtrail_bucket_name}/",
                                f"arn:aws:s3:::{self.processed_cloudwatch_bucket_name}/",
                                f"arn:aws:s3:::{self.processed_guardduty_bucket_name}/",
                                f"arn:aws:s3:::{self.athena_query_results_bucket_name}/"
                            ]
                        ),
                    ]
                )
            ]
        )

    def _add_bucket_policies(self):
        
        # CloudWatch Logs policies
        CW_LOGS_PRINCIPAL = iam.ServicePrincipal(f"logs.{self.region}.amazonaws.com")
        CW_LOGS_ARN = f"arn:aws:logs:{self.region}:{self.account}:log-group:*"
        
        self.log_list_bucket.add_to_resource_policy(
            iam.PolicyStatement(
                sid="AllowCloudWatchLogsGetBucketAcl",
                effect=iam.Effect.ALLOW,
                principals=[CW_LOGS_PRINCIPAL],
                actions=["s3:GetBucketAcl"],
                resources=[f"arn:aws:s3:::{self.log_list_bucket_name}"],
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
                resources=[f"arn:aws:s3:::{self.log_list_bucket_name}/*"],
                conditions={
                    "StringEquals": {"aws:SourceAccount": self.account},
                    "ArnLike": {"aws:SourceArn": CW_LOGS_ARN}
                }
            )
        )
        
        # CloudTrail policies
        CT_PRINCIPAL = iam.ServicePrincipal("cloudtrail.amazonaws.com")
        CT_ARN = f"arn:aws:cloudtrail:{self.region}:{self.account}:trail/*"

        self.log_list_bucket.add_to_resource_policy(
            iam.PolicyStatement(
                sid="AllowCloudTrailAclCheck",
                effect=iam.Effect.ALLOW,
                principals=[CT_PRINCIPAL],
                actions=["s3:GetBucketAcl"],
                resources=[f"arn:aws:s3:::{self.log_list_bucket_name}"],
                conditions={
                    "StringEquals": {"aws:SourceAccount": self.account},
                    "ArnLike": {"aws:SourceArn": CT_ARN}
                }
            )
        )

        self.log_list_bucket.add_to_resource_policy(
            iam.PolicyStatement(
                sid="AllowCloudTrailWrite",
                effect=iam.Effect.ALLOW,
                principals=[CT_PRINCIPAL],
                actions=["s3:PutObject"],
                resources=[f"arn:aws:s3:::{self.log_list_bucket_name}/AWSLogs/{self.account}/*"],
                conditions={
                    "StringEquals": {
                        "s3:x-amz-acl": "bucket-owner-full-control",
                        "aws:SourceAccount": self.account
                    },
                    "ArnLike": {"aws:SourceArn": CT_ARN}
                }
            )
        )

    def _create_security_group(self):
        vpc_ids = self.node.try_get_context("vpc_ids") or []

        if vpc_ids:
            self.quarantine_sg = ec2.CfnSecurityGroup(
                self, "QuarantineSecurityGroup",
                group_description="Security Group for Quarantined Instances",
                vpc_id=vpc_ids[0], 
                group_name="QuarantineSecurityGroup",
                security_group_egress=[] 
            )
            
            # Export the security group ID for other stacks
            CfnOutput(
                self, "QuarantineSGId",
                value=self.quarantine_sg.ref,
                export_name=f"{self.stack_name}-QuarantineSGId",
                description="Security group ID for quarantined instances"
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
                log_group_name=self.ir_log_group_name,
                deliver_logs_permission_arn=self.flow_logs_role.role_arn
            )

    def _create_dns_query_logging(self, vpc_ids):
        resolver_query_logging_config = route53resolver.CfnResolverQueryLoggingConfig(
            self, "ResolverQueryLoggingConfig",
            destination_arn=f"arn:aws:logs:{self.region}:{self.account}:log-group:{self.ir_log_group_name}",
        )

        for i, vpc_id in enumerate(vpc_ids):
            route53resolver.CfnResolverQueryLoggingConfigAssociation(
                self, f"ResolverQueryLoggingConfigAssociation{i}",
                resolver_query_log_config_id=resolver_query_logging_config.ref,
                resource_id=vpc_id
            )