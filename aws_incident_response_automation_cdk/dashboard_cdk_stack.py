from aws_cdk import (
    # Duration,
    Stack,
    aws_s3 as s3,
    aws_lambda as _lambda,
    aws_iam as iam,
    aws_apigateway as apigateway,
    aws_wafv2 as wafv2,
    aws_cloudfront as cloudfront,
    aws_cloudfront_origins as origins,
    aws_s3_deployment as s3deploy
)
from constructs import Construct

class DashboardCdkStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        vpc_ids = self.node.try_get_context("vpc_ids") or []

        self.s3_static_dashboard = s3.Bucket(self, "StaticDashboardBucket", {
            bucket_name=f"static-dashboard-bucket-{self.account}-{self.region}",
            removal_policy=cdk.RemovalPolicy.RETAIN,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            encryption=s3.BucketEncryption.S3_MANAGED,
            versioned=True,
            public_read_access=False
        })

        lambda_role = iam.Role(
            self, "DashboardLambdaRole",
            role_name="dashboard-querry-role-ik2w9tr9",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaBasicExecutionRole")
            ]
        )

        lambda_custom_policy = iam.Policy(
            self, "LambdaQueryPolicy",
            policy_name="lambda-querry-policy",
            statements=[
                iam.PolicyStatement(
                    sid="AthenaActions",
                    effect=iam.Effect.ALLOW,
                    actions=[
                        "athena:StartQueryExecution",
                        "athena:GetQueryExecution",
                        "athena:GetQueryResults",
                        "athena:StopQueryExecution"
                    ],
                    resources=["*"]
                ),
                iam.PolicyStatement(
                    sid="GlueCatalogRead",
                    effect=iam.Effect.ALLOW,
                    actions=[
                        "glue:GetDatabase",
                        "glue:GetDatabases",
                        "glue:GetTable",
                        "glue:GetTables",
                        "glue:GetPartitions"
                    ],
                    resources=["*"]
                ),
                iam.PolicyStatement(
                    sid="S3SourceAndResultAccess",
                    effect=iam.Effect.ALLOW,
                    actions=[
                        "s3:GetBucketLocation",
                        "s3:GetObject",
                        "s3:ListBucket",
                        "s3:PutObject",
                        "s3:AbortMultipartUpload"
                    ],
                    resources=[
                        "arn:aws:s3:::vel-athena-results",
                        "arn:aws:s3:::vel-athena-results/*",
                        "arn:aws:s3:::vel-processed-cloudtrail-logs",
                        "arn:aws:s3:::vel-processed-cloudtrail-logs/*",
                        "arn:aws:s3:::vel-processed-guardduty",
                        "arn:aws:s3:::vel-processed-guardduty/*",
                        "arn:aws:s3:::cloudwatch-formatted",
                        "arn:aws:s3:::cloudwatch-formatted/*"
                    ]
                )
            ]
        )

        lambda_role.attach_inline_policy(lambda_custom_policy)

        self.dashboard_lambda = _lambda.Function(self, "DashboardLambdaFunction", {
            function_name="dashboard-querry",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="dashboard_lambda.lambda_handler",
            code=_lambda.Code.from_asset("lambda/dashboard_lambda"),
            role=lambda_role,
            timeout=cdk.Duration.seconds(30),
            memory_size=256
        })

        self.api = apigtaeway.RestApi(self, "DashboardApiGateway", 
            rest_api_name="dashboard-api",
            description="An API for dashboard use for lambda",
            endpoint_configuration=apigateway.EndpointConfiguration(
                types=[apigateway.EndpointType.REGIONAL]
            ),
            default_cors_preflight_options=apigateway.CorsOptions(
                allow_origins=apigateway.Cors.ALL_ORIGINS,
                allow_methods=apigateway.Cors.ALL_METHODS,
                allow_headers=["Content-Type", "X-Amz-Date", "Authorization", "X-Api-Key"]
            ),
            deploy_options=apigateway.StageOptions(
                stage_name="prod"
            )
        )

        lambda_integration = apigateway.LambdaIntegration(self.dashboard_lambda)

        api.root.add_method("ANY", lambda_integration)

        proxy_resource = api.root.add_proxy(
            default_integration=lambda_integration,
            any_method=True
        )

        web_acl = wafv2.CfnWebACL(
            self, "DashboardWebACL",
            scope="CLOUDFRONT",
            default_action=wafv2.CfnWebACL.DefaultActionProperty(allow={}),
            rules=[
                wafv2.CfnWebACL.RuleProperty(
                    name="AWSManagedRulesCommonRuleSet",
                    priority=1,
                    override_action=wafv2.CfnWebACL.OverrideActionProperty(none={}),
                    statement=wafv2.CfnWebACL.StatementProperty(
                        managed_rule_group_statement=wafv2.CfnWebACL.ManagedRuleGroupStatementProperty(
                            vendor_name="AWS",
                            name="AWSManagedRulesCommonRuleSet"
                        )
                    ),
                    visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                        sampled_requests_enabled=True,
                        cloud_watch_metrics_enabled=True,
                        metric_name="CommonRuleSetMetric"
                    )
                )
            ],
            visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                sampled_requests_enabled=True,
                cloud_watch_metrics_enabled=True,
                metric_name="DashboardWebACL"
            )
        )

        distribution = cloudfront.Distribution(
            self, "DashboardDistribution",
            domain_names=["staticdashboard.website"],
            default_behavior=cloudfront.BehaviorOptions(
                origin=origins.S3BucketOrigin.with_origin_access_control(s3_static_dashboard),
                viewer_protocol_policy=cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
                allowed_methods=cloudfront.AllowedMethods.ALLOW_GET_HEAD_OPTIONS,
                cached_methods=cloudfront.CachedMethods.CACHE_GET_HEAD_OPTIONS,
                cache_policy=cloudfront.CachePolicy.CACHING_OPTIMIZED,
                compress=True
            ),
            additional_behaviors={
                "/prod/*": cloudfront.BehaviorOptions(
                    origin=origins.RestApiOrigin(api),
                    viewer_protocol_policy=cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
                    allowed_methods=cloudfront.AllowedMethods.ALLOW_ALL,
                    cache_policy=cloudfront.CachePolicy.CACHING_DISABLED,
                    origin_request_policy=cloudfront.OriginRequestPolicy.CORS_S3_ORIGIN
                )
            },
            default_root_object="index.html",
            price_class=cloudfront.PriceClass.PRICE_CLASS_100,
            minimum_protocol_version=cloudfront.SecurityPolicyProtocol.TLS_V1_2_2021,
            enable_ipv6=True,
            web_acl_id=web_acl.attr_arn,
            comment="Static Dashboard Distribution"
        )

        s3_static_dashboard.add_to_resource_policy(
            iam.PolicyStatement(
                sid="AllowCloudFrontServicePrincipal",
                effect=iam.Effect.ALLOW,
                principals=[iam.ServicePrincipal("cloudfront.amazonaws.com")],
                actions=["s3:GetObject"],
                resources=[f"arn:aws:s3:::s3-static-dashboard/*"],
                conditions={
                    "StringEquals": {
                        "AWS:SourceArn": f"arn:aws:cloudfront::{self.account}:distribution/{distribution.distribution_id}"
                    }
                }
            )
        )



