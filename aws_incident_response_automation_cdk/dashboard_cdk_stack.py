import aws_cdk as cdk
from aws_cdk import (
    # Duration,
    CfnOutput,
    Stack,
    aws_s3 as s3,
    aws_lambda as _lambda,
    aws_iam as iam,
    aws_apigateway as apigateway,
    aws_wafv2 as wafv2,
    aws_cloudfront as cloudfront,
    aws_cloudfront_origins as origins,
    aws_s3_deployment as s3deploy,
    aws_cognito as cognito,
    custom_resources as cr
)
from constructs import Construct

class DashboardCdkStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        self.s3_static_dashboard = s3.Bucket(self, "StaticDashboardBucket", 
            bucket_name=f"static-dashboard-bucket-{self.account}-{self.region}",
            removal_policy=cdk.RemovalPolicy.DESTROY,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            encryption=s3.BucketEncryption.S3_MANAGED,
            versioned=True,
            public_read_access=False,
            auto_delete_objects=True
        )

        lambda_role = iam.Role(
            self, "DashboardLambdaRole",
            role_name="dashboard-query-role",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaBasicExecutionRole")
            ]
        )

        lambda_custom_policy = iam.Policy(
            self, "LambdaQueryPolicy",
            policy_name="lambda-query-policy",
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
                        f"arn:aws:s3:::athena-query-results-{self.account}-{self.region}",
                        f"arn:aws:s3:::athena-query-results-{self.account}-{self.region}/*",
                        f"arn:aws:s3:::processed-cloudtrail-logs-{self.account}-{self.region}",
                        f"arn:aws:s3:::processed-cloudtrail-logs-{self.account}-{self.region}/*",
                        f"arn:aws:s3:::processed-guardduty-findings-{self.account}-{self.region}",
                        f"arn:aws:s3:::processed-guardduty-findings-{self.account}-{self.region}/*",
                        f"arn:aws:s3:::processed-cloudwatch-logs-{self.account}-{self.region}",
                        f"arn:aws:s3:::processed-cloudwatch-logs-{self.account}-{self.region}/*"
                    ]
                )
            ]
        )

        lambda_role.attach_inline_policy(lambda_custom_policy)

        self.dashboard_lambda = _lambda.Function(self, "DashboardLambdaFunction", 
            function_name="dashboard-query",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="dashboard_lambda.lambda_handler",
            code=_lambda.Code.from_asset("lambda/dashboard_query"),
            role=lambda_role,
            timeout=cdk.Duration.seconds(300),
            memory_size=256,
            environment={
                "ATHENA_OUTPUT_BUCKET": f"athena-query-results-{self.account}-{self.region}",
                "ACCOUNT_ID": self.account,
                "REGION": self.region
            }
        )

        self.api = apigateway.RestApi(self, "DashboardApiGateway", 
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

        logs_root = self.api.root.add_resource("logs")

        #logs/guardduty
        logs_root.add_resource("guardduty").add_method(
            "GET",
            apigateway.LambdaIntegration(self.dashboard_lambda),
        )

        #logs/cloudtrail
        logs_root.add_resource("cloudtrail").add_method(
            "GET",
            apigateway.LambdaIntegration(self.dashboard_lambda),
        )

        #logs/vpc
        logs_root.add_resource("vpc").add_method(
            "GET",
            apigateway.LambdaIntegration(self.dashboard_lambda),
        )

        #logs/eni_logs
        logs_root.add_resource("eni_logs").add_method(
            "GET",
            apigateway.LambdaIntegration(self.dashboard_lambda),
        )

        lambda_integration = apigateway.LambdaIntegration(self.dashboard_lambda)

        origin_access_identity = cloudfront.OriginAccessIdentity(self, "OAI")
        self.s3_static_dashboard.grant_read(origin_access_identity)

        distribution = cloudfront.Distribution(
            self, "DashboardDistribution",
            default_behavior=cloudfront.BehaviorOptions(
                origin=origins.S3BucketOrigin.with_origin_access_control(self.s3_static_dashboard),
                viewer_protocol_policy=cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
                allowed_methods=cloudfront.AllowedMethods.ALLOW_GET_HEAD_OPTIONS,
                cached_methods=cloudfront.CachedMethods.CACHE_GET_HEAD_OPTIONS,
                cache_policy=cloudfront.CachePolicy.CACHING_OPTIMIZED,
                compress=True
            ),
            additional_behaviors={
                "/logs/*": cloudfront.BehaviorOptions(
                    origin=origins.RestApiOrigin(self.api),
                    viewer_protocol_policy=cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
                    allowed_methods=cloudfront.AllowedMethods.ALLOW_ALL,
                    cache_policy=cloudfront.CachePolicy.CACHING_DISABLED,
                    origin_request_policy=cloudfront.OriginRequestPolicy.ALL_VIEWER_EXCEPT_HOST_HEADER,
                )
            },
            default_root_object="index.html",
            price_class=cloudfront.PriceClass.PRICE_CLASS_100,
            minimum_protocol_version=cloudfront.SecurityPolicyProtocol.TLS_V1_2_2021,
            enable_ipv6=True,
            #web_acl_id=web_acl.attr_arn,
            comment="Static Dashboard Distribution",
            error_responses=[
                cloudfront.ErrorResponse(
                    http_status=403,
                    response_http_status=200,
                    response_page_path="/index.html"
                ),
                cloudfront.ErrorResponse(
                    http_status=404,
                    response_http_status=200,
                    response_page_path="/index.html"
                )
            ]
        )

        user_pool = cognito.UserPool(self, "DashboardUserPool",
            user_pool_name="dashboard-user-pool",
            self_sign_up_enabled=True,
            sign_in_aliases=cognito.SignInAliases(email=True, username=True),
            auto_verify=cognito.AutoVerifiedAttrs(email=True),
            standard_attributes=cognito.StandardAttributes(
                email=cognito.StandardAttribute(required=True, mutable=False)
            ),
            password_policy=cognito.PasswordPolicy(
                min_length=8,
                require_lowercase=True,
                require_uppercase=True,
                require_digits=True,
                require_symbols=True
            ),
            account_recovery=cognito.AccountRecovery.EMAIL_ONLY
        )

        user_pool_client = user_pool.add_client("DashboardUserPoolClient",
            user_pool_client_name="dashboard-user-pool-client",
            auth_flows=cognito.AuthFlow(
                user_password=True,
                user_srp=True,
            ),
            prevent_user_existence_errors=True,
            o_auth=cognito.OAuthSettings(
                flows=cognito.OAuthFlows(
                    authorization_code_grant=True
                ),
                scopes=[cognito.OAuthScope.OPENID, cognito.OAuthScope.PHONE, cognito.OAuthScope.EMAIL, cognito.OAuthScope.PROFILE],
                callback_urls=[f"https://{distribution.domain_name}"],
                logout_urls=[f"https://{distribution.domain_name}"]
            )
        )

        user_pool_domain = user_pool.add_domain("UserPoolDomain",
            cognito_domain=cognito.CognitoDomainOptions(
                domain_prefix=f"dashboard-login-{self.account}"
            ),
            managed_login_version=cognito.ManagedLoginVersion.NEWER_MANAGED_LOGIN
        )

        managed_login_branding = cognito.CfnManagedLoginBranding(
            self, "ManagedLoginBranding",
            user_pool_id=user_pool.user_pool_id,
            client_id=user_pool_client.user_pool_client_id,
            use_cognito_provided_values=True
        )

        self.s3_static_dashboard.add_to_resource_policy(
            iam.PolicyStatement(
                sid="AllowCloudFrontServicePrincipal",
                effect=iam.Effect.ALLOW,
                principals=[iam.ServicePrincipal("cloudfront.amazonaws.com")],
                actions=["s3:GetObject"],
                resources=[f"arn:aws:s3:::{self.s3_static_dashboard.bucket_name}/*"],
                conditions={
                    "StringEquals": {
                        "AWS:SourceArn": f"arn:aws:cloudfront::{self.account}:distribution/{distribution.distribution_id}"
                    }
                }
            )
        )

        config_data = {
            "apiBaseUrl": f"https://{distribution.domain_name}",
            "region": self.region,
            "cognito": {
                "userPoolId": user_pool.user_pool_id,
                "clientId": user_pool_client.user_pool_client_id,
                "domain": f"{user_pool_domain.domain_name}.auth.{self.region}.amazoncognito.com",
                "redirectUri": f"https://{distribution.domain_name}"
            }
        }

        config_writer = cr.AwsCustomResource(self, "ConfigJsonWriter",
            on_update=cr.AwsSdkCall(
                service="S3",
                action="putObject",
                parameters={
                    "Bucket": self.s3_static_dashboard.bucket_name,
                    "Key": "config.json",
                    "Body": Stack.of(self).to_json_string(config_data),
                    "ContentType": "application/json",
                    "CacheControl": "no-cache, no-store, must-revalidate"
                },
                physical_resource_id=cr.PhysicalResourceId.of("ConfigJsonWriter")
            ),
            policy=cr.AwsCustomResourcePolicy.from_statements([
                iam.PolicyStatement(
                    actions=["s3:PutObject"],
                    resources=[f"{self.s3_static_dashboard.bucket_arn}/config.json"]
                )
            ])
        )

        s3deploy.BucketDeployment(self, "DeployStaticDashboard", 
            sources=[s3deploy.Source.asset("react/dist")],
            destination_bucket=self.s3_static_dashboard,
            distribution=distribution,
            distribution_paths=["/*"],
            prune=False
        )

        config_writer.node.add_dependency(self.s3_static_dashboard)

        CfnOutput(
            self, "CloudfrontURL",
            value=f"https://{distribution.domain_name}",
        )
