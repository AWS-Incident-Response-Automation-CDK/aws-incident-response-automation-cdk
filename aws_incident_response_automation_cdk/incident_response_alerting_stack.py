from aws_cdk import (
    Stack,
    Duration,
    aws_events as events,
    aws_events_targets as targets,
    aws_iam as iam,
    aws_lambda as _lambda,
    aws_sns as sns,
    aws_sns_subscriptions as sns_subscriptions,
    aws_stepfunctions as sfn,
)
from constructs import Construct

class IncidentResponseAlertingStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, 
                 isolation_sg_id: str = "",
                 **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        
        self.isolation_sg_id = isolation_sg_id

        self._create_sns_topic()
        self._create_alert_dispatch()
        self._create_incident_response_lambdas()
        self._create_incident_response_step_functions()
        self._create_event_bridge_rules()

    def _create_sns_topic(self):
        self.ir_alert_topic = sns.Topic(
            self, "IRAlertTopic",
            topic_name="IncidentResponseAlerts"
        )

    def _create_alert_dispatch(self):
        alert_emails = self.node.try_get_context("alert_email") or []

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
                actions=["sns:Publish", "ses:SendEmail", "ses:SendRawEmail"],
                resources=["*"]
            )
        )

        self.ir_alert_topic.add_subscription(
            sns_subscriptions.LambdaSubscription(self.alert_dispatch_function)
        )

    def _create_incident_response_lambdas(self):
        # Parse Findings Lambda
        self.parse_findings_function = _lambda.Function(
            self, "ParseFindingsLambda",
            function_name="ir-parse-findings-lambda",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="parse_findings.lambda_handler",
            code=_lambda.Code.from_asset("lambda/parse_findings"),
            timeout=Duration.minutes(5)
        )

        # Isolate EC2 Lambda
        self.isolate_ec2_function = _lambda.Function(
            self, "IsolateEC2Lambda",
            function_name="ir-isolate-ec2-lambda",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="isolate_ec2.lambda_handler",
            code=_lambda.Code.from_asset("lambda/isolate_ec2"),
            timeout=Duration.minutes(5),
            environment={
                "ISOLATION_SG_ID": self.isolation_sg_id
            }
        )

        self.isolate_ec2_function.add_to_role_policy(
            iam.PolicyStatement(
                actions=["ec2:ModifyInstanceAttribute", "ec2:DescribeInstances"],
                resources=["*"]
            )
        )

        # Quarantine IAM Lambda
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
                actions=["iam:AttachUserPolicy", "iam:ListAttachedUserPolicies"],
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