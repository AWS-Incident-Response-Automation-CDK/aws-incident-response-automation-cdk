#!/usr/bin/env python3
import os

import aws_cdk as cdk

from aws_incident_response_automation_cdk.foundation_stack import FoundationStack
from aws_incident_response_automation_cdk.security_networking_stack import SecurityNetworkingStack
from aws_incident_response_automation_cdk.data_processing_stack import DataProcessingStack
from aws_incident_response_automation_cdk.incident_response_alerting_stack import IncidentResponseAlertingStack
from aws_incident_response_automation_cdk.dashboard_cdk_stack import DashboardCdkStack

app = cdk.App()

env=cdk.Environment(
    account=os.getenv('CDK_DEFAULT_ACCOUNT'), 
    region=os.getenv('CDK_DEFAULT_REGION')
)

# Foundation Stack
foundation_stack = FoundationStack(app, "FoundationStack",
    env=env,
)

# Security Networking Stack
security_networking_stack = SecurityNetworkingStack(app, "SecurityNetworkingStack",
    log_list_bucket=foundation_stack.log_list_bucket,
    processed_cloudtrail_bucket_name=foundation_stack.processed_cloudtrail_logs_bucket.bucket_name,
    processed_cloudwatch_bucket_name=foundation_stack.processed_cloudwatch_logs_bucket.bucket_name,
    processed_guardduty_bucket_name=foundation_stack.processed_guardduty_findings_bucket.bucket_name,
    athena_query_results_bucket_name=foundation_stack.athena_query_results_bucket.bucket_name,
    kms_key_arn=foundation_stack.kms_key.key_arn,
    ir_log_group_name=foundation_stack.ir_log_group.log_group_name,
    env=env,
)
security_networking_stack.add_dependency(foundation_stack)

# Data Processing Stack
data_processing_stack = DataProcessingStack(app, "DataProcessingStack",
    log_list_bucket=foundation_stack.log_list_bucket,
    processed_cloudtrail_bucket_name=foundation_stack.processed_cloudtrail_logs_bucket.bucket_name,
    processed_cloudwatch_bucket_name=foundation_stack.processed_cloudwatch_logs_bucket.bucket_name,
    processed_guardduty_bucket_name=foundation_stack.processed_guardduty_findings_bucket.bucket_name,
    kms_key_arn=foundation_stack.kms_key.key_arn,
    ir_log_group_name=foundation_stack.ir_log_group.log_group_name,
    env=env,
)
data_processing_stack.add_dependency(foundation_stack)

# Incident Response Alerting Stack
incident_response_stack = IncidentResponseAlertingStack(app, "IncidentResponseAlertingStack",
    isolation_sg_id=security_networking_stack.quarantine_sg.ref if hasattr(security_networking_stack, 'quarantine_sg') else "",
    env=env,
)
incident_response_stack.add_dependency(security_networking_stack)

# Dashboard Stack
dashboard_stack = DashboardCdkStack(app, "DashboardCdkStack",
    env=env,
)

app.synth()
