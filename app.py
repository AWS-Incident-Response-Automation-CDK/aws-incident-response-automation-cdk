#!/usr/bin/env python3
import os

import aws_cdk as cdk

from aws_incident_response_automation_cdk.aws_incident_response_automation_cdk_stack import AwsIncidentResponseAutomationCdkStack
from aws_incident_response_automation_cdk.dashboard_cdk_stack import DashboardCdkStack

app = cdk.App()
env= cdk.Environment(account=os.getenv('CDK_DEFAULT_ACCOUNT'), region=os.getenv('CDK_DEFAULT_REGION'))
AwsIncidentResponseAutomationCdkStack(app, "AwsIncidentResponseAutomationCdkStack",
    env=env,
    )

DashboardCdkStack(app, "DashboardCdkStack",
    env=env,
    )
app.synth()
