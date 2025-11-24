import aws_cdk as core
import aws_cdk.assertions as assertions

from aws_incident_response_automation_cdk.aws_incident_response_automation_cdk_stack import AwsIncidentResponseAutomationCdkStack

# example tests. To run these tests, uncomment this file along with the example
# resource in aws_incident_response_automation_cdk/aws_incident_response_automation_cdk_stack.py
def test_sqs_queue_created():
    app = core.App()
    stack = AwsIncidentResponseAutomationCdkStack(app, "aws-incident-response-automation-cdk")
    template = assertions.Template.from_stack(stack)

#     template.has_resource_properties("AWS::SQS::Queue", {
#         "VisibilityTimeout": 300
#     })
