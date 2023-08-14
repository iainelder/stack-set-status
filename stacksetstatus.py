import re
from typing import Dict, FrozenSet, Optional, Union

ReasonMap = Dict[str, Union[str, FrozenSet[str]]]

REASON_MAP: ReasonMap = {
    "Null": r"^null$",
    "No updates": r"No updates are to be performed\.",
    "Initiated": frozenset([r"^User initiated operation$", r"^User Initiated$"]),
    "Cancelled by failures": r"Cancelled since failure tolerance has exceeded",
    "Trust missing": r"Account (.*?) should have '(.*?)' role with trust relationship to Role '(.*?)'\.",
    "Account suspended": r"ACCOUNT_SUSPENDED",
    "Default role creation error": r"^DEFAULT_ROLE_CREATION_ERROR$",
    "Failed to get stack status": r"^Failed to get stack status$",
    "STS not activated": r"STS is not activated in this region for account:(.*?). Your account administrator can activate STS in this region using the IAM Console\..*",
    "Denied instance operation": r"User: arn:aws:sts::(.*?):assumed-role/(stacksets-exec-.*?)/(.*?) is not authorized to perform: (.*?) on resource: arn:aws:cloudformation:(.*?):(.*?):stack/(StackSet-.*?)/\* with an explicit deny",
    "SCP denied instance operation": r"^User: arn:aws:sts::(.*?):assumed-role/(stacksets-exec-.*?)/(.*?) is not authorized to perform: (.*?) on resource: arn:aws:cloudformation:(.*?):(.*?):stack/StackSet-(.*?) with an explicit deny in a service control policy$",
    "SCP denial to resource": r"ResourceLogicalId:(.*?), ResourceType:(.*?), ResourceStatusReason:User: (.*?) is not authorized to perform: (.*?) with an explicit deny in a service control policy \(Service: (.*?); Status Code: (.*?); Error Code: (.*?); Request ID: (.*?); Proxy: (.*?)\)\..*",
    "Delivery channel limit": r"ResourceLogicalId:(.*?), ResourceType:(.*?), ResourceStatusReason:Failed to put delivery channel '(.*?)' because the maximum number of delivery channels: (.*?) is reached\. \(Service: (.*?); Status Code: (.*?); Error Code: (.*?); Request ID: (.*?); Proxy: (.*?)\)\.",
    "Unupdatable": r"Stack:(.*?) is in (.*?) state and can not be updated\.",
    "Resource already exists": r"ResourceLogicalId:(.*), ResourceType:(.*), ResourceStatusReason:(.*) already exists\.",
    "Resource already exists in stack": r"ResourceLogicalId:(.*), ResourceType:(.*), ResourceStatusReason:(.*) already exists in stack (.*)\.",
    "SSM parameter on advanced tier": r"ResourceLogicalId:(.*?), ResourceType:AWS::SSM::Parameter, ResourceStatusReason:This parameter uses the advanced-parameter tier. You can't downgrade a parameter from the advanced-parameter tier to the standard-parameter tier. If necessary, you can delete the advanced parameter and recreate it as a standard parameter. Be aware that standard parameters have a value limit of 4096 characters. \(Service: AmazonSSM; Status Code: 400; Error Code: ValidationException; Request ID: (.*?); Proxy: (.*?)\)\.",
    "Invalid principal in key policy": r'ResourceLogicalId:(.*?), ResourceType:AWS::KMS::Key, ResourceStatusReason:Resource handler returned message: "Policy contains a statement with one or more invalid principals. \(Service: Kms, Status Code: 400, Request ID: (.*?)\)" \(RequestToken: (.*?), HandlerErrorCode: InvalidRequest\).',
    "SLR exists with different description": r"ResourceLogicalId:(.*?), ResourceType:AWS::IAM::ServiceLinkedRole, ResourceStatusReason:SLR \[(.*?)\] already exists but has a different description: \[(.*?)\]\. Please verify your SLR use case\. If you are sure the use case is correct please modify your CloudFormation template and keep SLR description consistent\.\.",
}


def summarize_reason(
    status_reason: Optional[str],
    reason_map: ReasonMap=REASON_MAP,
    default: str="__Unmatched",
) -> str:
    """Summarizes the status reason by mapping from a matching pattern. Returns default for no match."""

    # Visidata uses visidata.wrappers.TypedWrapper to represent null values.
    # I don't know how to import that type when curses is unitialized.
    if not isinstance(status_reason, str):
        return summarize_reason("null", reason_map, default)

    for summary, patternlist in reason_map.items():
        if isinstance(patternlist, str):
            patternlist = frozenset([patternlist])
        for pattern in patternlist:
            if re.search(pattern, status_reason):
                return summary

    return default
