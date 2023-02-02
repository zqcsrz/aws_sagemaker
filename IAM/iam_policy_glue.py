import json
import logging
import operator
import pprint
import time

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)
iam = boto3.resource('iam')

def list_policies(scope):
    """
    Lists the policies in the current account.
    :param scope: Limits the kinds of policies that are returned. For example,
                  'Local' specifies that only locally managed policies are returned.
    :return: The list of policies.
    """
    try:
        policies = list(iam.policies.filter(Scope=scope))
        logger.info("Got %s policies in scope '%s'.", len(policies), scope)
    except ClientError:
        logger.exception("Couldn't get policies for scope '%s'.", scope)
        raise
    else:
        return policies
def get_default_policy_statement(policy_arn):
    """
    Gets the statement of the default version of the specified policy.
    :param policy_arn: The ARN of the policy to look up.
    :return: The statement of the default policy version.
    """
    try:
        policy = iam.Policy(policy_arn)
        # To get an attribute of a policy, the SDK first calls get_policy.
        policy_doc = policy.default_version.document
        policy_statement = policy_doc.get('Statement', None)
        logger.info("Got default policy doc for %s.", policy.policy_name)
        logger.info(policy_doc)
    except ClientError:
        logger.exception("Couldn't get default policy statement for %s.", policy_arn)
        raise
    else:
        return policy_statement
if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
    print('-' * 88)
    print("Welcome to the AWS Identity and Account Management policy demo.")
    print('-' * 88)
    policies = list_policies('AWS')
    print(f"Your account has {len(policies)} managed policies:")
    print(policies)
    glue_arn = 'arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole'
    default_statement=get_default_policy_statement(glue_arn)
