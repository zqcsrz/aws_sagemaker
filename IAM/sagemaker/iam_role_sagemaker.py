import json
import logging
import pprint

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)
iam = boto3.resource('iam')


def list_roles(count):
    """
    Lists the specified number of roles for the account.
    :param count: The number of roles to list.
    """
    try:
        roles = list(iam.roles.limit(count=count))
        for role in roles:
            logger.info("Role: %s", role.name)
    except ClientError:
        logger.exception("Couldn't list roles for the account.")
        raise
    else:
        return roles

def create_role(role_name, allowed_services):
    """
    Creates a role that lets a list of specified services assume the role.
    :param role_name: The name of the role.
    :param allowed_services: The services that can assume the role.
    :return: The newly created role.
    """
    trust_policy = {
        'Version': '2012-10-17',
        'Statement': [{
            'Effect': 'Allow',
            'Principal': {'Service': service},
            'Action': 'sts:AssumeRole'
        } for service in allowed_services]
    }

    try:
        role = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(trust_policy))
        logger.info("Created role %s.", role.name)
    except ClientError:
        logger.exception("Couldn't create role %s.", role_name)
        raise
    else:
        return role
def get_role(role_name):
    """
    Gets a role by name.

    :param role_name: The name of the role to retrieve.
    :return: The specified role.
    """
    try:
        role = iam.Role(role_name)
        role.load()  # calls GetRole to load attributes
        logger.info("Got role with arn %s.", role.arn)
    except ClientError:
        logger.exception("Couldn't get role named %s.", role_name)
        raise
    else:
        return role

def attach_policy(role_name, policy_arn):
    try:
        iam.Role(role_name).attach_policy(PolicyArn=policy_arn)
        logger.info("Attached policy %s to role %s.", policy_arn, role_name)
    except ClientError:
        logger.exception("Couldn't attach policy %s to role %s.", policy_arn, role_name)
        raise


if __name__ == '__main__':
    role_name='sagemaker_developer'
    # role = create_role(
    #     role_name,
    #     ['sagemaker.amazonaws.com', 'batchoperations.s3.amazonaws.com'])
    # policy_arn='arn:aws:iam::aws:policy/AmazonSageMakerFullAccess'
    # attach_policy(role.name, policy_arn)
    # print(f"Attached policy {policy_arn} to {role.name}.")
    role=get_role(role_name)
    print(role.name)
    print(role.arn)