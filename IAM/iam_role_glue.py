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


def list_policies(role_name):
    """
    Lists inline policies for a role.
    :param role_name: The name of the role to query.
    """
    try:
        role = iam.Role(role_name)
        for policy in role.policies.all():
            logger.info("Got inline policy %s.", policy.name)
    except ClientError:
        logger.exception("Couldn't list inline policies for %s.", role_name)
        raise


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


def attach_policy(role_name, policy_arn):
    try:
        iam.Role(role_name).attach_policy(PolicyArn=policy_arn)
        logger.info("Attached policy %s to role %s.", policy_arn, role_name)
    except ClientError:
        logger.exception("Couldn't attach policy %s to role %s.", policy_arn, role_name)
        raise


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
    print('-' * 88)
    print("Welcome to the AWS Identity and Account Management role demo.")
    print('-' * 88)
    roles = list_roles(20)
    print(roles)
    role = get_role('glue-developer')
    print(role)
    list_policies('demo-iam-role')
    role_name = 'glue-developer'
    allowed_services = 'glue.amazonaws.com'
    # role = create_role(
    #     role_name,
    #     ['glue.amazonaws.com'])
    # print(f"Created role {role.name}, with trust policy:")
    #
    policy_arn = 'arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole'
    attach_policy(role.name, policy_arn)
