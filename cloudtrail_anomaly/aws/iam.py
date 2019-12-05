import boto3
from botocore.exceptions import ClientError

from cloudtrail_anomaly import log


def get_roles_in_account(cloudaux=None):
    """Return the roles in the account"""

    log.info('Getting roles from {}'.format(cloudaux.conn_details['account_number']))
    response = cloudaux.call(
        'iam.client.list_roles',
        PathPrefix='/',
        MaxItems=100)

    roles = {}
    while True:
        next_token = response.get('Marker', None)
        for role in response.get('Roles', []):
            roles[role['Arn']] = role
        if next_token:
            response = cloudaux.call(
                'iam.client.list_roles',
                MaxItems=100,
                Marker=next_token)
        else:
            break

    return roles
