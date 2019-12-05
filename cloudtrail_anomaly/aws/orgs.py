import boto3
from botocore.exceptions import ClientError

from cloudtrail_anomaly import log


def get_accounts_from_orgs(cloudaux=None):
    """Return the account"""

    log.info('Getting accounts from organizations')
    response = cloudaux.call(
        'organizations.client.list_accounts'
    )

    accounts = []
    while True:
        next_token = response.get('NextToken', None)
        for account in response.get('Accounts', []):
            accounts.append(account['Id'])
        if next_token:
            response = cloudaux.call(
                'organizations.client.list_accounts',
                NextToken=next_token)
        else:
            break

    return accounts
