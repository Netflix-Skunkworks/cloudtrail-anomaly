import datetime
import json
import time
import yaml

import boto3
from cloudaux import CloudAux
import click
import click_log
import iso8601
import pytz

from cloudtrail_anomaly import log
from cloudtrail_anomaly.__about__ import __version__
from cloudtrail_anomaly.aws.orgs import get_accounts_from_orgs
from cloudtrail_anomaly.aws.iam import get_roles_in_account
from cloudtrail_anomaly.aws.athena import query_athena, create_table
from cloudtrail_anomaly.aws.s3 import read_data_from_s3

click_log.basic_config(log)


class YAML(click.ParamType):
    name = 'yaml'
    def convert(self, value, param, ctx):
        try:
            with open(value, 'rb') as f:
                return yaml.load(f.read(), Loader=yaml.SafeLoader)
        except (IOError, OSError) as e:
            self.fail('Could not open file: {0}'.format(value))


class CommaList(click.ParamType):
    name = 'commalist'
    def convert(self, value, param, ctx):
        return value.split(',')

class AppContext(object):
    def __init__(self):
        self.config = None


pass_context = click.make_pass_decorator(AppContext, ensure=True)

 
@click.group()
@click_log.simple_verbosity_option(log)
@click.version_option(version=__version__)
@click.option('--config', type=YAML(), help='Configuration file to use.')
@pass_context
def cli(ctx, config):
    if not ctx.config:
        ctx.config = config
    log.debug('Current context. Config: {}'.format(json.dumps(ctx.config, indent=2)))


@cli.group()
def detect():
    pass

@cli.group()
def setup():
    pass


@detect.command()
@click.option('--accounts', type=CommaList(), help='Comma separated list of AWS accounts')
@pass_context
def anomaly(ctx, accounts):
    """Detect anomalies in CloudTrail"""

    conn_details = {
        'account_number': ctx.config.get('aws', {}).get('organizations', {}).get('accountId', '123'),
        'assume_role': ctx.config.get('aws', {}).get('organizations', {}).get('roleName', '123'),
        'session_name': 'cloudtrail-anomaly'
    }

    ca = CloudAux(**conn_details)

    if not accounts:
        accounts = get_accounts_from_orgs(ca)
        log.info('Received {} accounts from Organizations'.format(len(accounts)))
    else:
        log.info('Received {} accounts from command line'.format(len(accounts)))

    conn_details['assume_role'] = ctx.config.get('aws', {}).get('iam', {}).get('roleName', '123')

    conn_details_athena = {
        'account_number': ctx.config['aws']['athena']['accountId'],
        'assume_role': ctx.config['aws']['athena']['roleName'],
        'session_name': 'cloudtrail-anomaly',
        'region': ctx.config.get('aws', {}).get('region', 'us-east-1')
    }
    ca_athena = CloudAux(**conn_details_athena)

    dynamodb = boto3.resource('dynamodb', region_name=ctx.config.get('aws', {}).get('region', 'us-east-1'))
    dynamo_table = dynamodb.Table(ctx.config.get('aws', {}).get('dynamoTableName', 'cloudtrail_anomaly'))

    sns_topic = boto3.client('sns', region_name=ctx.config.get('aws', {}).get('region', 'us-east-1'))

    for account in accounts:
        conn_details['account_number'] = account
        
        ca = CloudAux(**conn_details)
        
        roles = get_roles_in_account(ca)

        for role in roles:
            role_name = roles[role]['RoleName']
            new_ttl = int(time.mktime((datetime.datetime.now() + datetime.timedelta(days=ctx.config['roleAction']['dayThreshold'])).timetuple()))
            principal_id = roles[role]['RoleId']
            athena_query = "SELECT DISTINCT eventsource, eventname FROM cloudtrail_{} WHERE useridentity.type = 'AssumedRole' AND useridentity.sessioncontext.sessionissuer.principalid= '{}' AND eventTime > to_iso8601(current_timestamp - interval '1' hour);".format(account, principal_id)

            log.info('Running Athena Query for {} in {}'.format(roles[role]['RoleName'], account))
            file_name = query_athena(ctx.config, athena_query, ca_athena)

            if not file_name:
                log.error("Execution failed or timed out")
                continue

            s3_key = ctx.config.get('aws', {}).get('athena', {}).get('prefix', 'cloudtrail_anomaly') + '/' + file_name

            data = read_data_from_s3(ctx.config['aws']['athena']['bucket'], s3_key, ca_athena)

            role_actions = []

            # Remove the header and loop through calls in last hour:
            for call in data[1:]:
                service_pair = call.split(',')
                service_action = ':'.join(service_pair)
                if len(service_action) == 0:
                    continue

                log.debug('Checking DynamoDB for never seen before actions on {} in {}'.format(role_name, account))
                key = {'RoleId': principal_id, 'Action': service_action}
                response = dynamo_table.get_item(Key=key)

                if response and 'Item' in response:
                    dynamo_table.update_item(Key=key,
                                             UpdateExpression='SET #ttl = :ttl',
                                             ExpressionAttributeNames={'#ttl': 'TTL'},
                                             ExpressionAttributeValues={':ttl': new_ttl})
                else:
                    # keep track of which actions are new
                    if service_action not in ctx.config['roleAction'].get('IgnoredActionsNotify', []):
                        role_actions.append(service_action)
                        log.info('Newly seen action: {} - {} in {}'.format(role_name, service_action, account))
                    dynamo_table.put_item(Item={'RoleId': principal_id,
                                                'Action': service_action,
                                                'TTL': new_ttl})

            if len(role_actions) > 0:
                arn = role
                create_date = roles[role]['CreateDate']
                role_name = roles[role]['RoleName']
                skip_alert = False

                # if the role is too new, don't alert
                if create_date > datetime.datetime.now(pytz.utc) - datetime.timedelta(days=ctx.config['roleAction']['dayThreshold']):
                    skip_alert = True
                    log.debug('{} in {} is too new, skipping alert'.format(role_name, account))
                # if the role is a service role, don't alert
                if 'aws-service-role' in arn.split('/'):
                    skip_alert = True
                    log.debug('{} in {} is an AWS service role, skipping alert'.format(role_name, account))

                if not skip_alert:
                    log.info('Sending alert for new actions for {} in {}'.format(role_name, account))
                    alert = {
                        'actions': ', '.join(action for action in role_actions),
                        'role': role_name,
                        'account': account
                    }
                    sns_topic.publish(
                        TopicArn=ctx.config['aws']['snsTopicArn'],
                        Message=json.dumps(alert)
                    )


@setup.command()
@click.option('--accounts', type=CommaList(), help='Comma separated list of AWS accounts')
@pass_context
def athena(ctx, accounts):
    """Setup athena tables."""

    conn_details = {
        'account_number': ctx.config.get('aws', {}).get('organizations', {}).get('accountId', '123'),
        'assume_role': ctx.config.get('aws', {}).get('organizations', {}).get('roleName', '123'),
        'session_name': 'cloudtrail-anomaly'
    }

    ca = CloudAux(**conn_details)

    conn_details_athena = {
        'account_number': ctx.config['aws']['athena']['accountId'],
        'assume_role': ctx.config['aws']['athena']['roleName'],
        'session_name': 'cloudtrail-anomaly',
        'region': ctx.config.get('aws', {}).get('region', 'us-east-1')
    }
    ca_athena = CloudAux(**conn_details_athena)

    if not accounts:
        accounts = get_accounts_from_orgs(ca)
        log.info('Received {} accounts from Organizations'.format(len(accounts)))
    else:
        log.info('Received {} accounts from command line'.format(len(accounts)))

    for account in accounts:        
        file_name = create_table(ctx.config, accounts[0], ca_athena)

        if not file_name:
            log.error("Execution failed or timed out for account {}".format(account))
            continue
        else:
            log.info("Successfully created Athena table for account {}".format(account))

    log.info('Successfully created Athena tables')


if __name__ == '__main__':
    cli()
