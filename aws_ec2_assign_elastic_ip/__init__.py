""" Assign EC2 Elastic IP to the current instance """
import logging
import logging.config
import sys

if sys.platform in ['win32', 'cygwin']:
    import ntpath as ospath
else:
    import os.path as ospath

import boto.utils
from netaddr import IPNetwork, AddrFormatError, AddrConversionError
from boto.ec2 import connect_to_region
from boto.utils import get_instance_metadata
import requests


from aws_ec2_assign_elastic_ip.command_line_options import ARGS as args
from ec2_metadata import EC2Metadata

logging.config.fileConfig('{0}/logging.conf'.format(
    ospath.dirname(ospath.realpath(__file__))))

logger = logging.getLogger('aws-ec2-assign-eip')

class TimeoutSession(requests.Session):
    def __init__(self, timeout=None, *args, **kwargs):
        self.timeout = timeout
        super(TimeoutSession, self).__init__(*args, **kwargs)

    def request(self, *args, **kwargs):
        kwargs.setdefault('timeout', self.timeout)
        return super(TimeoutSession, self).request(*args, **kwargs)

ec2_metadata = EC2Metadata(TimeoutSession(1))

region = args.region

# Fetch instance metadata

try:
    region = ec2_metadata.region
except requests.exceptions.ConnectTimeout:
    pass

# Connect to AWS EC2
if args.access_key or args.secret_key:
    # Use command line credentials
    import boto3
    client = boto3.client('ec2',
        region_name=region,
        aws_access_key_id=args.access_key,
        aws_secret_access_key=args.secret_key
    )
else:
    # Use environment vars or global boto configuration or instance metadata
    client = boto3.client('ec2', region_name=region)

logger.info('Connected to AWS EC2 in {0}'.format(region))


def main():
    """ Main function """
    # Get our instance name
    instance_id = ec2_metadata.instance_id

    # Check if the instance already has an Elastic IP
    # If so, exit
    if _has_associated_address(instance_id):
        logger.warning('{0} is already assigned an Elastic IP. Exiting.'.format(
            instance_id))
        sys.exit(0)

    # Get an unassigned Elastic IP
    address = _get_unassociated_address()

    # Exit if there were no available Elastic IPs
    if not address:
        sys.exit(1)

    # Assign the Elastic IP to our instance
    if args.dry_run:
        logger.info('Would assign IP {0}'.format(address['PublicIp']))
    else:
        _assign_address(instance_id, address)


def _assign_address(instance_id, address):
    """ Assign an address to the given instance ID

    :type instance_id: str
    :param instance_id: Instance ID
    :type address: boto.ec2.address
    :param address: Elastic IP address
    :returns: None
    """
    logger.debug('Trying to associate {0} with {1}'.format(
        instance_id, address['PublicIp']))

    # Check if this is an VPC or standard allocation
    try:
        if address['Domain'] == 'standard':
            # EC2 classic association
            connection.associate_address(
                instance_id,
                public_ip=address['PublicIp'])
        else:
            # EC2 VPC association
            connection.associate_address(
                instance_id,
                allocation_id=address['AllocationId'])
    except Exception as error:
        logger.error('Failed to associate {0} with {1}. Reason: {2}'.format(
            instance_id, address['PublicIp'], error))
        sys.exit(1)

    logger.info('Successfully associated Elastic IP {0} with {1}'.format(
        address['PublicIp'], instance_id))


def _get_unassociated_address():
    """ Return the first unassociated EIP we can find

    :returns: boto.ec2.address or None
    """
    eip = None

    for address in client.describe_addresses()['Addresses']:
        # Check if the address is associated
        if address.get('InstanceId'):
            logger.debug('{0} is already associated with {1}'.format(
                address['PublicIp'], address['InstanceId']))
            continue

        # Check if the address is attached to an ENI
        if address.get('NetworkInterfaceId'):
            logger.debug('{0} is already attached to {1}'.format(
                address.public_ip, address['NetworkInterfaceId']))
            continue

        # Check if the address is in the valid IP's list
        if _is_valid(address['PublicIp']):
            logger.debug('{0} is unassociated and OK for us to take'.format(
                address['PublicIp']))
            eip = address
            break

        else:
            logger.debug(
                '{0} is unassociated, but not in the valid IPs list'.format(
                    address.public_ip, address.instance_id))

    if not eip:
        logger.error('No unassociated Elastic IP found!')

    return eip


def _has_associated_address(instance_id):
    """ Check if the instance has an Elastic IP association

    :type instance_id: str
    :param instance_id: Instances ID
    :returns: bool -- True if the instance has an Elastic IP associated
    """
    if client.describe_addresses(Filters=[
        {
            'Name': 'instance-id',
            'Values': [instance_id],
        }
    ])['Addresses']:
        return True
    return False

def _is_ip_in_range(address, ips):
    """ Check if the IP is in a given range.

    :type address: str
    :param address: IP address to check
    :type ips: str
    :param ips: IP range
    :returns: bool -- True if association is OK
    """
    if not ips:
        return True

    for conf_ip in ips.split(','):
        try:
            for ip in IPNetwork(conf_ip):
                if str(ip) == str(address):
                    return True

        except AddrFormatError as err:
            logger.error('Invalid valid IP configured: {0}'.format(err))
            pass

        except AddrConversionError as err:
            logger.error('Invalid valid IP configured: {0}'.format(err))
            pass

    return False


def _is_valid(address):
    """ Check if the configuration allows us to assign this address

    :type address: str
    :param address: IP address to check
    :returns: bool -- True if association is OK
    """
    if _is_ip_in_range(address, args.valid_ips):
        if args.invalid_ips and _is_ip_in_range(address, args.invalid_ips):
            return False
        else:
            return True

    return False
