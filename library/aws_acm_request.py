#!/usr/bin/python3
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Robert Mendal <rmendal@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = '''
---
module: aws_acm_request

short_description: Assume aws role generate ssl certs for puppet and return
them as files.

version_added: "2.9.4"

description:
    - Uses the awx ops-prod service account to request and export a cert for
      puppet agents. It then splits the information into the correct files and
      sets their permissions before copying them to the remote host.

options:
    Domain_Name:
        description:
            - The hostname of the server to get the puppet cert
              (e.g. foo.bar.baz.fizzbuzz.com)
        required: true
    AWS_SECRET_ACCESS_KEY:
        description:
            - Key for the awx service account, accessed securely by awx.
        required: true
    AWS_DEFAULT_REGION:
        description:
            - Default region for awx service account to use.
              Required for requesting a cert.
        required: true
    AWS_ACCESS_KEY_ID:
        description:
            - ID for the awx service account, accessed securely by awx.
        required: true

extends_documentation_fragment:
    - aws

author:
    - Robert Mendal (rmendal@gmail.com)
'''

EXAMPLES = '''
# Request a certificate
- name: Request the certs
    aws_acm_request:
      Domain_Name: "foo.bar.baz.fizzbuzz.com"
      AWS_SECRET_ACCESS_KEY: "redacted"
      AWS_DEFAULT_REGION: "us-west-2"
      AWS_ACCESS_KEY_ID: "redacted"
'''

RETURN = '''
changed:
    description: Returns True if all key/cert files were created locally
    type: str
    returned: always
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.aws.core import AnsibleAWSModule
from time import sleep
import boto3
from string import hexdigits
from random import sample
from os.path import exists

try:
    from botocore.exceptions import ClientError, ParamValidationError
except ImportError:
    pass  # caught by AnsibleAWSModule


def cert(module):
    # AVAILABLE PARAMETERS FOR THIS MODULE
    params = {
        'DomainName': module.params.get('Domain_Name'),
        'AWS_SECRET_ACCESS_KEY': module.params.get('AWS_SECRET_ACCESS_KEY'),
        'AWS_DEFAULT_REGION': module.params.get('AWS_DEFAULT_REGION'),
        'AWS_ACCESS_KEY_ID': module.params.get('AWS_ACCESS_KEY_ID'),
    }

    # SEED RESULT DICT
    result = dict(
        changed=False,
    )

    # if the user is working with this module in only check mode we do not
    # want to make any changes to the environment, just return the current
    # state with no modifications
    if module.check_mode:
        module.exit_json(**result)

    # ESTABLISH A SESSION WITH AWS & CREATE CLIENT
    session = boto3.Session(
     aws_access_key_id=params.get('AWS_ACCESS_KEY_ID'),
     aws_secret_access_key=params.get('AWS_SECRET_ACCESS_KEY'),
     region_name=params.get('AWS_DEFAULT_REGION'),
    )
    client = session.client('acm')

    # REQUEST A CERTIFICATE FROM PRIVATE CA IN AWS ACM
    request = client.request_certificate(
        DomainName=params.get('DomainName'),
        CertificateAuthorityArn="your-arn-here",
    )

    # EXPORT THE NEWLY CREATED CERTIFICATE
    # The while loop bakes in time while the cert is created.
    # In testing we found that varying time was needed between request and
    # export else export would fail to find the newly created cert.

    """Pass phrase is required but will be stripped out prior to copying files
    to remote host. This was an easy way to randomize it so that it's never
    predictable"""
    pass_phrase = str.encode(''.join(sample(hexdigits, 10)), 'utf-8')
    i = 0
    while True:
        try:
            export_cert = client.export_certificate(
                CertificateArn=request.get("CertificateArn"),
                Passphrase=pass_phrase
            )
            break
        except Exception as e:
            i=i+1
            if i == 5:
                raise e
            sleep(5)

    # ACM returns a JSON blob, pull the necessary info out
    certificate = export_cert.get('Certificate')
    chain = export_cert.get('CertificateChain')
    key = export_cert.get('PrivateKey')

    # WRITE THE STRINGS TO FILES
    # The associated playbook deals with the files
    DomainName = params.get('DomainName')

    with open (f'{DomainName}.key', 'x') as f:
        write_priv_key = f.write(key)

    with open (f'{DomainName}.pem', 'x') as f:
        write_certificate = f.write(certificate)

    with open (f'{DomainName}-ca.pem', 'x') as f:
        write_chain = f.write(chain)

    with open (f'{DomainName}-pass.txt', 'x') as f:
        write_pass = f.write(pass_phrase.decode('utf-8'))

    # If the files were created successfully seed the result dict
    if (exists(f"{DomainName}.key") is True and
            exists(f"{DomainName}.pem") is True and
            exists(f"{DomainName}-ca.pem") is True and
            exists(f'{DomainName}-pass.txt') is True):
        result['changed'] = True
        module.exit_json(**result)

    # During the execution of the module, if there is an exception or a
    # conditional state that effectively causes a failure, run
    # AnsibleModule.fail_json() to pass in the message and the result
    else:
        module.fail_json(msg='The module has encountered an error', **result)

    # In the event of a successful module execution, you will want to
    # simple AnsibleModule.exit_json(), passing the key/value results
    # module.exit_json(**result)


def main():
    # ACCEPT ARGUMENTS AND PASS TO MODULE FOR PARSING
    module_args = dict(
        Domain_Name=dict(required=True),
        AWS_SECRET_ACCESS_KEY=dict(required=True),
        AWS_DEFAULT_REGION=dict(required=True),
        AWS_ACCESS_KEY_ID=dict(required=True),
    )
    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    cert(module)


if __name__ == '__main__':
    main()
