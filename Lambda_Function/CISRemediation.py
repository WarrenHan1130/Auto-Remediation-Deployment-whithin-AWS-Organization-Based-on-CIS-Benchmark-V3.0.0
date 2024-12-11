import boto3
import json
import datetime
import botocore
import csv
import uuid

def publish_notification(session, topic_arn, message, subject):
    try:
        # Create a SNS client to sent message
        client = session.client('sns')
        response = client.publish(TopicArn=topic_arn, Message=message, Subject=subject)
        print(f"Email Notification published. Message ID: {response['MessageId']}")

    except Exception as e:
        print(f"Error publishing to SNS: {str(e)}")

def auto_update_securityhub_status(event, session):
    securityhub_client = session.client('securityhub')
    finding_id = event['detail']['findings'][0]['Id']
    product_arn = event['detail']['findings'][0]['ProductArn']

    response = securityhub_client.batch_update_findings(
        FindingIdentifiers=[
            {
                'Id': finding_id,
                'ProductArn': product_arn
            },
        ],
        Workflow={
            'Status': 'RESOLVED'
        },
        Note={
            'Text': 'Auto-remediation task has been invoked',
            'UpdatedBy': 'CIS Remediation Master'
        }
    )

#CIS 1.2 (Security contact information should be provided for an AWS account)
def cis_1_2(session, account_id):

    #remediation
    account_client = session.client('account')
    try:
        account_client.put_alternate_contact(
            AccountId='account_id', 
            AlternateContactType='SECURITY',  
            EmailAddress='security-contact@example.com',  
            Name='Security Contact',  
            PhoneNumber='+1-000-000-000', 
            Title='Security Manager' 
        )
        print("Successfully updating alternate contact")
        return True
    except Exception as e:
        print(f"Error updating alternate contact: {str(e)}")
        return False
    
# CIS 1.4 (IAM root user access key should not exist)
def cis_1_4(session):
     print("No Automated Remediation exists for this control ID. Sending Remediation steps to SNS Topic")
     return True

# CIS 1.5 (IAM root user should enable MFA)
def cis_1_5(session):
     print("No Automated Remediation exists for this control ID. Sending Remediation steps to SNS Topic")
     return True

# CIS 1.6 (Hardware MFA should be enabled for the root user)
def cis_1_6(session):
     print("No Automated Remediation exists for this control ID. Sending Remediation steps to SNS Topic")
     return True
    
# CIS 1.8 Ensure IAM password policy requires minimum length of 14 or greater (Automated)
def cis_1_8(session):

    iam = session.client('iam')

    try:
        password_policy = iam.get_account_password_policy()
        print("Password Policy:", password_policy['PasswordPolicy'])
        password_policy['PasswordPolicy']['MinimumPasswordLength'] = 14
        print("Password Policy:", password_policy['PasswordPolicy'])
        if 'ExpirePasswords' in password_policy['PasswordPolicy']:
            del password_policy['PasswordPolicy']['ExpirePasswords']
        iam.update_account_password_policy(**password_policy['PasswordPolicy'])
        print("remediation for CIS 1.8 done")
        return True
        
    except (iam.exceptions.NoSuchEntityException, KeyError):
        print("Password policy does not exist. Will create new policy.")
        password_policy = {
            'MinimumPasswordLength': 14,
            'RequireUppercaseCharacters': True,
            'RequireLowercaseCharacters': True,
            'RequireNumbers': True,
            'RequireSymbols': True,
            'MaxPasswordAge': 90
        }
        iam.update_account_password_policy(**password_policy)
        print("remediation for CIS 1.8 done")
        return True
    except Exception as e:
        print(f"Remediation failed: {e}")
        return False

# CIS 1.9 (Ensure IAM password policy prevents password reuse)
def cis_1_9(session):

    # remediation
    iam = session.client('iam')

    try:
        password_policy = iam.get_account_password_policy()  # return dict
        print("Password Policy:", password_policy['PasswordPolicy'])
        password_policy['PasswordPolicy']['PasswordReusePrevention'] = 24
        print("Password Policy:", password_policy['PasswordPolicy'])
        if 'ExpirePasswords' in password_policy['PasswordPolicy']:
            del password_policy['PasswordPolicy']['ExpirePasswords']
        iam.update_account_password_policy(**password_policy['PasswordPolicy'])
        print("remediation for CIS 1.9 done")
        return True

    except (iam.exceptions.NoSuchEntityException):
        # todo: set a default password policy for all password-policy-related controls
        password_policy = {
            'MaxPasswordAge': 90,
            'MinimumPasswordLength': 14,  # CIS 1.8
            'PasswordReusePrevention': 24,  # CIS 1.9
            'RequireLowercaseCharacters': True,
            'RequireNumbers': True,
            'RequireSymbols': True,
            'RequireUppercaseCharacters': True,
        }
        iam.update_account_password_policy(**password_policy)
        print("remediation for CIS 1.9 done")
        return True

    except Exception as e:
        print("Service failure occurred while updating password policy:", str(e))
        return False

# CIS 1.10 (MFA should be enabled for all IAM users that have a console password)
def cis_1_10(session):
    print("No Automated Remediation exists for this control ID. Sending Remediation steps to SNS Topic")
    return True

# CIS 1.12 (IAM user credentials unused for 45 days should be removed)
def cis_1_12(session):
    # remediation
    iam = session.client('iam')

    current_time = datetime.datetime.now(datetime.timezone.utc)
    disabled_keys = []
    disabled_users = []
    password_deleted_users = []
    try:
        response = iam.list_users()
        if not response['Users']:
            print("No IAM users found in the account.")
        else:
            for user in response['Users']:
                add = False
                user_name = user['UserName']
                try:
                    access_keys = iam.list_access_keys(UserName=user_name)['AccessKeyMetadata']
                    if not access_keys:
                        print(f"User {user_name} has no access keys.")
                    else:
                        for key in access_keys:
                            
                            acc_key_id = key['AccessKeyId']
                            access_key_last_used = iam.get_access_key_last_used(AccessKeyId=acc_key_id).get('AccessKeyLastUsed')
                            last_used = access_key_last_used.get('LastUsedDate') if access_key_last_used else None 
                            if last_used is not None and (current_time - last_used).days > 45:
                                iam.delete_access_key(UserName=user_name, AccessKeyId=acc_key_id)
                                disabled_keys.append(acc_key_id)
                                add = True
                    if add:
                        disabled_users.append(user_name)
                except Exception as e:
                     print(f"Cannot get the access keys for the IAM user '{user_name}': {str(e)}")
    except Exception as e:
        print("Service failure occurred while updating password policy:", str(e))

    try: 
        # Generate the credential report 
        generate_report_response = iam.generate_credential_report() 
        print(f"Generate Credential Report Response: {generate_report_response}") 
        # Retrieve the generated credential report 
        report_response = iam.get_credential_report() 
        # Decode the report as it's returned in base64 
        report_content = report_response['Content'].decode('utf-8') 

        csv_reader = csv.DictReader(report_content.splitlines())
        report_data = list(csv_reader)

        for row in report_data:
            
            if row['user'] != '<root_account>':
                last_used = row['password_last_used']
                if last_used != 'no_information':
                    last_used = datetime.datetime.strptime(last_used, '%Y-%m-%dT%H:%M:%S+00:00')
                    if (current_time - last_used).days > 45:
                        iam.delete_login_profile(UserName = row['user'])
                        password_deleted_users.append(row['user'])
    except Exception as e: 
        print(f"Error getting credential report: {e}") 

    return disabled_keys, disabled_users, password_deleted_users
    
# CIS 1.14 (IAM users' access keys should be rotated every 90 days or less)
def cis_1_14(session):

    # remediation
    iam = session.client('iam')

    current_time = datetime.datetime.now(datetime.timezone.utc)
    disabled_keys = []
    disabled_users = []
    try:
        response = iam.list_users()
        if not response['Users']:
            print("No IAM users found in the account.")
        else:
            for user in response['Users']:
                add = False
                user_name = user['UserName']
                try:
                    access_keys = iam.list_access_keys(UserName=user_name)['AccessKeyMetadata']
                    if not access_keys:
                        print(f"User {user_name} has no access keys.")
                    else:
                        for key in access_keys:
                            
                            acc_key_id = key['AccessKeyId']
                            create_time = key['CreateDate']
                            days_since_create = (current_time - create_time).days
                            print(f"Days since create: {days_since_create}")
                            if days_since_create >= 90:
                                iam.update_access_key(UserName=user_name, AccessKeyId=acc_key_id, Status='Inactive')
                                disabled_keys.append(acc_key_id)
                                add = True
                    if add:
                        disabled_users.append(user_name)
                except Exception as e:
                     print(f"Cannot get the access keys for the IAM user '{user_name}': {str(e)}")
    except Exception as e:
        print("Service failure occurred while updating password policy:", str(e))
        
    return disabled_keys, disabled_users

# CIS 1.15 (IAM users' policy should be attached to the group)
def cis_1_15(session):

    # remediation
    counter = 1

    iam = session.client('iam')
    user_list = iam.list_users()['Users']
    for user in user_list:
        user_name = user['UserName'] # str

        policies_attached = iam.list_attached_user_policies(UserName=user_name)
        if policies_attached['AttachedPolicies']:
            # create an IAM group and assign the policy to it
            group_name = user_name + '_group' + str(counter)
            iam.create_group(GroupName = group_name)

            for policy in policies_attached['AttachedPolicies']:

                policy_name = policy['PolicyName']
                policy_arn = policy['PolicyArn']

                try:
                    iam.attach_group_policy(GroupName=group_name, PolicyArn=policy_arn)
                    iam.detach_user_policy(UserName=user_name, PolicyArn=policy_arn)
                    print(f"Attach policy successfully '{policy_name}'")
                    
                except Exception as e:
                    print(f"Failed to attach policy '{policy_arn}' to group '{group_name}'")
                    print(f"Failed to detach policy '{policy_arn}' from user '{user_name}'")
                    return False

            # add the user to the new group
            try:
                iam.add_user_to_group(GroupName=group_name, UserName=user_name)
                print(f"Added user '{user_name}' to group '{group_name}'")
            except Exception as e:
                print(f"Failed to add user '{user_name}' to group '{group_name}'")
                return False

            counter += 1
            
    return True

# CIS 1.17 Ensure a support role has been created to manage incidents with AWS Support
def cis_1_17(session):

    # remediation
    iam = session.client('iam')

    # create a trust policy for create_role
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    # only AWS Support can assume the role
                    "Service": "support.amazonaws.com"
                },
                "Action": "sts:AssumeRole"
            }
        ]
    }

    # create a role
    support_role_name = 'support_role'
    try:
        iam.create_role(
            RoleName=support_role_name,
            # specify who can assume this support_role later
            AssumeRolePolicyDocument=json.dumps(trust_policy)
        )
        print(f"Support role {support_role_name} created successfully.")

        # attach the AWSSupportAccess policy to the role
        iam.attach_role_policy(
            RoleName=support_role_name,
            PolicyArn='arn:aws:iam::aws:policy/AWSSupportAccess'
        )
        print(f"Support policy has attached to {support_role_name} successfully.")
    except Exception as e:
        print(f"Failed to create support role {support_role_name}: {str(e)}")
        return False

    return True

# CIS 1.19 (Ensure that all the expired SSL/TLS certificates stored in AWS IAM are removed)
def cis_1_19(session):
    
    # remediation
    iam = session.client('iam')
    
    current_date = datetime.datetime.now(datetime.timezone.utc)
    
    deleted_certificates = []
    
    try:
        
        response = iam.list_server_certificates()
        certificates = response['ServerCertificateMetadataList']

        for cert in certificates:
            cert_name = cert['ServerCertificateName']
            expiration_date = cert['Expiration']

            if expiration_date < current_date:
                print(f"Certificate {cert_name} has expired on {expiration_date}. Deleting...")
                try:
                    iam.delete_server_certificate(ServerCertificateName=cert_name)
                    deleted_certificates.append(cert_name)
                    print(f"Deleted expired certificate: {cert_name}")
                    
                except Exception as e:
                    print(f"Failed to delete certificate {cert_name}: {str(e)}")
            else:
                print(f"Certificate {cert_name} is valid until {expiration_date}. No action needed.")
                
    except Exception as e:
        print("Failed to get certificates:", str(e))

    return deleted_certificates

#CIS 1.20 (IAM Access Analyzer external access analyzer should be enabled)
def cis_1_20(session, region):
    
    # remediation
    accessAna = session.client('accessanalyzer', region_name=region)
    analyzer_name = 'ExternalAccessAnalyzer'
    try:
        accessAna.create_analyzer(analyzerName=analyzer_name, type='ACCOUNT')
        print(f"Enabled Access Analyzer '{analyzer_name}' in region {region}.")
        return True
        
    except Exception as e:
        print(f"Failed to create analyzer {analyzer_name}: {str(e)}")
        return False
    
#CIS 1.22 (IAM identities should not have the AWSCloudShellFullAccess policy attached)
def cis_1_22(session):
    
    # remediation
    iam = session.client('iam')
    users_be_detached = []
    roles_be_detached = []
    groups_be_detached = []
    
    try:
        users = iam.list_users()['Users']
        roles = iam.list_roles()['Roles']
        groups = iam.list_groups()['Groups']

        if not users:
            print("No IAM users found in the account.")
        else:
            for user in users:
                user_name = user['UserName']
                try:
                    policies = iam.list_attached_user_policies(UserName=user_name)['AttachedPolicies']
                    if policies:
                        for policy in policies:
                            policy_name = policy['PolicyName']
                            if policy_name == 'AWSCloudShellFullAccess':
                                policy_arn = policy['PolicyArn']
                                iam.detach_user_policy(UserName=user_name, PolicyArn=policy_arn)
                                users_be_detached.append(user_name)
                                print(f"Detached policy '{policy_name}' from user '{user_name}'")
                except Exception as e:
                    print(f"Failed to detach policy from user '{user_name}': {str(e)}")

        if not roles:
            print("No IAM roles found in the account.")
        else:
            for role in roles:
                role_name = role['RoleName']
                try:
                    policies = iam.list_attached_role_policies(RoleName=role_name)['AttachedPolicies']
                    if policies:
                        for policy in policies:
                            policy_name = policy['PolicyName']
                            if policy_name == 'AWSCloudShellFullAccess':
                                policy_arn = policy['PolicyArn']
                                iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
                                roles_be_detached.append(role_name)
                                print(f"Detached policy '{policy_name}' from user '{role_name}'")
                except Exception as e:
                    print(f"Failed to detach policy from role '{role_name}': {str(e)}")

        if not groups:
            print("No IAM groups found in the account.")
        else:
            for group in groups:
                group_name = group['GroupName']
                try:
                    policies = iam.list_attached_group_policies(GroupName=group_name)['AttachedPolicies']
                    if policies:
                        for policy in policies:
                            policy_name = policy['PolicyName']
                            if policy_name == 'AWSCloudShellFullAccess':
                                policy_arn = policy['PolicyArn']
                                iam.detach_group_policy(GroupName=group_name, PolicyArn=policy_arn)
                                groups_be_detached.append(group_name)
                                print(f"Detached policy '{policy_name}' from user '{group_name}'")
                except Exception as e:
                    print(f"Failed to detach policy from role '{group_name}': {str(e)}")

    except Exception as e:
        print("Failed to get IAM users/roles/groups list:", str(e))

    return users_be_detached, roles_be_detached, groups_be_detached    

# CIS 2.1.1 (S3 buckets should require requests to use Secure Socket Layer, set to deny HTTP requests)
def cis_2_1_1(session, bucket_name):
    
    # remediation
    s3_client = session.client('s3')
    
    try:
        response = s3_client.get_bucket_policy(Bucket=bucket_name)
        current_policy = json.loads(response['Policy'])

        http_deny_bucket_policy = [
            {
                'Sid': 'AllowSSLRequestsOnly',
                'Action': 's3:*',
                'Effect': 'Deny',
                'Resource': f'arn:aws:s3:::{bucket_name}/*',
                'Condition': {
                    'Bool': {
                        'aws:SecureTransport': 'false'
                    }
                },
                'Principal': '*'
            }
        ]

        current_policy['Statement'].extend(http_deny_bucket_policy)
        final_policy = json.dumps(current_policy)

    except Exception:
        http_deny_bucket_policy = {
        'Version': '2012-10-17',
        'Statement': [
            {
                'Sid': 'AllowSSLRequestsOnly',
                'Action': 's3:*',
                'Effect': 'Deny',
                'Resource': f'arn:aws:s3:::{bucket_name}/*',
                'Condition': {
                    'Bool': {
                            'aws:SecureTransport': 'false'
                    }
                },
                'Principal': '*'
            }
        ]
        }

        final_policy = json.dumps(http_deny_bucket_policy)

    s3_client.put_bucket_policy(
        Bucket=bucket_name,
        Policy=final_policy
    )
    print(f"Bucket policy for {bucket_name} has been updated to allow HTTP requests only.")
    return True

#CIS 2.1.2 (S3 general purpose buckets should have MFA delete enabled)
def cis_2_1_2(session):

    #remediation
    print("No Automated Remediation exists for this control ID. Sending Remediation steps to SNS Topic")
    return True

#CIS 2.1.4.1 (S3 general purpose buckets should block public access at account level)
def cis_2_1_4_1(session, aws_account_id):

    # remediation
    s3_control = session.client('s3control')

    s3_control.put_public_access_block(
        PublicAccessBlockConfiguration={
            'BlockPublicAcls': True,
            'IgnorePublicAcls': True,
            'BlockPublicPolicy': True,
            'RestrictPublicBuckets': True
        },
        AccountId = aws_account_id
    )
    
    print(f"Public access blocked for bucket at account level for {aws_account_id}") 
    return True

#CIS 2.1.4.2 (S3 general purpose buckets should block public access at bucket level)
def cis_2_1_4_2(session, bucket_name):

    # remediation
    s3_client = session.client('s3')
    s3_client.put_public_access_block(
        Bucket = bucket_name,
        PublicAccessBlockConfiguration={
        'BlockPublicAcls': True,
        'IgnorePublicAcls': True,
        'BlockPublicPolicy': True,
        'RestrictPublicBuckets': True
        }
    )

    print(f"Public access blocked for bucket: {bucket_name})")
    return True

#CIS 2.2.1 (EBS default encryption should be enabled)
def cis_2_2_1(session):

    # remediation
    ec2_client = session.client('ec2')
    try:
        ec2_client.enable_ebs_encryption_by_default()
        print("EBS encryption is enabled by default.")
        return True

    except Exception as e:
        print(f"Failed to enable EBS encryption by default: {str(e)}")
        return False
        
#CIS 2.3.1 (RDS DB instances should have encryption at-rest enabled)
def cis_2_3_1(session, rds_instance_id, account_id):

    # remediation
    rds_client = session.client('rds')
    snapshot_id = f"{rds_instance_id}-snapshot-remediation"
    kms_client = session.client('kms')
    alias_name = 'alias/rds-encryption'

    try:
        rds_client.create_db_snapshot(
            DBSnapshotIdentifier = snapshot_id,
            DBInstanceIdentifier= rds_instance_id
        )
        print (f"Snapshot {snapshot_id} created for RDS instance {rds_instance_id}")

    except Exception as e:
        print("Failed to create snapshot for RDS instance", str(e))
        return False

    waiter = rds_client.get_waiter('db_snapshot_available')
    waiter.wait(DBSnapshotIdentifier = snapshot_id)
    print(f"Snapshot {snapshot_id} is now available.")

    try:
        alias_name_list = kms_client.list_aliases()

        kms_key_id = None

        for alias in alias_name_list['Aliases']:
            if alias['AliasName'] == alias_name:
                kms_key_id = alias['TargetKeyId']
                print(f"KMS key with alias {alias_name} already exists. Using existing key.")
                break

        if not kms_key_id:
            kms_policy = {
                'Version': '2012-10-17',
                'Statement': [
                    {
                        'Sid': 'Allow direct access to key metadata to the account',
                        'Effect': 'Allow',
                        'Principal': {
                            'AWS': f'arn:aws:iam::{account_id}:root'
                        }, 
                        'Action': 'kms:*',
                        'Resource': '*',
                    },
                    {
                        'Sid': 'Allow access through RDS for all principals in the account that are authorized to use RDS',
                        'Effect': 'Allow',
                        'Principal': {
                            'AWS': '*'
                        },
                        'Action': [
                            'kms:Encrypt',
                            'kms:Decrypt',
                            'kms:ReEncrypt*',
                            'kms:GenerateDataKey*',
                            'kms:DescribeKey',
                            'kms:CreateGrant',
                            'kms:ListGrants',
                        ],
                        'Resource': '*'
                    }
                ]
            }
            kms_policy = json.dumps(kms_policy)

            kms_key_response = kms_client.create_key(
                Description="KMS Key for encrypting RDS Snapshot",
                KeyUsage='ENCRYPT_DECRYPT',
                Origin='AWS_KMS',
                Policy = kms_policy
            )

            kms_key_id = kms_key_response['KeyMetadata']['KeyId']

            kms_client.create_alias (
                AliasName = alias_name,
                TargetKeyId = kms_key_id
            )
    except Exception as e:
        print("Failed to create KMS key: ", str(e))
        return False

    encrypted_snapshot_id = f"{snapshot_id}-encrypted"
    
    try:
        copy_response = rds_client.copy_db_snapshot(
            SourceDBSnapshotIdentifier=snapshot_id,
            TargetDBSnapshotIdentifier=encrypted_snapshot_id,
            KmsKeyId=kms_key_id 
        )
        print(f"Encrypted snapshot {encrypted_snapshot_id} created successfully.")

    except Exception as e:
        print(f"Failed to create encrypted snapshot: {e}")
        return False

    rds_client.delete_db_instance(
        DBInstanceIdentifier=rds_instance_id,
        SkipFinalSnapshot=True
    )

    waiter = rds_client.get_waiter('db_instance_deleted')
    waiter.wait(DBInstanceIdentifier = rds_instance_id)
    print(f"Original unencrypted RDS instance {rds_instance_id} deleted.")
    
    waiter = rds_client.get_waiter('db_snapshot_available')
    waiter.wait(DBSnapshotIdentifier = encrypted_snapshot_id)
    print(f"Snapshot {encrypted_snapshot_id} is now available.")

    try:
        rds_client.restore_db_instance_from_db_snapshot(
            DBInstanceIdentifier = rds_instance_id,
            DBSnapshotIdentifier= encrypted_snapshot_id,
        )
        print(f"Encrypted RDS instance {rds_instance_id} created from snapshot.")

    except Exception as e:
        print("Failed to create encrypted RDS instance:", str(e))
        return False

    return True

#CIS 2.3.2 (RDS automatic minor version upgrades should be enabled)
def cis_2_3_2(session, rds_instance_id):

    # remediation
    rds_client = session.client('rds')
    
    try:
        rds_client.modify_db_instance(
            DBInstanceIdentifier=rds_instance_id,
            AutoMinorVersionUpgrade=True,
            ApplyImmediately=True
        )
        print(f"Automatic minor version upgrade enabled for RDS instance {rds_instance_id}.")
        return True
    
    except Exception as e:
        print(f"Failed to enable automatic minor version upgrade for RDS instance {rds_instance_id}: {str(e)}")
        return False

#CIS 2.3.3 (Ensure that public access is not given to RDS Instance)
def cis_2_3_3(session):

    """
    AWS Config triggered:
    The publiclyAccessible field is true in the Amazon RDS instance configuration item.
    (if this rule is non-compliant, at least one DB instance existed and its publiclyAccessible field is set as YES)
    (when creating a database, 'public access' is a required field, so do not take such exception into consideration)

    remediation:
    1. initiate a RDS client class
    2. list all instancews in RDS, and loop this dictionary to change the "PubliclyAccessible" to False

    """
    # remediation
    rds = session.client('rds')

    instances = rds.describe_db_instances()

    for instance in instances['DBInstances']:
        identifier = instance['DBInstanceIdentifier']

        try:
            ifPublicAccessible = instance['PubliclyAccessible']
            if ifPublicAccessible:
                try: 
                    rds.modify_db_instance(
                        DBInstanceIdentifier = identifier,
                        PubliclyAccessible = False
                    )

                    if not instances['PubliclyAccessible']:
                        print(f"Successfully set PubliclyAccessible field to false: {identifier}")

                except Exception as e:
                    print(f"Failed to modify the PubliclyAccessible flag for {identifier}: {e}")

        # Neptune DB instances and Amazon DocumentDB clusters do not have the PubliclyAccessible flag and cannot be evaluated.
        except Exception as e:
            print(f"Failed to get the PubliclyAccessible status for {identifier}: {e}")


    return True

#CIS 2.4.1 (Ensure that encryption is enabled for EFS file systems)
def cis_2_4_1(session):

    """
    AWS Config triggered:
    1. the encrypted key of Amazon EFS is set to false;
    2. the KMS key used by the EFS file system does not match the KmsKeyId parameter.

    remediation:
    *"Once you create an EFS file system, you cannot change its encryption setting. 
      This means that you cannot modify an unencrypted file system to make it encrypted. 
      Instead, you need to create a new, encrypted file system."


      (https://docs.aws.amazon.com/efs/latest/ug/encryption-at-rest.html)

      So this control cannot completely auto-remediated by lambda function.
      We can only create a new, encrypted file system automatically and ask the user migrate the data to it manually.

    1. initiate a EFS client class 
    2. list all EFS file system and check if the system is not encrypted or not with KMS key
    3. create a new empty file system for each non-compliant one
    """

    efs = session.client('efs')
    kms = session.client('kms')

    non_compliant_file_systems = []
    new_efs_file_systems =[]

    # list all the keyid in the kms
    keyid_list = kms.list_keys()

    file_systems = efs.describe_file_systems()

    for file_system in file_systems['FileSystems']:
        file_system_id = file_system['FileSystemId']  # string
        encrypted = file_system['Encrypted']
        kms_key_id = file_system['KmsKeyId']

        if not encrypted or kms_key_id not in keyid_list:
            new_file_system = efs.create_file_system(
                    Encrypted = True,
            )
            new_efs_file_systems.append(new_file_system['FileSystemId'])
            non_compliant_file_systems.append(file_system_id)

    return non_compliant_file_systems, new_efs_file_systems
        
#CIS 3.1 (CloudTrail should be enabled and configured with at least one multi-Region trail that includes read and write management events)
def cis_3_1(session, region, account_id):
    
    # remediation
    if region == 'us-east-1':
        cloudtrail_client = session.client('cloudtrail')
        cloud_trail_name = 'cloudtrailformanagementevent'
        s3_client = session.client('s3', region_name=region)
        base_name = 'managementeventcloudtrail'
        s3_bucket_name = f"{base_name}-{account_id}-{region}"

        try:
            if region == 'us-east-1':
                s3_client.create_bucket(Bucket=s3_bucket_name)

            else:
                s3_client.create_bucket (
                    Bucket = s3_bucket_name,
                    CreateBucketConfiguration={'LocationConstraint': region}
                )

            bucket_policy = {
            'Version': '2012-10-17',
            'Statement': [
                {
                    'Sid': 'AWSCloudTrailAclCheck',
                    'Action': 's3:GetBucketAcl',
                    'Effect': 'Allow',
                    'Resource': f'arn:aws:s3:::{s3_bucket_name}',
                    'Principal': {
                        'Service': 'cloudtrail.amazonaws.com'
                    },
                    'Condition': {
                        'StringEquals': {
                            'AWS:SourceArn': f'arn:aws:cloudtrail:{region}:{account_id}:trail/{cloud_trail_name}'
                        }
                    }
                },
                {
                    'Sid': 'AWSCloudTrailWrite',
                    'Effect': 'Allow',
                    'Principal': {
                        'Service': 'cloudtrail.amazonaws.com'
                    },
                    'Action': 's3:PutObject',
                    'Resource': f'arn:aws:s3:::{s3_bucket_name}/AWSLogs/{account_id}/*',
                    "Condition": {
                        "StringEquals": {
                            "AWS:SourceArn": f"arn:aws:cloudtrail:{region}:{account_id}:trail/{cloud_trail_name}",
                            "s3:x-amz-acl": "bucket-owner-full-control"
                        }
                    }
                }
            ]
            }

            bucket_policy = json.dumps(bucket_policy)
            s3_client.put_bucket_policy(Bucket = s3_bucket_name, Policy = bucket_policy)
        except Exception as e:
            print("Failed to create bucket for cloud trail: ", str(e))
            return False

        event_selectors=[
            {
                'ReadWriteType': 'All',
                'IncludeManagementEvents': True,
                'DataResources': []
            }
        ]

        try:
            cloudtrail_client.create_trail(
                Name= cloud_trail_name,
                S3BucketName=s3_bucket_name,
                IsMultiRegionTrail=True,
                IncludeGlobalServiceEvents=True,
                EnableLogFileValidation=True
            )

            cloudtrail_client.put_event_selectors(
                TrailName = cloud_trail_name,
                EventSelectors = event_selectors
            )


            cloudtrail_client.start_logging(Name=cloud_trail_name)
            print(f"The cloud trail {cloud_trail_name} start to recording")

        except Exception as e:
            print("Failed to create cloud trail: ", str(e))
            return False

        return True

    else:
        return False

#CIS 3.2 (CloudTrail log file validation should be enabled)
def cis_3_2(session, trail_name):
    
    # remediation
    cloudtrail_client = session.client('cloudtrail')
    try:
        cloudtrail_client.update_trail(Name = trail_name, EnableLogFileValidation = True)
        print(f"Cloudtrail log file validation has been enabled for {trail_name}")
        return True
    except Exception as e:
        print("Failed to enable cloudtrail log file validation: ", str(e))
        return False

#CIS 3.3 Ensure AWS Config is enabled in all regions
def cis_3_3(session):
    print("No Automated Remediation exists for this control ID. Sending Remediation steps to SNS Topic")
    return True
    
#CIS 3.4 (Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket)
def cis_3_4(session, bucket_name, account_id, region):

    # remediation
    s3_client = session.client('s3')
    base_name = 'accesslogbucket'
    log_bucket_name = f"{base_name}-{account_id}-{region}"
    try:
        s3_client.head_bucket(Bucket=log_bucket_name)
        print(f"Bucket {log_bucket_name} already exists")
        
    except Exception:
        try:
            
            if region == 'us-east-1':
                s3_client.create_bucket(Bucket=log_bucket_name)
            else:
                s3_client.create_bucket(
                    Bucket=log_bucket_name,
                    CreateBucketConfiguration={'LocationConstraint': region}
                )
                
            bucket_policy = {
                'Version': '2012-10-17',
                'Statement': [
                    {
                        'Sid': 'Enable other S3 bucket store logs',
                        'Effect': 'Allow',
                        'Principal': {
                            'Service': 'logging.s3.amazonaws.com'
                        }, 
                        'Action': 's3:PutObject',
                        'Resource': f'arn:aws:s3:::{log_bucket_name}/Logs/*'
                    },
                    {
                        'Sid': 'AWSS3AclCheck',
                        'Action': 's3:GetBucketAcl',
                        'Effect': 'Allow',
                        'Resource': f'arn:aws:s3:::{log_bucket_name}',
                        'Principal': {
                            'Service': 'logging.s3.amazonaws.com'
                        }
                    }
                ]
            }
            bucket_policy = json.dumps(bucket_policy)
            s3_client.put_bucket_policy(Bucket=log_bucket_name, Policy=bucket_policy)
            print(f"{log_bucket_name} bucket has been created to store access logs")

        except Exception as e:
            print("Failed to create bucket for access logs: ", str(e))
            return False
    
        try:
            logging_config = {
                'LoggingEnabled': {
                    'TargetBucket': log_bucket_name,
                    'TargetPrefix': 'accesslogs/'
                }
            }

            s3_client.put_bucket_logging(Bucket = bucket_name, BucketLoggingStatus = logging_config)

            print(f"Access logging enabled for S3 bucket '{bucket_name}'")

        except Exception as e:
            print("Failed to enable access logging for S3 bucket: ", str(e))
            return False

    return True
        
#CIS 3.5 (CloudTrail should have encryption at-rest enabled)
def cis_3_5(session, account_id, trail_name):
    
    # remediation
    kms_client = session.client('kms')
    cloudtrail_client = session.client('cloudtrail')
    alias_name = 'alias/cloudtrail-encryption'
    
    try:
        alias_name_list = kms_client.list_aliases()
        
        kms_key_id = None
        
        for alias in alias_name_list['Aliases']:
            if alias['AliasName'] == alias_name:
                kms_key_id = alias['TargetKeyId']
                print(f"KMS key with alias {alias_name} already exists. Using existing key.")
                break
                
        if not kms_key_id:
            kms_policy = {
                'Version': '2012-10-17',
                'Statement': [
                    {
                        'Sid': 'Enable IAM User Permissions',
                        'Effect': 'Allow',
                        'Principal': {
                            'AWS': f'arn:aws:iam::{account_id}:root'
                        }, 
                        'Action': 'kms:*',
                        'Resource': '*',
                    },
                    {
                        'Sid': 'Allow CloudTrail to use the key for encryption and decryption',
                        'Effect': 'Allow',
                        'Principal': {
                            'Service': 'cloudtrail.amazonaws.com'
                        },
                        'Action': [
                            'kms:Encrypt',
                            'kms:Decrypt',
                            'kms:ReEncrypt*',
                            'kms:GenerateDataKey*',
                            'kms:DescribeKey'
                        ],
                        'Resource': '*'
                    }
                ]
            }
            kms_policy = json.dumps(kms_policy)

            kms_key_response = kms_client.create_key(
                Description="KMS Key for encrypting CloudTrail logs",
                KeyUsage='ENCRYPT_DECRYPT',
                Origin='AWS_KMS',
                Policy = kms_policy
            )

            kms_key_id = kms_key_response['KeyMetadata']['KeyId']

            kms_client.create_alias (
                AliasName = alias_name,
                TargetKeyId = kms_key_id
            )
    except Exception as e:
        print("Failed to create KMS key: ", str(e))
        return False

    try:
        cloudtrail_client.update_trail(
            Name = trail_name,
            KmsKeyId = kms_key_id  
        )
        
        print(f"CloudTrail {trail_name} has been encrypted with KMS key.")
        return True
        
    except Exception as e:
        print("Failed to update cloud trail: ", str(e))
        return False

#CIS 3.6 (AWS KMS key rotation should be enabled)
def cis_3_6(session, kms_key_id):

    # remediation
    kms_client = session.client('kms')

    try:
        rotation_setting = kms_client.get_key_rotation_status(KeyId = kms_key_id)
        if not rotation_setting['KeyRotationEnabled']:
            kms_client.enable_key_rotation(KeyId = kms_key_id)
            print(f"KMS key rotation has been enabled for key {kms_key_id}")
            return True
                
    except Exception as e:
        print("Failed to get KMS key rotation status: ", str(e))
        return False

#CIS 3.7 (VPC flow logging should be enabled in all VPCs)
def cis_3_7(session, vpc_id, region, account_id):

    # remediation
    ec2_client = session.client('ec2')
    logs_client = session.client('logs')
    iam_client = session.client('iam')
    role_name = 'CIS-Remediations-VPC-Log-Role'

    try:
        flow_logs = ec2_client.describe_flow_logs(
            Filters = [
                {'Name': 'resource-id', 'Values': [vpc_id]}
            ]
        )

        if flow_logs['FlowLogs']:
            print(f"VPC flow logging is already enabled for VPC {vpc_id}")
            return False
            
        else:
            print(f"VPC flow logging is not enabled for VPC {vpc_id}. Enabling...")
            try:
                iam_client.get_role(RoleName = role_name)
                print(f"IAM role {role_name} already exists.")
                
            except Exception as e:
                try:
                    trust_policy = {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {
                                    "Service": "vpc-flow-logs.amazonaws.com"
                                },
                                "Action": "sts:AssumeRole"
                            }
                        ]
                    }

                    iam_client.create_role(
                        RoleName = role_name,
                        AssumeRolePolicyDocument=json.dumps(trust_policy)
                    )
                    print("CIS-Remediations-VPC-Log-Role created successfully.")

                except Exception as e:
                    print("Failed to create CIS-Remediations-VPC-Log-Role: ", str(e))
                    return False

                try:
                    iam_client.attach_role_policy(
                        RoleName = role_name,
                        PolicyArn = 'arn:aws:iam::aws:policy/CloudWatchFullAccess'
                    )
                    print("CloudWatchFullAccess policy attached to CIS-Remediations-VPC-Log-Role.")

                except Exception as e:
                    print("Failed to attach CloudWatchFullAccess policy to CIS-Remediations-VPC-Log-Role", str(e))
                    iam_client.delete_role(RoleName = role_name)
                    print("CIS-Remediations-VPC-Log-Role deleted successfully.")
                    return False

            try:
                log_group_name = f"/aws/vpc-flow-logs/{vpc_id}"
                logs_client.create_log_group(logGroupName=log_group_name)
                print(f"Log group {log_group_name} created successfully.")

            except Exception as e:
                print("Failed to create log group: ", str(e))
                print("CIS-Remediations-VPC-Log-Role deleted successfully.")
                return False

            response = ec2_client.create_flow_logs(
                ResourceIds=[vpc_id],
                ResourceType='VPC',
                TrafficType='REJECT',
                LogDestinationType='cloud-watch-logs',
                LogDestination=f'arn:aws:logs:{region}:{account_id}:log-group:{log_group_name}:*',
                DeliverLogsPermissionArn=f'arn:aws:iam::{account_id}:role/{role_name}'
            )

            if response['Unsuccessful']:
                print("Failed to enable VPC flow logging.")
                logs_client.delete_log_group(logGroupName=log_group_name)
                print(f"Log group {log_group_name} deleted successfully.")
                return False

            else:
                print("VPC flow logging has been enabled.")
                return True
                
    except Exception as e:
            print(f"Failed to enable VPC flow logging: {str(e)}")
            return False
        
#CIS 3.8 (S3 general purpose buckets should log object-level write events)
def cis_3_8(session, region, account_id):

    # remediation
    if region == 'us-east-1':
        cloudtrail_client = session.client('cloudtrail')
        cloud_trail_name = 'cloudtrailforlogwrite'
        s3_client = session.client('s3', region_name = region)
        base_name = 'logobjectlevelcloudtrailwrite'
        s3_bucket_name = f"{base_name}-{account_id}-{region}"

        try:
            if region == 'us-east-1':
                s3_client.create_bucket(Bucket=s3_bucket_name)
            else:
                s3_client.create_bucket (
                    Bucket = s3_bucket_name,
                    CreateBucketConfiguration={'LocationConstraint': region}
                )

            bucket_policy = {
            'Version': '2012-10-17',
            'Statement': [
                {
                    'Sid': 'AWSCloudTrailAclCheck',
                    'Action': 's3:GetBucketAcl',
                    'Effect': 'Allow',
                    'Resource': f'arn:aws:s3:::{s3_bucket_name}',
                    'Principal': {
                        'Service': 'cloudtrail.amazonaws.com'
                    },
                    'Condition': {
                        'StringEquals': {
                            'AWS:SourceArn': f'arn:aws:cloudtrail:{region}:{account_id}:trail/{cloud_trail_name}'
                        }
                    }
                },
                {
                    'Sid': 'AWSCloudTrailWrite',
                    'Effect': 'Allow',
                    'Principal': {
                        'Service': 'cloudtrail.amazonaws.com'
                    },
                    'Action': 's3:PutObject',
                    'Resource': f'arn:aws:s3:::{s3_bucket_name}/*',
                    "Condition": {
                        "StringEquals": {
                            "AWS:SourceArn": f"arn:aws:cloudtrail:{region}:{account_id}:trail/{cloud_trail_name}",
                            "s3:x-amz-acl": "bucket-owner-full-control"
                        }
                    }
                }
            ]
            }

            bucket_policy = json.dumps(bucket_policy)
            s3_client.put_bucket_policy(Bucket = s3_bucket_name, Policy = bucket_policy)
        except Exception as e:
            print("Failed to create bucket for cloud trail: ", str(e))
            return False

        event_selectors=[
            {
                'ReadWriteType': 'WriteOnly',
                'IncludeManagementEvents': False,
                'DataResources': [
                    {
                        'Type': 'AWS::S3::Object',
                        'Values': ['arn:aws:s3']
                    }
                ]
            }
        ]

        try:
            cloudtrail_client.create_trail(
                Name= cloud_trail_name,
                S3BucketName=s3_bucket_name,
                IsMultiRegionTrail=True,
                EnableLogFileValidation= True
            )

            cloudtrail_client.put_event_selectors(
                TrailName = cloud_trail_name,
                EventSelectors = event_selectors
            )


            cloudtrail_client.start_logging(Name=cloud_trail_name)
            print(f"The cloud trail {cloud_trail_name} start to recording")

        except Exception as e:
            print("Failed to create cloud trail: ", str(e))
            return False

        return True
    else:
        return False

#CIS 3.9 (S3 general purpose buckets should log object-level read events)
def cis_3_9(session, region, account_id):

    # remediation
    if region == 'us-east-1':
        cloudtrail_client = session.client('cloudtrail')
        cloud_trail_name = 'cloudtrailforlogread'
        s3_client = session.client('s3', region_name = region)
        base_name = 'logobjectlevelcloudtrailread'
        s3_bucket_name = f"{base_name}-{account_id}-{region}"
    
        try:
            if region == 'us-east-1':
                s3_client.create_bucket(Bucket=s3_bucket_name)

            else:
                s3_client.create_bucket (
                    Bucket = s3_bucket_name,
                    CreateBucketConfiguration={'LocationConstraint': region}
                )

            bucket_policy = {
            'Version': '2012-10-17',
            'Statement': [
                {
                    'Sid': 'AWSCloudTrailAclCheck',
                    'Action': 's3:GetBucketAcl',
                    'Effect': 'Allow',
                    'Resource': f'arn:aws:s3:::{s3_bucket_name}',
                    'Principal': {
                        'Service': 'cloudtrail.amazonaws.com'
                    },
                    'Condition': {
                        'StringEquals': {
                            'AWS:SourceArn': f'arn:aws:cloudtrail:{region}:{account_id}:trail/{cloud_trail_name}'
                        }
                    }
                },
                {
                    'Sid': 'AWSCloudTrailWrite',
                    'Effect': 'Allow',
                    'Principal': {
                        'Service': 'cloudtrail.amazonaws.com'
                    },
                    'Action': 's3:PutObject',
                    'Resource': f'arn:aws:s3:::{s3_bucket_name}/*',
                    "Condition": {
                        "StringEquals": {
                            "AWS:SourceArn": f"arn:aws:cloudtrail:{region}:{account_id}:trail/{cloud_trail_name}",
                            "s3:x-amz-acl": "bucket-owner-full-control"
                        }
                    }
                }
            ]
            }

            bucket_policy = json.dumps(bucket_policy)
            s3_client.put_bucket_policy(Bucket = s3_bucket_name, Policy = bucket_policy)
        except Exception as e:
            print("Failed to create bucket for cloud trail: ", str(e))
            return False

        event_selectors=[
            {
                'ReadWriteType': 'ReadOnly',
                'IncludeManagementEvents': False,
                'DataResources': [
                    {
                        'Type': 'AWS::S3::Object',
                        'Values': ['arn:aws:s3']
                    }
                ]
            }
        ]

        try:
            cloudtrail_client.create_trail(
                Name= cloud_trail_name,
                S3BucketName=s3_bucket_name,
                IsMultiRegionTrail=True,
                EnableLogFileValidation= True
            )

            cloudtrail_client.put_event_selectors(
                TrailName = cloud_trail_name,
                EventSelectors = event_selectors
            )


            cloudtrail_client.start_logging(Name=cloud_trail_name)
            print(f"The cloud trail {cloud_trail_name} start to recording")

        except Exception as e:
            print("Failed to create cloud trail: ", str(e))
            return False

        return True

    else:
        return False

#CIS 5.1 (Network ACLs should not allow ingress from 0.0.0.0/0 to port 22 or port 3389)
def cis_5_1(session, network_acl_id):

    # remediation
    ec2_client = session.client('ec2')
    nacl = ec2_client.describe_network_acls(NetworkAclIds=[network_acl_id])['NetworkAcls'][0]
    ports = [22, 3389]

    for entry in nacl['Entries']:
        if entry['Egress'] is False and entry['RuleAction'] == 'allow':
            cidr_block = entry.get('CidrBlock')
            ipv6_cidr_block = entry.get('Ipv6CidrBlock')
            port_range = entry.get('PortRange')
            rule_number = entry['RuleNumber']

            if cidr_block == '0.0.0.0/0' or ipv6_cidr_block == '::/0':
                if port_range is None:
                    ec2_client.delete_network_acl_entry (
                        NetworkAclId = network_acl_id,
                        Egress = False,
                        RuleNumber=entry['RuleNumber']
                    )
                    print(f"Network ACL entry {rule_number} deleted successfully.")
                else:
                    if (port_range['From'] == port_range['To']):
                        if (port_range['From'] in ports):
                            ec2_client.delete_network_acl_entry (
                                NetworkAclId = network_acl_id,
                                Egress = False,
                                RuleNumber=entry['RuleNumber']
                            )
                            print(f"Network ACL entry {rule_number} deleted successfully.")
                    else:
                        if any(port_range['From'] <= port <= port_range['To'] for port in ports):
                            ec2_client.delete_network_acl_entry(
                                NetworkAclId=network_acl_id,
                                Egress=False,
                                RuleNumber=rule_number
                            )
                            print(f"Network ACL entry {rule_number} deleted successfully.")
      
    return True

#CIS 5.2 (EC2 security groups should not allow ingress from 0.0.0.0/0 to remote server administration ports)
def cis_5_2(session, sg_id):

    # remediation
    ec2_client = session.client('ec2')
    ports = [22, 3389]

    try:
        sg = ec2_client.describe_security_groups(GroupIds=[sg_id])['SecurityGroups'][0]
        inbound_rules = sg['IpPermissions']
        
    except Exception as e:
        print("Failed to get security group: ", str(e))
        return False

    for rule in inbound_rules:
        for ip_range in rule.get('IpRanges', []):
            if ip_range.get('CidrIp') == '0.0.0.0/0':

                if rule.get('IpProtocol') == '-1':
                    ec2_client.revoke_security_group_ingress(
                        GroupId=sg_id,
                        IpPermissions=[rule]
                    )
                    print(f"Security Group {sg_id} completely open rule (all traffic) deleted successfully.")

                else:
                
                    from_port = rule.get('FromPort')
                    to_port = rule.get('ToPort')

                    if from_port == to_port:
                        if from_port in ports:
                            ec2_client.revoke_security_group_ingress(
                                GroupId = sg_id,
                                IpPermissions = [rule]
                            )
                        print(f"Security Group {sg_id} entry for port {from_port} deleted successfully.")
                    else:
                        if any(from_port <= port <= to_port for port in ports):
                            ec2_client.revoke_security_group_ingress(
                                GroupId=sg_id,
                                IpPermissions = [rule]
                            )
                            print(f"Security Group {sg_id} entry for port range {from_port}-{to_port} deleted successfully.")

    return True

#CIS 5.3 (EC2 security groups should not allow ingress from ::/0 to remote server administration ports)
def cis_5_3(session, sg_id):

    # remediation
    ec2_client = session.client('ec2')
    ports = [22, 3389]

    try:
        sg = ec2_client.describe_security_groups(GroupIds=[sg_id])['SecurityGroups'][0]
        inbound_rules = sg['IpPermissions']

    except Exception as e:
        print("Failed to get security group: ", str(e))
        return False

    for rule in inbound_rules:
        for ip_range in rule.get('IpRanges', []):
            if ip_range.get('CidrIpv6') == '::/0':

                if rule.get('IpProtocol') == '-1':
                    ec2_client.revoke_security_group_ingress(
                        GroupId=sg_id,
                        IpPermissions=[rule]
                    )
                    print(f"Security Group {sg_id} completely open rule (all traffic) deleted successfully.")

                else:

                    from_port = rule.get('FromPort')
                    to_port = rule.get('ToPort')

                    if from_port == to_port:
                        if from_port in ports:
                            ec2_client.revoke_security_group_ingress(
                                GroupId = sg_id,
                                IpPermissions = [rule]
                            )
                        print(f"Security Group {sg_id} entry for port {from_port} deleted successfully.")
                    else:
                        if any(from_port <= port <= to_port for port in ports):
                            ec2_client.revoke_security_group_ingress(
                                GroupId=sg_id,
                                IpPermissions = [rule]
                            )
                            print(f"Security Group {sg_id} entry for port range {from_port}-{to_port} deleted successfully.")

    return True

#CIS 5.4 (VPC default security groups should not allow inbound or outbound traffic)
def cis_5_4(session, vpc_id, sg_id, new_sg_name):

    #remediation
    ec2_client = session.client('ec2')

    try:
        source_sg = ec2_client.describe_security_groups(GroupIds=[sg_id])
        inbound_rules = source_sg['SecurityGroups'][0]['IpPermissions']
        outbound_rules = source_sg['SecurityGroups'][0]['IpPermissionsEgress']

    except Exception as e:
        print(f"Failed to get security group {sg_id}: {str(e)}")
        return False
    
    new_sg = ec2_client.create_security_group(
        GroupName = new_sg_name,
        Description = f"CIS Remediation for {vpc_id}",
        VpcId = vpc_id
    )

    new_sg_id = new_sg['GroupId']
    print(f"New security group {new_sg_id} created successfully.")

    if inbound_rules:
        adjusted_inbound_rules = []
        for rule in inbound_rules:
            adjusted_inbound_rule = rule.copy()

            if "UserIdGroupPairs" in rule:
                adjusted_user_id_group_pairs = []
                for pair in rule["UserIdGroupPairs"]:
                    if pair["GroupId"] == sg_id:
                        adjusted_pair = pair.copy()
                        adjusted_pair["GroupId"] = new_sg_id
                        adjusted_user_id_group_pairs.append(adjusted_pair)
                    else:
                        adjusted_user_id_group_pairs.append(pair)
                adjusted_inbound_rule["UserIdGroupPairs"] = adjusted_user_id_group_pairs
                
            adjusted_inbound_rules.append(adjusted_inbound_rule)
            
        try:
            ec2_client.authorize_security_group_ingress(
                GroupId=new_sg_id,
                IpPermissions=adjusted_inbound_rules
            )
            print(f"Inbound rules authorized for security group {new_sg_id}.")
            
        except ec2_client.exceptions.ClientError as e:
            if "InvalidPermission.Duplicate" in str(e):
                print("Duplicate inbound rule found, skipping authorization.")
            else:
                print("Failed to authorize inbound rules for security group:", str(e))
                return False
                
        ec2_client.revoke_security_group_ingress(
            GroupId = sg_id,
            IpPermissions = inbound_rules
        )
        print("Old security group inbound rules removed.")

    if outbound_rules:
        
        adjusted_outbound_rules = []
        for rule in outbound_rules:
            adjusted_outbound_rule = rule.copy()

            if "UserIdGroupPairs" in rule:
                adjusted_user_id_group_pairs = []
                for pair in rule["UserIdGroupPairs"]:
                    if pair["GroupId"] == sg_id:
                        adjusted_pair = pair.copy()
                        adjusted_pair["GroupId"] = new_sg_id
                        adjusted_user_id_group_pairs.append(adjusted_pair)
                    else:
                        adjusted_user_id_group_pairs.append(pair)
                adjusted_outbound_rule["UserIdGroupPairs"] = adjusted_user_id_group_pairs

            adjusted_outbound_rules.append(adjusted_outbound_rule)
            
        try:
            ec2_client.authorize_security_group_egress(
                GroupId=new_sg_id,
                IpPermissions=adjusted_outbound_rules
            )
            print(f"Outbound rules authorized for security group {new_sg_id}.")
            
        except ec2_client.exceptions.ClientError as e:
            if "InvalidPermission.Duplicate" in str(e):
                print("Duplicate inbound rule found, skipping authorization.")
            else:
                print("Failed to authorize inbound rules for security group:", str(e))
                return False

        ec2_client.revoke_security_group_egress(
            GroupId = sg_id,
            IpPermissions = outbound_rules
        )
        print("Old security group outbound rules removed.")

    response = ec2_client.describe_instances(
        Filters=[{'Name': 'instance.group-id', 'Values': [sg_id]}]
    )

    if not response['Reservations']:
        print("No instances found in the security group.")
        return True

    instances_to_update = []
    for reservation in response['Reservations']:
        for instance in reservation['Instances']:
            instances_to_update.append(instance['InstanceId'])

    for instance_id in instances_to_update:
        
        instance_details = ec2_client.describe_instances(InstanceIds=[instance_id])
        current_sg_ids = [
            sg['GroupId'] for sg in instance_details['Reservations'][0]['Instances'][0]['SecurityGroups']
        ]

        updated_sg_ids = [sg_id for sg_id in current_sg_ids if sg_id != sg_id]
        updated_sg_ids.append(new_sg_id)

        ec2_client.modify_instance_attribute(
            InstanceId = instance_id,
            Groups = updated_sg_ids
        )

        print(f"Updated security groups for instance {instance_id}")

    return True
    
#CIS 5.6 (EC2 Instances sollten Instance Metadata Service Version 2 () IMDSv2 verwenden)
def cis_5_6(session, instance_id):

    #remediation
    ec2_client = session.client('ec2')

    ec2_client.modify_instance_metadata_options(
        InstanceId = instance_id,
        HttpTokens = 'required'
    )
    print(f"Instance {instance_id} has been updated to use IMDSv2.")

    return True