import boto3
import json
from CISRemediation import *
import datetime


def lambda_handler(event, context):

    finding_json = event['detail']['findings'][0]

    aws_account_id = finding_json['AwsAccountId']
    region = finding_json['Resources'][0]['Region']
    security_control_id = finding_json['Compliance']['SecurityControlId']

    session = boto3.Session()
    sts_client = session.client('sts')  # Security Token Service client
    assume_role = sts_client.assume_role(
        RoleArn=f'arn:aws:iam::{aws_account_id}:role/CIS_Remediator_Role',
        RoleSessionName='CIS_Remediator_Session'
    )

    # -- retrieve temporary credentials and create the target session
    credentials = assume_role['Credentials']
    tempory_session = boto3.Session(
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken'],
        region_name=region
    )

    sns_client = tempory_session.client('sns')
    response_list = sns_client.list_topics()
    topic_arn = []
    for topic in response_list['Topics']:
        topic_arn.append(topic['TopicArn'])

    sns_arn = None
    for arn in topic_arn:
        # loops through topic_arn to find out arn specifically for cis remediation
        if "CISRemediationSNSTopic" in arn:
            sns_arn = arn
            break

    if sns_arn:
        print(f"Found SNS Topic ARN: {sns_arn}")
    else:
        print("Can not find SNS Topic ARN")
        return None

    #CIS 1.2 (Security contact information should be provided for an AWS account)
    if(security_control_id == "Account.1"):
        response = cis_1_2(tempory_session, aws_account_id)
        if response:
            subject = "CIS 1.2 Remediation Result"
            message = f"""

            A security contact information is created for account {aws_account_id}.
            Please modify the details of name, phone number, job tile and email address through AWS Console later.

            Account id : {aws_account_id}
            Region : {region} """

            publish_notification(tempory_session, sns_arn, message, subject)
            auto_update_securityhub_status(event, tempory_session)
        
    # CIS 1.4 (IAM root user access key should not exist)
    if (security_control_id == "IAM.4"):
        response = cis_1_4(tempory_session)
        if response:
            subject = "CIS 1.4 Remediation Result"
            message = f"""

            The root user access key needs to be removed manually. 
            Steps to perform remediation:
            1. Remove Root user access key in your account
            
            Account id : {aws_account_id}
            Region : {region} """

            publish_notification(tempory_session, sns_arn, message, subject)

    # CIS 1.5 (IAM root user should enable MFA)
    if (security_control_id == "IAM.9"):
        response = cis_1_5(tempory_session)
        if response:
            subject = "CIS 1.5 Remediation Result"
            message = f"""

            The root user MFA needs to be enabled anually. 
            Steps to perform remediation:
            1. Enable MFA for root user

            Account id : {aws_account_id}
            Region : {region} """

            publish_notification(tempory_session, sns_arn, message, subject)

    # CIS 1.6 (Hardware MFA should be enabled for the root user)
    if (security_control_id == "IAM.6"):
        response = cis_1_6(tempory_session)
        if response:
            subject = "CIS 1.6 Remediation Result"
            message = f"""

            The root user hardware MFA needs to be enabled manually. 
            Steps to perform remediation:
            1. Enable Hardware MFA for root user

            Account id : {aws_account_id}
            Region : {region} """

            publish_notification(tempory_session, sns_arn, message, subject)
            
    # CIS 1.8 Ensure IAM password policy requires minimum length of 14 or greater (Automated)
    if (security_control_id == "IAM.15"):
        response = cis_1_8(tempory_session)
        if response:
            subject = "CIS 1.8 Remediation Result"
            message = f"""

            Password policy changed. By default the minimum length of password will be set to 14.

            Account id : {aws_account_id}
            Region : {region} """

            publish_notification(tempory_session, sns_arn, message, subject)
            auto_update_securityhub_status(event, tempory_session)

    # CIS 1.9 (Ensure IAM password policy prevents password reuse)
    if (security_control_id == "IAM.16"):
        response = cis_1_9(tempory_session)
        if response:
            subject = "CIS 1.9 Remediation Result"
            message = f"""

            Password policy changed. By default the user can not use previous 24 passwords when set a new password.

            Account id : {aws_account_id}
            Region : {region} """

            publish_notification(tempory_session, sns_arn, message, subject)
            auto_update_securityhub_status(event, tempory_session)

    # CIS 1.10 (MFA should be enabled for all IAM users that have a console password)
    if (security_control_id == "IAM.5"):
        response = cis_1_10(tempory_session)
        if response:
            subject = "CIS 1.6 Remediation Result"
            message = f"""

            The MFA for IAM user needs to be enabled manually. 
            Steps to perform remediation:
            1. Enable MFA for all IAM users that have a console password

            Account id : {aws_account_id}
            Region : {region} """

            publish_notification(tempory_session, sns_arn, message, subject)
        
    # CIS 1.12 (IAM user credentials unused for 45 days should be removed)
    if (security_control_id == "IAM.22"):
        disabled_keys, disabled_users, password_deleted_users = cis_1_12(tempory_session)
        if disabled_keys or disabled_users or password_deleted_users:
            subject = "CIS 1.12 Remediation Result"
            message = f"""

            The IAM user credentials are not used for 45 days will be removed include passwords and access keys.

            Account id : {aws_account_id}
            Region : {region} 
            The following IAM users' access keys have been DISABLED: {disabled_users}
            The following access keys have been DISABLED: {disabled_keys}
            The following passwords have been DELETED: {password_deleted_users} """

            publish_notification(tempory_session, sns_arn, message, subject)
            auto_update_securityhub_status(event, tempory_session)

    # CIS 1.14 (IAM users' access keys should be rotated every 90 days or less)
    if (security_control_id == "IAM.3"):
        disabled_keys, disabled_users = cis_1_14(tempory_session)
        if disabled_keys or disabled_users:
            subject = "CIS 1.14 Remediation Result"
            message = f"""

            Access keys' status changed. By default, access keys will be set to inactive after 90 days.

            Account id : {aws_account_id}
            Region : {region} 
            The following IAM users' access keys have been DISABLED: {disabled_users}
            The following access keys have been DISABLED: {disabled_keys} """

            publish_notification(tempory_session, sns_arn, message, subject)
            auto_update_securityhub_status(event, tempory_session)

    # CIS 1.15 (IAM users' policy should be attached to the group)
    if (security_control_id == "IAM.2"):
        response = cis_1_15(tempory_session)
        if response:
            subject = "CIS 1.15 Remediation Result"
            message = f"""

            The policies previously attached directly to IAM users have been moved to newly created groups. 
            
            Users have been added to these groups, ensuring that the permissions of each users remain the same but are now applied at the group level.

            Account id : {aws_account_id}
            Region : {region} """

            publish_notification(tempory_session, sns_arn, message, subject)
            auto_update_securityhub_status(event, tempory_session)

    # CIS 1.17 Ensure a support role has been created to manage incidents with AWS Support
    if (security_control_id == "IAM.18"):
        response = cis_1_17(tempory_session)
        if response:
            subject = "CIS 1.17 Remediation Result"
            message = f"""

            A support role has been created to manage incidents with AWS Support.

            Account id : {aws_account_id}
            Region : {region} """

            publish_notification(tempory_session, sns_arn, message, subject)
            auto_update_securityhub_status(event, tempory_session)

    # CIS 1.19 (Ensure that all the expired SSL/TLS certificates stored in AWS IAM are removed)
    if (security_control_id == "IAM.26"):
        deleted_certificates = cis_1_19(tempory_session)
        if deleted_certificates:
            subject = "CIS 1.19 Remediation Result"
            message = f"""

            All the expired SSL/TLS certificates stored in AWS IAM are removed

            Account id : {aws_account_id}
            Region : {region} 
            
            The following certificates have been DELETED: {deleted_certificates}"""

            publish_notification(tempory_session, sns_arn, message, subject)
            auto_update_securityhub_status(event, tempory_session)

    #CIS 1.22 (IAM identities should not have the AWSCloudShellFullAccess policy attached)
    if (security_control_id == "IAM.27"):
        users_be_detached, roles_be_detached, groups_be_detached = cis_1_22(tempory_session)
        if users_be_detached or roles_be_detached or groups_be_detached:
            subject = "CIS 1.22 Remediation Result"
            message = f"""

            The IAM identities with the AWSCloudShellFullAccess policy attached will be removed include user/role/group.

            Account id : {aws_account_id}
            Region : {region} 
            The following IAM users' AWSCloudShellFullAccess policy have been DETACHED: {users_be_detached}
            The following IAM roles' AWSCloudShellFullAccess policy have been DETACHED: {roles_be_detached}
            The following IAM groups' AWSCloudShellFullAccess policy have been DETACHED: {groups_be_detached} """

            publish_notification(tempory_session, sns_arn, message, subject)
            auto_update_securityhub_status(event, tempory_session)

    #CIS 1.20 (IAM Access Analyzer external access analyzer should be enabled)
    if (security_control_id == "IAM.28"):
        response = cis_1_20(tempory_session, region)
        if response:
            subject = "CIS 1.20 Remediation Result"
            message = f"""

            IAM Access Analyzer external access analyzer should be enabled.

            Account id : {aws_account_id}
            Region : {region} 

            The IAM Access Analyzer external access analyzer has been ENABLED."""

            publish_notification(tempory_session, sns_arn, message, subject)
            auto_update_securityhub_status(event, tempory_session)

    #CIS 2.1.4.1 (S3 general purpose buckets should block public access at account level)
    if (security_control_id == "S3.1"):
        response = cis_2_1_4_1(tempory_session, aws_account_id)
        if response:
            subject = "CIS 2.1.4.1 Remediation Result"
            message = f"""

            S3 general purpose buckets should block public access at account level.

            Account id : {aws_account_id}
            Region : {region} 

            The policy to block public access has been ENABLED."""

            publish_notification(tempory_session, sns_arn, message, subject)
            auto_update_securityhub_status(event, tempory_session)
            
    # CIS 2.1.1 (S3 buckets should require requests to use Secure Socket Layer, set to deny HTTP requests)
    if (security_control_id == "S3.5"):
        bucket_name = finding_json["Resources"][0]["Details"]["AwsS3Bucket"]["Name"]
        response = cis_2_1_1(tempory_session, bucket_name)
        if response:
            subject = "CIS 2.1.1 Remediation Result"
            message = f"""

            {bucket_name} bucket policy has been updated.

            Account id : {aws_account_id}
            Region : {region}"""

            publish_notification(tempory_session, sns_arn, message, subject)
            auto_update_securityhub_status(event, tempory_session)

    #CIS 2.1.4.2 (S3 general purpose buckets should block public access at bucket level)
    if (security_control_id == "S3.8"):
        bucket_name = finding_json["Resources"][0]["Details"]["AwsS3Bucket"]["Name"]
        response = cis_2_1_4_2(tempory_session, bucket_name)
        if response:
            subject = "CIS 2.1.4.2 Remediation Result"
            message = f"""

            S3 general purpose buckets should block public access at bucket level.

            Account id : {aws_account_id}
            Region : {region} 

            The policy to block public access has been ENABLED."""

            publish_notification(tempory_session, sns_arn, message, subject)
            auto_update_securityhub_status(event, tempory_session)

    #CIS 2.1.2 (S3 general purpose buckets should have MFA delete enabled)
    if (security_control_id == "S3.20"):
        bucket_name = finding_json["Resources"][0]["Details"]["AwsS3Bucket"]["Name"]
        response = cis_2_1_2(tempory_session)
        if response:
            subject = "CIS 2.1.2 Remediation Result"
            message = f"""

            The MFA delete enabled needs to be manually enabled for {bucket_name} bucket.

            Steps to perform remediation:
            1. Enable Hardware MFA for root user

            Account id : {aws_account_id}
            Region : {region}"""

            publish_notification(tempory_session, sns_arn, message, subject)

    #CIS 3.8 (S3 general purpose buckets should log object-level write events)
    if (security_control_id == "S3.22"):
        response = cis_3_8(tempory_session, region, aws_account_id)
        if response:
            subject = "CIS 3.8 Remediation Result"
            message = f"""

            A S3 bucket is created at {region} to store the logs of object-level write events.
            A cloud trail is created to record the write events of all S3 buckets.
            
            Account id : {aws_account_id}
            Region : {region}"""

            publish_notification(tempory_session, sns_arn, message, subject)
            auto_update_securityhub_status(event, tempory_session)

    #CIS 3.9 (S3 general purpose buckets should log object-level read events)
    if (security_control_id == "S3.23"):
        response = cis_3_9(tempory_session, region, aws_account_id)
        if response:
            subject = "CIS 3.9 Remediation Result"
            message = f"""

            A S3 bucket is created at {region} to store the logs of object-level read events.
            A cloud trail is created to record the read events of all S3 buckets.

            Account id : {aws_account_id}
            Region : {region}"""

            publish_notification(tempory_session, sns_arn, message, subject)
            auto_update_securityhub_status(event, tempory_session)

    #CIS 3.1 (CloudTrail should be enabled and configured with at least one multi-Region trail that includes read and write management events)
    if(security_control_id == "CloudTrail.1"):
        response = cis_3_1(tempory_session, region, aws_account_id)
        if response:
            subject = "CIS 3.1 Remediation Result"
            message = f"""

            A multi-Region cloud tral is created at {region} to store the read and write management events.

            Account id : {aws_account_id}
            Region : {region}"""

            publish_notification(tempory_session, sns_arn, message, subject)
            auto_update_securityhub_status(event, tempory_session)

    #CIS 3.5 (CloudTrail should have encryption at-rest enabled)
    if(security_control_id == "CloudTrail.2"):
        trail_name = finding_json["Resources"][0]["Id"]
        response = cis_3_5(tempory_session, aws_account_id, trail_name)
        if response:
            subject = "CIS 3.5 Remediation Result"
            message = f"""

            A kms key cloudtrail-encryption-key is created to encrypt the cloud trail {trail_name}.
            
            The cloud trail {trail_name} is encrypted with the kms key cloudtrail-encryption-key.

            Account id : {aws_account_id}
            Region : {region}"""

            publish_notification(tempory_session, sns_arn, message, subject)
            auto_update_securityhub_status(event, tempory_session)

    #CIS 3.2 (CloudTrail log file validation should be enabled)
    if(security_control_id == "CloudTrail.4"):
        trail_name = finding_json["Resources"][0]["Id"]
        response = cis_3_2(tempory_session, trail_name)
        if response:
            subject = "CIS 3.2 Remediation Result"
            message = f"""
            
            The cloud trail {trail_name} has ENABLED the log file validation.

            Account id : {aws_account_id}
            Region : {region}"""

            publish_notification(tempory_session, sns_arn, message, subject)
            auto_update_securityhub_status(event, tempory_session)

    #CIS 3.4 (Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket)
    if(security_control_id == "CloudTrail.7"):
        base_name = 'accesslogbucket'
        logic_bucket_name = f"{base_name}-{aws_account_id}-{region}"
        bucket_name = finding_json["Resources"][0]["Id"].split(':::')[-1]
        response = cis_3_4(tempory_session, bucket_name, aws_account_id, region)
        if response:
            subject = "CIS 3.4 Remediation Result"
            message = f"""

            The S3 bucket {logic_bucket_name} is CREATED or ENABLED to store the access logs of the S3 bucket {bucket_name}.

            Account id : {aws_account_id}
            Region : {region}"""

            publish_notification(tempory_session, sns_arn, message, subject)
            auto_update_securityhub_status(event, tempory_session)

    #CIS 3.6 (AWS KMS key rotation should be enabled)
    if(security_control_id == "KMS.4"):
        kms_key_id = finding_json['Resources'][0]['Details']['AwsKmsKey']['KeyId']
        response = cis_3_6(tempory_session, kms_key_id)
        if response:
            subject = "CIS 3.6 Remediation Result"
            message = f"""

            The AWS KMS key {kms_key_id} Enabled Automatically rotation for one year.

            Account id : {aws_account_id}
            Region : {region}"""

            publish_notification(tempory_session, sns_arn, message, subject)
            auto_update_securityhub_status(event, tempory_session)

    #CIS 3.7 (VPC flow logging should be enabled in all VPCs)
    if (security_control_id == 'EC2.6'):
        vpc_id = finding_json['Resources'][0]['Id'].split('/')[-1]
        reponse = cis_3_7(tempory_session, vpc_id, region, aws_account_id)
        if reponse:
            subject = "CIS 3.7 Remediation Result"
            message = f"""

            The VPC flow logging is ENABLED at {vpc_id}.
            A IAM role CIS-Remediations-VPC-Log-Role is created to enable the VPC flow logging.

            Account id : {aws_account_id}
            Region : {region}"""

            publish_notification(tempory_session, sns_arn, message, subject)
            auto_update_securityhub_status(event, tempory_session)

    #CIS 2.2.1 (EBS default encryption should be enabled)
    if (security_control_id == 'EC2.7'):
        response = cis_2_2_1(tempory_session)
        if response:
            subject = "CIS 2.2.1 Remediation Result"
            message = f"""

            The defaul encryption is ENABLED for all EBS volumes.

            Account id : {aws_account_id}
            Region : {region}"""

            publish_notification(tempory_session, sns_arn, message, subject)
            auto_update_securityhub_status(event, tempory_session)

    #CIS 2.3.3 (Ensure that public access is not given to RDS Instance)
    if(security_control_id == 'RDS.2'):
        response = cis_2_3_3(tempory_session)
        if response:
            subject = "CIS 2.3.3 Remediation Result"
            message = f"""

            PubliclyAcessible flags in RDS instances have been set to "No". 
            Amazon Relational Database Service (Amazon RDS) instances are not publicly accessible now. 

            CIS 2.3.3: Ensure that public access is not given to RDS Instance
            Account id : {aws_account_id}
            Region : {region} 

            The IAM Access Analyzer external access analyzer has been ENABLED."""

            publish_notification(tempory_session, sns_arn, message, subject)
            auto_update_securityhub_status(event, tempory_session)

    #CIS 2.3.1 (RDS DB instances should have encryption at-rest enabled)
    if (security_control_id == 'RDS.3'):
        rds_instance_id = finding_json['Resources'][0]['Details']['AwsRdsDbInstance']['DBInstanceIdentifier']
        #If you did not see the remediation result, please check the Timeout in Lambda function configuration. 
        #The database may take more time than setted in the Timeout because of the size.
        response = cis_2_3_1(tempory_session, rds_instance_id, aws_account_id)
        if response:
            subject = "CIS 2.3.1 Remediation Result"
            message = f"""
    
            The RDS instance {rds_instance_id} is encrypted with the created rds-encryption KMS key .
            
            Account id : {aws_account_id}
            Region : {region}"""

            publish_notification(tempory_session, sns_arn, message, subject)
            auto_update_securityhub_status(event, tempory_session)

    #CIS 2.3.2 (RDS automatic minor version upgrades should be enabled)
    if (security_control_id == 'RDS.13'):
        rds_instance_id = finding_json['Resources'][0]['Details']['AwsRdsDbInstance']['DBInstanceIdentifier']
        response = cis_2_3_2(tempory_session, rds_instance_id)
        if response:
            subject = "CIS 2.3.2 Remediation Result"
            message = f"""

            The RDS automatic minor version is enabled for the RDS instance {rds_instance_id}.

            Account id : {aws_account_id}
            Region : {region}"""

            publish_notification(tempory_session, sns_arn, message, subject)
            auto_update_securityhub_status(event, tempory_session)

    #CIS 2.4.1 (Ensure that encryption is enabled for EFS file systems)
    if(security_control_id == 'EFS.1'):
        non_compliant_file_systems, new_efs_file_systems = cis_2_4_1(tempory_session)
        non_compliant_text = "\n".join(non_compliant_file_systems) if non_compliant_file_systems else "None"
        new_efs_text = "\n".join(new_efs_file_systems) if new_efs_file_systems else "None"

        if non_compliant_file_systems:
            subject = "CIS 2.4.1 Remediation Result [ACTIONS REQUIRED!]"
            message = f"""

            New empty EFS file systems have been created.
            PLEASE MIGRATE DATA FROM NON-COMPLIANT SYSTEMS TO NEW SYSTEMS MANUALLY.

            Non-compliant EFS File Systems:
            {non_compliant_text}

            Newly Created Encrypted EFS File Systems:
            {new_efs_text}


            CIS 2.4.1: Ensure that encryption is enabled for EFS file systems
            Account id : {aws_account_id}
            Region : {region} 

            The IAM Access Analyzer external access analyzer has been ENABLED."""

            publish_notification(tempory_session, sns_arn, message, subject)
            auto_update_securityhub_status(event, tempory_session)

    #CIS 5.1 (Network ACLs should not allow ingress from 0.0.0.0/0 to port 22 or port 3389)
    if (security_control_id == 'EC2.21'):
        network_acl_id = finding_json["Resources"][0]["Details"]["AwsEc2NetworkAcl"]["NetworkAclId"]
        response = cis_5_1(tempory_session, network_acl_id)
        if response:
            subject = "CIS 5.1 Remediation Result"
            message = f"""

            The Network ACL {network_acl_id} has removed the rule which allow ingress from 0.0.0.0/0 to port 22 or port 3389.

            Account id : {aws_account_id}
            Region : {region}"""

            publish_notification(tempory_session, sns_arn, message, subject)
            auto_update_securityhub_status(event, tempory_session)

    #CIS 5.2 (EC2 security groups should not allow ingress from 0.0.0.0/0 to remote server administration ports)
    if (security_control_id == 'EC2.53'):
        sg_id = finding_json["Resources"][0]["Details"]["AwsEc2SecurityGroup"]["GroupId"]
        response = cis_5_2(tempory_session, sg_id)
        if response:
            subject = "CIS 5.2 Remediation Result"
            message = f"""

            The Security Group {sg_id} has removed the inbound rule which allow ingress from 0.0.0.0/0 to to remote server administration ports (Port 22 and Port 3389).

            Account id : {aws_account_id}
            Region : {region}"""

            publish_notification(tempory_session, sns_arn, message, subject)
            auto_update_securityhub_status(event, tempory_session)

    #CIS 5.3 (EC2 security groups should not allow ingress from ::/0 to remote server administration ports)
    if (security_control_id == 'EC2.54'):
        sg_id = finding_json["Resources"][0]["Details"]["AwsEc2SecurityGroup"]["GroupId"]
        response = cis_5_3(tempory_session, sg_id)
        if response:
            subject = "CIS 5.3 Remediation Result"
            message = f"""

            The Security Group {sg_id} has removed the inbound rule which allow ingress from ::/0 to to remote server administration ports (Port 22 and Port 3389).

            Account id : {aws_account_id}
            Region : {region}"""

            publish_notification(tempory_session, sns_arn, message, subject)
            auto_update_securityhub_status(event, tempory_session)
        
    #CIS 5.4 (VPC default security groups should not allow inbound or outbound traffic)
    if (security_control_id == 'EC2.2'):
        sg_id = finding_json["Resources"][0]["Details"]["AwsEc2SecurityGroup"]["GroupId"]
        vpc_id = finding_json["Resources"][0]["Details"]["AwsEc2SecurityGroup"]["VpcId"]
        new_sg_name = f"{vpc_id}_{uuid.uuid4().hex[:8]}"
        response = cis_5_4(tempory_session, vpc_id, sg_id, new_sg_name)
        if response:
            subject = "CIS 5.4 Remediation Result"
            message = f"""

            The Security Group {sg_id} assosiated with the VPC {vpc_id} has removed all the inbound and outbound rules.
            A new Security Group {new_sg_name} is created to assosiate with the VPC {vpc_id} and previous rules.

            Account id : {aws_account_id}
            Region : {region}"""

            publish_notification(tempory_session, sns_arn, message, subject)
            auto_update_securityhub_status(event, tempory_session)

    #CIS 5.6 (EC2 Instances sollten Instance Metadata Service Version 2 () IMDSv2 verwenden)
    if (security_control_id == 'EC2.8'):
        instance_id = finding_json["Resources"][0]["Id"].split("/")[-1]
        response = cis_5_6(tempory_session, instance_id)
        if response:
            subject = "CIS 5.6 Remediation Result"
            message = f"""

            The EC2 Instanse {instance_id} has enabled the Instance Metadata Service Version 2 (IMDSv2).

            Account id : {aws_account_id}
            Region : {region}"""

            publish_notification(tempory_session, sns_arn, message, subject)
            auto_update_securityhub_status(event, tempory_session)

    #CIS 3.3 Ensure AWS Config is enabled in all regions
    if(security_control_id == 'Config.1'):
        response = cis_3_3(tempory_session)
        if response:
            subject = "CIS 3.3 Remediation Result"
            message = f"""

            AWS Config is currently not enabled in region: {region}.
            You may choose to enable this service based on your specific compliance and monitoring requirements.

            Please note that no auto-remediation is set up for this control due to the following considerations:

            1. Global Resource Considerations: global resource tracking might only need to be enabled in specific regions instead of all regions;
            2. Cost Implications: Automatically enabling AWS Config in all regions can lead to higher-than-expected expenses, particularly in regions where monitoring may not be necessary.

            CIS 3.3: Ensure AWS Config is enabled in all regions
            Account id : {aws_account_id}
            Region : {region} 
            """

            publish_notification(tempory_session, sns_arn, message, subject)
            auto_update_securityhub_status(event, tempory_session)

    