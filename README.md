# Auto-Remediation-in-AWS-Organization-Based-on-CIS-Benchmark-V3.0.0-
Therefore, the core of this project is how to use CIS Benchmark V3.0.0 as a guide to securely use AWS cloud resources in large organizations through automated means.

In this project on resource monitoring and non-compliant resource remediation, we will mainly use Cloud Formation, AWS Config, Security Hub, Event Bridge, and Lambda Function from AWS resources.

**Last updated - Nov 2024**

# Catalogs
<details>
<summary>Lists</summary>

## Contents

- [Introduction](#1-introduction)
    - [1.1 Background](#11-Background)
    - [1.2 CIS Benchmark and CIS AWS Foundations Benchmark](#12-CIS-Benchmark-and-CIS-AWS-Foundations-Benchmark)
    - [1.3 CISv3.0.0 Recommended Controls](#13-CISv300-Recommended-Controls)
- [Framework Design](#2-framework-design)
    - [2.1 Non-compliant Resource Detection](#21-non-compliant-resource-detection)
    - [2.2 Integration of Detection Results](#22-integration-of-detection-results)
    - [2.3 Non-compliant Resource Remediation](#23-non-compliant-resource-remediation)
    - [2.4 (Optional) Adjustment of Detection Rules](#24-optional-adjustment-of-detection-rules)
- [Required AWS Serivce](#3-Required-AWS-Service)
- [Environment Setup](#4-Environment-Setup)
	- [4.1 Delegated Administrator Account Set Up - Account Level](#41-delegated-administrator-account-set-up---account-level)
		- [4.1.1 Set the Member Account to be the Delegated Administrator Account for the Security Hub](#411-set-the-member-account-to-be-the-delegated-administrator-account-for-the-security-hub)
    	- [4.1.2 Set Configuration in the Delegated Administrator Account](#412-set-configuration-in-the-delegated-administrator-account)
    	- [4.1.3 Set Lambda Function in the Delegated Administrator Account](#413-set-lambda-function-in-the-delegated-administrator-account)
    	- [4.1.4 Modify Lambda Function IAM Role Permissions in the Delegated Administrator Account](#414-modify-lambda-function-iam-role-permissions-in-the-delegated-administrator-account)
		- [4.1.5 Set the Event Bridge in the Delegated Administrator Account](#415-set-the-event-bridge-in-the-delegated-administrator-account)
    - [4.2 CloudFormation Stacksets Deployment - Organization Level](#42-cloudformation-stacksets-deployment---organization-level)
		- [4.2.1 AWS Config Deployment](#421-aws-config-deployment)
    	- [4.2.2 Remediation Role Deployment](#422-remediation-role-deployment)
    	- [4.2.3 SNS Notification Deployment](#423-sns-notification-deployment)
	- [4.3 AWS Service Catalog Deployment - Organization Level](#43-aws-service-catalog-deployment---organization-level)
		- [4.3.1 Management Account Set Up](#431-management-account-set-up)
    	- [4.3.2 Member Account Set Up](#432-member-account-set-up)
		- [4.3.3 Summary](#433-summary)
    - [4.4 Optional Requirement](#44-optional-requirement)

</details>

# 1. Introduction

## 1.1 Background
With the rapid popularization of cloud computing, cloud resources have become the core platform for enterprises and individuals to store, process, and manage data. With cloud resources, enterprises can obtain high-performance computing power at a lower cost and easily achieve global service coverage with its high flexibility.

However, the security of cloud resources is critical for data privacy protection, business continuity, and compliance with laws and regulations. Any security breach can lead to sensitive data leakage, interruption, and substantial economic losses. Therefore, securing cloud resources has become a critical task that must be addressed.

To address this challenge, the Center for Internet Security (CIS) has designed a set of practical security benchmarks that provide clear guidance on securing cloud resources.

As the world's leading cloud service provider, Amazon offers a wealth of cloud resources through its AWS (Amazon Web Services) platform, including network architecture services (such as VPC), database services (such as RDS and DynamoDB), storage solutions (such as S3 and EBS), and compute services (such as EC2) to meet different business scenarios' requirements of different business scenarios.

However, monitoring and preventing every security breach in a large organization is a greater challenge.

Therefore, the ultimate goal of this project is to use CIS Benchmark V3.0.0 as a guide to automate the secure use of AWS cloud resources in large organizations.

## 1.2 CIS Benchmark and CIS AWS Foundations Benchmark
CIS Benchmark is a series of globally recognized security configuration guides developed by the Center for Internet Security (CIS) covering various technology environments, including operating systems, cloud platforms, databases, network devices, and applications. The guidelines help organizations strengthen the protection of their IT systems and mitigate potential risks by providing specific, standardized configuration recommendations.

The CIS AWS Foundations Benchmark is a security configuration benchmark designed by the Center for Internet Security (CIS) specifically for Amazon Web Services (AWS) environments. This set of guidelines provides best practices for AWS accounts and services to help organizations ensure the security and compliance of their cloud resources, including identity and access management (IAM), logging, monitoring, and network configuration. It provides AWS users with more targeted security monitoring and remediation of non-compliant resources.

## 1.3 CISv3.0.0 Recommended Controls

# 2. Framework Design
The framework shown in the figure reflects the overall design concept of the project. The implementation of the entire framework will be divided into four parts:

Part 1. Non-compliant Resource Detection
Part 2. Integration of Detection Results
Part 3. Non-compliant Resource Remediation
Part 4. (Optional) Adjustment of Detection Rules
![CIS Benchmark Structure](./ScreenShots/Structure-parts.png)

## 2.1 Non-compliant Resource Detection
In this part AWS Config will undertake the resource detection task.

AWS Config is a service for continuously monitoring and evaluating the configuration of AWS resources. It automatically logs configuration changes and evaluates resources against predefined rules or custom rules the user sets (via AWS Config rules). It detects noncompliance by comparing the current state of the resource with the expected state. In this way, AWS Config ensures that resources comply with organizational standards, governance policies, and security best practices.

AWS Config tends to be triggered in two ways one is that instant detection is triggered when a resource is created or changed. The second is to automatically trigger a check on a resource every 24 hours based on a set rule.

If there are any non-compliant results AWS Config sends the results to Security Hub for integration.

![First Part](./ScreenShots/part1.png)

## 2.2 Integration of Detection Results
In this section, the Security Hub will be responsible for integrating discoveries from the AWS Config. Integration here means that the Security Hub receives findings not only from different regions of the account but also from different regions of other accounts in the AWS organization.

To implement this idea, each account in the AWS organization needs to enable Security Hub and send the received findings centrally to an administrative account for processing.

Thanks to the functionality provided by AWS, users can integrate discovery from other accounts by setting one account in the organization as the [Delegated Administrator Account](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_delegate_policies.html) for Security Hub. 

At the same time, the [Central Configuration](https://docs.aws.amazon.com/securityhub/latest/userguide/central-configuration-intro.html) feature provided by the Security Hub of the Delegated Administrator account allows users to turn on the Security Hub of other member accounts at once to perform the detection.

The Security Hub then sends the discovery to the Event Bridge which acts as a bridge to trigger the Lambda Function for subsequent remediation tasks.

![Second Part](./ScreenShots/part2.png)
![Security Hub](./ScreenShots/SecurityHub.png)

## 2.3 Non-compliant Resource Remediation
In this part, AWS Lambda takes responsibility for remediating non-compliant resources. Since Security Hub findings are integrated into the Delegated Administrator account, users only need to deploy the Lambda function from this account to manage remediation tasks.

AWS Lambda is a serverless computing service that allows users to run code without provisioning or managing servers. It automatically executes code based on triggers, enabling automated resource remediation by integrating Lambda functions with EventBridge. These Lambda functions interact with AWS resources by calling API operations through the AWS SDK.

Each Lambda function is assigned an IAM Role to control access and ensure secure operations. This IAM Role defines a set of permissions through a Policy file, specifying which services and operations the function can access.

For cross-account remediation, member accounts within an AWS organization must be configured with a dedicated IAM Role. This role is responsible for performing remediation tasks specific to each account. A dedicated IAM role in the Delegated Administrator account will also assume this dedicated IAM role.

![Third Part](./ScreenShots/part3.png)

## 2.4 (Optional) Adjustment of Detection Rules
This optional part will allow users to manually enable or disable a particular detection rule in AWS Config for a member account.

The implementation of this part comes mainly from an article called ["Disabling Security Hub controls in a multi-account environment"](https://aws.amazon.com/blogs/security/disabling-security-hub-controls-in-a-multi-account-environment/). See the corresponding [GitHub](https://github.com/aws-samples/aws-security-hub-cross-account-controls-disabler) for details.

# 3. Required AWS Serivce
1. [AWS Config](https://docs.aws.amazon.com/config/latest/developerguide/WhatIsConfig.html): A service that continuously monitors and evaluates the configuration of AWS resources against predefined or custom compliance rules.

2. [AWS Security Hub](https://docs.aws.amazon.com/securityhub/latest/userguide/what-is-securityhub.html): A centralized service that provides comprehensive security visibility, consolidating findings from multiple AWS services and third-party tools.

3. [AWS Lambda Function](https://docs.aws.amazon.com/lambda/latest/dg/welcome.html): A serverless computing service that runs code in response to events, enabling automated workflows and resource remediation.

4. [Amazon EventBridge](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-what-is.html): A serverless event bus that connects application events across AWS services and custom applications for automated workflows.

5. [Amazon Simple Notification Service (SNS)](https://docs.aws.amazon.com/sns/latest/dg/welcome.html): A fully managed messaging service for sending notifications to subscribers via multiple delivery methods like email or SMS.

6. [AWS CloudFormation](https://docs.aws.amazon.com/cloudformation/): A service that simplifies infrastructure management by allowing users to define, provision, and manage AWS resources using declarative code templates, ensuring consistent and repeatable deployments.

# 4. Environment Setup
This section explains how to deploy an automated remediation solution within an AWS Organization using the management account.

<span style = "color:red">Note: Any platform code deployed at the organization level will not be applied to the management account. This aligns with the principle of least privilege for the management account, meaning users should avoid setting up resources or configurations directly on the management account. This approach enhances the security of the management account by reducing its exposure and ensuring it does not require security checks for managed resources.</span>

## 4.1 Delegated Administrator Account Set Up - Account Level
In this part users need to make some manual settings for the Delegated Administrator Account of Security Hub. 

The reason for not automating this part of the setup is that users only need to make a few settings for one account.

Part 1. Set the Member Account to be the Delegated Administrator Account for the Security Hub 
Part 2. Set Configuration in the Delegated Administrator Account
Part 3. Set Lambda Function in the Delegated Administrator Account
Part 4. Modify Lambda Function IAM Role Permissions in the Delegated Administrator Account
Part 5. Set the Event Bridge in the Delegated Administrator Account

### 4.1.1 Set the Member Account to be the Delegated Administrator Account for the Security Hub 
1. Users need to enable Security Hub in the management account and then authorize one of the member accounts in the organization as a Delegated Administrator Account.

[!securityhub1]((./ScreenShots/securityhub1.png))

### 4.1.2 Set Configuration in the Delegated Administrator Account
1. Set up Central Configuration in the Delegated Administrator Account to enable Security Hub in all member accounts and use CIS Benchmark V3.0.0 as a benchmark.

[!securityhub2]((./ScreenShots/securityhub2.png))
[!securityhub3]((./ScreenShots/securityhub3.png))

<span style = "color:red">Note: When selecting monitoring areas it is recommended to select only the desired areas. If all areas are selected, additional time may be required to complete the setup.</span>

### 4.1.3 Set Lambda Function in the Delegated Administrator Account
1. Search for Lambda Function in AWS and set it up in the following order
`Create Function > Function name > Self-defined name > Runtime > python 3.8`

2. Upload the [CISRemediation.zip](./Lambda_Function/CISRemediation.zip) in the Lambda_Function folder that contains all the functions used to automate the fix after the functions have been created.

[!securityhub4]((./ScreenShots/securityhub4.png))

3. Once the code is uploaded, users need to add a Trigger to the Lambda Function and set the Event Bridge as the source so that the findings can trigger the corresponding fix function. 

[!securityhub5]((./ScreenShots/securityhub5.png))
[!securityhub6]((./ScreenShots/securityhub6.png))

4. Then users need to go to Configuration > General Configuration and set the Timeout as 30 sec. Otherwise some Lambda Functions can not execute in time.

### 4.1.4 Modify Lambda Function IAM Role Permissions in the Delegated Administrator Account
1. After successfully setting up the Lambda Function it automatically creates an IAM Role in the Delegated Administrator Account. Users will need to find this role and set up a separate permission for it in order to assume the Remediation Role in the other member accounts.

2. After finding the corresponding IAM Role follow these steps to add the policy
`Add permissions > Create inline policy > JSON > Copy the policy below > Name the policy as CISRemediation`

3. {
	"Version": "2012-10-17",
	"Statement": [
		{
			"Sid": "CrossAccountRemediatorRoleAssumption",
			"Effect": "Allow",
			"Action": "sts:AssumeRole",
			"Resource": "arn:aws:iam::*:role/CIS_Remediator_Role"
		}
	]
}

[!securityhub7]((./ScreenShots/securityhub7.png))

### 4.1.5 Set the Event Bridge in the Delegated Administrator Account
1. Search for Event Bridge in AWS and set it up.

2. In the `Build event pattern` set the `Event source` to `Other`.

3. In the `Creation method` set it to `Custom pattern`.

4. Copy the rule in [Event_Trigger.jason] in Event_Bridge_Trigger folder into the `Event pattern`.

5. Set the target to the Lambda Function user created in previous.

[!securityhub8]((./ScreenShots/securityhub8.png))
[!securityhub9]((./ScreenShots/securityhub9.png))

## 4.2 CloudFormation Stacksets Deployment - Organization Level
In this part, we will introduce three CloudFormation templates for deploying AWS resources at the organizational level.

These templates will be deployed to each member account through the admin account to ensure that a corresponding AWS resource is created in each member account.

Part 1. AWS Config Deployment
Part 2. Remediation Role Deployment
Part 3. SNS Notification Deployment

### 4.2.1 AWS Config Deployment
Since AWS Config is a regional resource, users in the corresponding region of their member accounts need to manually turn it on and set up the corresponding rules. Therefore, implementing this is not practical in large organizations.

The remediation solution provides a CloudFormation template called [Auto_AWS_Config_Deployment](./CloudFormation_Depolyment/Auto_AWS_Config_Deployment.yml) to automatically enable AWS Config in all member accounts for the corresponding region.

1. Upload the template in your management account by following the order of the following options `CloudFormation > StackSets > Create StackSet`

2. After a successful upload, users will be directed to the parameter settings page. This template already includes all the required parameters needed to enable the AWS Config service.

All parameters have been pre-configured with default values; however, users can modify these values to meet specific requirements. Each parameter includes a brief description to help users understand its purpose.

Special attention should be given to two parameters: Record global resource types and Record selected resource types.

When configuring these parameters, users should ensure that the Record selected resource types option is set to False. Since AWS Config is a regional service, enabling this option would result in global resources being redundantly recorded in every region where AWS Config is enabled. This would lead to unnecessary duplicate detections and increased costs.

The Record selected resource types option should only be enabled when neither of the first two options for recording resources is being utilized.

![AWS Config](./ScreenShots/awsconficloud.png)

![AWS Config2](./ScreenShots/awsconfig2.png)

<span style = "color:red">Note: If global resources need to be logged, users only need to enable AWS Config's global resource logging feature in one of the member accounts' regions. To fulfill this requirement users should run the template twice. The first time set up only one region and select Record Global Resources. The second time set up a region other than the previous region and do not record global resources.</span>

3. For the `Specify regions` option select regions to enable AWS Config.

4. Set the `Deployment targets` to `Deploy to organization` to ensure that this setting is deployed to all member accounts.

5. Set `Automatic deployment` to `Activated` in the `Auto-deployment options` to ensure that new member accounts joining the organization are also automatically enabled for AWS Config.

![AWS Config3](./ScreenShots/awsconfig3.png)

6. After successful setup, users can check in Stack instances to see if AWS Config has been successfully turned on in the selected region for each account.

![AWS Config4](./ScreenShots/awsconfig4.png)

### 4.2.2 Remediation Role Deployment
IAM Role being a global resource, users need to set up this role manually in each member account. Therefore, it is not practical to implement this feature in large organizations.

The remediation solution provides an application called [Auto_Remediator_Role_Deployment](./CloudFormation_Depolyment/Auto_Remediator_Role_Deployment.yml) CloudFormation template to automatically create the IAM Role for remediation measures in all member accounts.

1. Upload the template in your management account by following the order of the following options `CloudFormation > StackSets > Create StackSet`

2. After a successful upload, users will be directed to the parameter settings page. This template already includes all the required parameters needed to create a IAM Role.

3. Fill the first parameter with the ARN of the IAM Role that will be used to execute the Lambda Function so that the Security Hub's Delegated Administrator Account can assume the CIS_Remediator_Role of the member account.

<span style = "color:red">Note: It is recommended that users do not change the name of the role as it is used by default in the Lambda Function.</span>

![IAM Role1](./ScreenShots/iamrole1.png)

4. For the `Specify regions` option make sure to select only one region to create.

Since IAM roles are global resources selecting multiple regions will result in duplicate creation and thus conflicts.

![IAM Role2](./ScreenShots/iamrole2.png)

5. After successful setup, users can check in Stack instances to see if IAM role has been successfully created in the selected region for each account.

![IAM Role3](./ScreenShots/iamrole3.png)

### 4.2.3 SNS Notification Deployment
Since SNS Notification is a regional resource, users in the region corresponding to its member accounts need to open it manually and set up email addresses. Therefore, it is not practical to implement this feature in large organizations.

The remediation solution provides an application called [Auto_SNS_Notification_Deployment] (. /CloudFormation_Depolyment/Auto_SNS_Notification_Deployment.yml) CloudFormation template to automatically enable SNS Notification in all member accounts of the corresponding region.

1. Upload the template in your management account by following the order of the following options `CloudFormation > StackSets > Create StackSet`

2. After a successful upload, users will be directed to the parameter settings page. This template already includes all the required parameters needed to enable the SNS Notification.

3. Fill the email address to receive the notification of remediation result.

![SNS1](./ScreenShots/sns1.png)

4. For the `Specify regions` option select regions to enable SNS Notification.

5. After successful setup, users can check in Stack instances to see if SNS Notification has been successfully created in the selected region for each account.

![SNS2](./ScreenShots/sns2.png)

6. Please go to the email address users set to confirm the subcription.

<span style = "color:red">Note: The following deployment method is optional. The user only need to choose one way to deploy.</span>

## 4.3 AWS Service Catalog Deployment - Organization Level
AWS Service Catalog is designed to help organizations centrally manage and deploy an approved collection of IT services. It allows administrators to create and manage catalogs to deploy AWS resources.

Since AWS Service Catalog also uses the same template code as CloudFormation for product deployment. Therefore, users can also use this service to deploy AWS resources required for automated remediation programs.

Users can package the template code for product deployment in member accounts. Compared to CloudFormation, Sevice Catalog supports version release management, privilege access, and cost management, making it ideal for future updates and maintenance.

Users can easily upgrade the product or roll back to a previous version with versioning.

Privilege control ensures only authorized users or teams can access and use specific products.

Cost management helps users track and optimize resource usage more efficiently.

In addition, Service Catalog's centralized management capabilities support cross-account and multi-region product deployments, enabling organizations to maintain consistency and efficiency in large-scale environments.

<span style = "color:red">Note: All of the template code used in Service Catalog is the same as that used in CloudFormation. Therefore, when using Service Catalog products, please follow the same procedure as before. The section here only provides how to create and share Service Catalog products.</span>

### 4.3.1 Management Account Set Up

1. Search the Service Catalog in AWS in Management Account.

2. Follow these steps to create a product
`Product list > Create product > CloudFormation > Version details > Use a template file > Upload file` 

Then users need to enter the `Product name` and `Owner`

The `Support details` is optional.  

![CATALOG1](./ScreenShots/catalog1.png)
![CATALOG2](./ScreenShots/catalog2.png)

3. Follow these stesp to create portfolios for the products
`Portfolios > Create portfolio > After Creation > Actions > Add product to portfolio > Select the previous created products`

Users can add multiple products into one portfolio.

![CATALOG3](./ScreenShots/catalog3.png)

4. In Share tab users need to set how to share the portfolio. (For this product users should choose `AWS Organization`.)

![CATALOG4](./ScreenShots/catalog4.png)

### 4.3.2 Member Account Set Up

1. For member accounts receiving products search Service Catalog in AWS.

2. Follow these steps to receive a portfolio
`Portfolios > Imported > Actions > Import portfolio > Organization > Enter the Portfolio ID of the portfolio created in the Management Account`

![CATALOG5](./ScreenShots/catalog5.png)

3. In the Access tab choose the IAM User, Group or Role can use this product.

![CATALOG6](./ScreenShots/catalog6.png)

4. Log into the member account by the IAM User which the users have given access.

5. After login user can find the product under `Provisioning > Products`

![CATALOG7](./ScreenShots/catalog7.png)

### 4.3.3 Summary
AWS Service Catalog provides more flexible product deployment. Product owners can provide ongoing maintenance for automated remediation programs through version updates. 

At the same time the integration with IAM User better restricts access to the product by other users. 

However, compared to CloudFormation's direct deployment, Service Catalog requires more settings for product usage such as IAM User permissions and product acceptance. 

Therefore, this part is only an innovation of the project and is not mandatory for users.

# 4.4 Optional Requirement
For the creation of optional requirements follow the steps in [GitHub](https://github.com/aws-samples/aws-security-hub-cross-account-controls-disabler).