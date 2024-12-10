# Auto-Remediation-in-AWS-Organization-Based-on-CIS-Benchmark-V3.0.0-
The core of this project is how to use the security rules in CIS Benchmark V3.0.0 to monitor the resources of each account in an AWS organization in real-time and remediate the non-compliant resources. 

In this project on resource monitoring and non-compliant resource remediation, we will mainly use Cloud Formation, AWS Config, Security Hub, Event Bridge, and Lambda Function from AWS resources.

**Last updated - Nov 2024**

# Catalogs
<details>
<summary>Lists</summary>

## Contents

- [Introduction](#Introduction)
- [Framework Design](#Framework Design)

</details>

# 1. Introduction

## 1.1 Background
With the rapid popularization of cloud computing, cloud resources have become the core platform for enterprises and individuals to store, process, and manage data. With cloud resources, enterprises can obtain high-performance computing power at a lower cost and easily achieve global service coverage with its high flexibility.

However, the security of cloud resources is critical for data privacy protection, business continuity, and compliance with laws and regulations. Any security breach can lead to sensitive data leakage, interruption, and substantial economic losses. Therefore, securing cloud resources has become a critical task that must be addressed.

To address this challenge, the Center for Internet Security (CIS) has designed a set of practical security benchmarks that provide clear guidance on securing cloud resources.

As the world's leading cloud service provider, Amazon offers a wealth of cloud resources through its AWS (Amazon Web Services) platform, including network architecture services (such as VPC), database services (such as RDS and DynamoDB), storage solutions (such as S3 and EBS), and compute services (such as EC2) to meet different business scenarios' requirements of different business scenarios.

So the ultimate goal of this project is how to use CIS Benchmark V3.0.0 as a guide to ensure that AWS cloud resources are being used securely.

## 1.2 CIS Benchmark and CIS AWS Foundations Benchmark
CIS Benchmark is a series of globally recognized security configuration guides developed by the Center for Internet Security (CIS) covering various technology environments, including operating systems, cloud platforms, databases, network devices, and applications. The guidelines help organizations strengthen the protection of their IT systems and mitigate potential risks by providing specific, standardized configuration recommendations.

The CIS AWS Foundations Benchmark is a security configuration benchmark designed by the Center for Internet Security (CIS) specifically for Amazon Web Services (AWS) environments. This set of guidelines provides best practices for AWS accounts and services to help organizations ensure the security and compliance of their cloud resources, including identity and access management (IAM), logging, monitoring, and network configuration. It provides AWS users with more targeted security monitoring and remediation of non-compliant resources.

## 1.3 CISv3.0.0 Recommended Controls
