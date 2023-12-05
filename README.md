# Infrastructure as a Code using Pulumi

Steps to Run the Pulumi code to build infrastructure on AWS using python

This setup creates a VPC in us-east-1 by default with Internet Gateway and create one private subnet and one public subnet in each of 3AZs. Then Route tables are created for public and private subnets. Create EC2 instances with Security groups associated.Auto Scaling Group with Load balancer. Attached instances of Autoscaling group to Target Group. Implemented Secrets Manager and SSM Parameter Store to store credentials and information safely accessible. 

To make the infrastructure loosely-coupled, created SNS topics which will trigger lambda function to send email via mailgun and store in dynamodb about the message.Lambda adds the files after downloading to the GCS Cloud Storage buckets. To make the infrastructure secure, added SSL certificates to Load balancer.



1. Install Pulumi - https://www.pulumi.com/docs/install/
2. Install AWS CLI and set Profiles as demo using AWS keys - https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html
3. Install Python - https://www.pulumi.com/docs/languages-sdks/python/
4. set path if not set for pulumi
5. Download the repo and change the location to /infra/
6. export AWS_PROFILE=demo
7. gcloud auth application-default login
8. source venv/bin/activate
9. pulumi login --local
10. pulumi stack select demo
11. pulumi up
12. pulumi refresh
13. pulumi destroy

**Command to Upload  SSL certificate from Namecheap** 
```
aws iam upload-server-certificate --server-certificate-name demo_vyshnavi2024_me --certificate-body file://demo_vyshnavi2024_me.crt --private-key file://demo_vyshnavi2024_me.key --certificate-chain file://demo_vyshnavi2024_me.ca-bundle
```
