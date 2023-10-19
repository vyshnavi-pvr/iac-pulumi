# iac-pulumi

Steps to Run the Pulumi code to build infrastructure on AWS using python

This setup creates a VPC in us-east-1 by default with Internet Gateway and create one private subnet and one public subnet in each of 3AZs. Then Route tables are created for public and private subnets. Ec2 Instances are creted with security groups in the same VPC created.

1. Install Pulumi - https://www.pulumi.com/docs/install/
2. Install AWS CLI and set Profiles as demo using AWS keys - https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html
3. Install Python - https://www.pulumi.com/docs/languages-sdks/python/
4. set path if not set for pulumi
5. Download the repo and change the location to /infra/
6. export AWS_PROFILE=demo
7. source venv/bin/activate
8. pulumi login --local
9. pulumi stack select demo
10. pulumi up
