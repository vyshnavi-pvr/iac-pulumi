# """An AWS Python Pulumi program"""

import pulumi
from pulumi_aws import ec2, get_availability_zones, iam, route53, autoscaling, lb, cloudwatch, sns
import ipaddress
from pulumi_aws import ec2, secretsmanager, ssm
import subprocess
import os

'''======================================'''
is_debug = False
# ec2_key_name = pulumi.Config("iac-pulumi").require("key")#"ec2-deployer"
ec2_key_name = "ec2-deployer4"
# subnet_prefix_length = int(vpc_cidr.split("/")[1]) + num_subnets


def get_userdata_script():

    user_data_script = """#!/bin/bash

        . /home/admin/cs_env/bin/activate

        sudo systemctl daemon-reload

        sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -c file:/opt/cloudwatch-config.json -s
        sudo systemctl enable amazon-cloudwatch-agent
        sudo systemctl start amazon-cloudwatch-agent
        # sudo systemctl stop amazon-cloudwatch-agent

        # sudo systemctl restart amazon-cloudwatch-agent
        # sudo systemctl enable amazon-cloudwatch-agent.service

        sudo systemctl enable csye6225
        sudo systemctl start csye6225
        # sudo systemctl status csye6225

        # sudo service start amazon-cloudwatch-agent 
               
        """
    return user_data_script


def calculate_subnets(vpc_cidr, subnet_prefix_length):
    """Calculate subnets based on VPC CIDR and desired subnet prefix length."""
    return [str(subnet) for subnet in ipaddress.ip_network(vpc_cidr).subnets(new_prefix=subnet_prefix_length)]


def getIAMInstanceRole():

    # Create an IAM role
    ec2_role = iam.Role("csye2023-instance-role",
                        assume_role_policy="""{
            "Version": "2012-10-17",
            "Statement": [{
                "Action": "sts:AssumeRole",
                "Effect": "Allow",
                "Sid": "",
                "Principal": {
                    "Service": "ec2.amazonaws.com"
                }
            }]
        }"""
                        )

    # Create an instance profile
    instance_profile = iam.InstanceProfile("csye2023-instance-role_profile",
                                           role=ec2_role.name
                                           )

    # 2. Attach a policy to the role that grants access to Secrets Manager
    policy = iam.Policy("csye2023-secrets-policy",
                        description="A policy that grants access to Secrets Manager",
                        policy=pulumi.Output.from_input({
                            "Version": "2012-10-17",
                            "Statement": [{
                                "Action": [
                                    "secretsmanager:GetSecretValue",
                                    "secretsmanager:DescribeSecret",
                                    "ssm:*",
                                    "sns:*"
                                ],
                                "Resource": "*",
                                "Effect": "Allow"
                            }]
                        })
                        )

    # Attach the policy to the role
    role_policy_attachment = iam.RolePolicyAttachment("secrets-policy-attachment",
                                                      role=ec2_role.name,
                                                      policy_arn=policy.arn
                                                      )
    role_policy_attachment2 = iam.RolePolicyAttachment("policy-attachment2",
                                                       role=ec2_role.name,
                                                       policy_arn="arn:aws:iam::aws:policy/AmazonSSMFullAccess"
                                                       )

    cloudwatch_agent_policy_attachment = iam.RolePolicyAttachment("cloudwatch-agent-policy-attachment",
                                                                  role=ec2_role.name,
                                                                  policy_arn="arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy")

    return instance_profile


def getKeyPair():

    print("Creating Key pair *************** ")
    key_filename = ec2_key_name
    pub_key_secret_name = "ec2-deployer-public-key5"
    private_key_secret_name = "ec2-deployer-private-key5"
    public_key = None
    try:

        public_secret = secretsmanager.get_secret_version(
            secret_id=pub_key_secret_name)
        private_secret = secretsmanager.get_secret_version(
            secret_id=private_key_secret_name)
        # Use the apply method to print the secret value
        public_key = public_secret.secret_string
        private_key = private_secret.secret_string
        print(f"retrived pub key {public_key}")
    except:
        print("Public key not exists!")

    if not public_key:
        # Generate a new RSA key pair
        subprocess.run(["ssh-keygen", "-t", "rsa", "-b",
                       "4096", "-f", key_filename, "-N", ""])

        # Read and print the content of the public key file
        with open(f"{key_filename}.pub", "r") as file:
            public_key = file.read()

        # Read keys into variables if needed
        with open(f"{key_filename}", "r") as file:
            private_key = file.read()

        # Remove key material from machine
        os.remove(f"{key_filename}")
        os.remove(f"{key_filename}.pub")

    key_pair = ec2.KeyPair(resource_name=ec2_key_name,
                           key_name=ec2_key_name, public_key=public_key)
    pulumi.export('publicKey', key_pair.public_key)

    pub_secret = secretsmanager.Secret("ec2-deployer-public-key5",
                                       name="ec2-deployer-public-key5",
                                       description="public key for deployer EC2 key pair"
                                       )

    pub_secret_version = secretsmanager.SecretVersion("ec2-deployer-public-secret-version",
                                                      secret_id=pub_secret.id,
                                                      secret_string=public_key
                                                      )

    private_secret = secretsmanager.Secret("ec2-deployer-private-key5",
                                           name="ec2-deployer-private-key5",
                                           description="Private key for deployer EC2 key pair"
                                           )

    private_secret_version = secretsmanager.SecretVersion("ec2-deployer-private-secret-version",
                                                          secret_id=private_secret.id,
                                                          secret_string=private_key
                                                          )

    return key_pair
