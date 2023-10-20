# """An AWS Python Pulumi program"""

import pulumi
from pulumi_aws import ec2, get_availability_zones
import ipaddress
from pulumi_aws import ec2, secretsmanager
import subprocess
import os

# ami_id = 'ami-08c92838631c75988'  

is_debug = False
# # Fetch the region from pulumi config
region = pulumi.Config("aws").require("region")
vpc_cidr = "10.0.0.0/" + pulumi.Config("iac-pulumi").require("vpcCidr")
print(f"VPC cidr-{vpc_cidr}")
instance_type = pulumi.Config("iac-pulumi").require("instance_type") #'t2.micro'

root_volume_size =int(pulumi.Config("iac-pulumi").require("volume_size"))# 25
root_volume_type = pulumi.Config("iac-pulumi").require("volume_type")#'gp2'
subnet_prefix_length = int(pulumi.Config("iac-pulumi").require("subnet_prefix_length"))#24
# ec2_key_name = pulumi.Config("iac-pulumi").require("key")#"ec2-deployer"
ec2_key_name= "ec2-deployer"
public_subnets = []
private_subnets = []

# Get availability zones in the current region
azs = get_availability_zones(state="available")

# Limit to 3 if more available
actual_az_count = min(len(azs.names), 3)

num_subnets = actual_az_count * 2


# subnet_prefix_length = int(vpc_cidr.split("/")[1]) + num_subnets


def calculate_subnets(vpc_cidr, subnet_prefix_length):
    """Calculate subnets based on VPC CIDR and desired subnet prefix length."""
    return [str(subnet) for subnet in ipaddress.ip_network(vpc_cidr).subnets(new_prefix=subnet_prefix_length)]


def getLatestAMI():
    ami = ec2.get_ami(
        most_recent="true",
        owners=["831891561989"], 
        filters=[
            ec2.GetAmiFilterArgs(name="name", values=["cye6225_2023_*"])
        ]
    )
    print(f"AMI Id: {ami.id}, AMI Name: {ami.name}")
    return ami.id


def createSubnets():
    print(f"Creating Subnets......using VPC CIDR {vpc_cidr} and length: {subnet_prefix_length}")

    subnet_cidr_blocks = calculate_subnets(vpc_cidr, subnet_prefix_length)
    if is_debug:
        print(f"subnet cidr blocks {subnet_cidr_blocks}")

    for i, az in enumerate(azs.names[:actual_az_count]):
        # Calculate the CIDR ranges for subnets
        public_cidr = str(subnet_cidr_blocks[i])
        private_cidr = str(subnet_cidr_blocks[i + actual_az_count])

        # Create public subnet
        public_subnet = ec2.Subnet(f"public-subnet-{az}",
                                   vpc_id=vpc.id,
                                   cidr_block=public_cidr,
                                   availability_zone=az,
                                   map_public_ip_on_launch=True,
                                   )
        public_subnets.append(public_subnet)

        if is_debug:
            print(public_subnet, public_subnet.id)

        # Associate public subnets with the public route table
        ec2.RouteTableAssociation(f"public-subnet-association-{i}",
                                  subnet_id=public_subnet.id,
                                  route_table_id=public_route_table.id,
                                  )

        # Create private subnet
        private_subnet = ec2.Subnet(f"private-subnet-{az}",
                                    vpc_id=vpc.id,
                                    cidr_block=private_cidr,
                                    availability_zone=az,
                                    )
        private_subnets.append(private_subnet)

        # Associate private subnets with the private route table
        ec2.RouteTableAssociation(f"private-subnet-association-{i}",
                                  subnet_id=private_subnet.id,
                                  route_table_id=private_route_table.id,
                                  )


def getKeyPair():

    print("Creating Key pair *************** ")
    key_filename = ec2_key_name
    pub_key_secret_name = "ec2-deployer-public-key"
    private_key_secret_name = "ec2-deployer-private-key"
    public_key = None
    try:

        public_secret = secretsmanager.get_secret_version(secret_id=pub_key_secret_name)
        private_secret = secretsmanager.get_secret_version(secret_id=pub_key_secret_name)
        # Use the apply method to print the secret value
        public_key = public_secret.secret_string
        private_key = private_secret.secret_string
        print(f"retrived pub key {public_key}")
    except:
        print ("Public key not exists!")

    if not public_key:
        # Generate a new RSA key pair
        subprocess.run(["ssh-keygen", "-t", "rsa", "-b", "4096", "-f", key_filename, "-N", ""])

        # Read and print the content of the public key file
        with open(f"{key_filename}.pub", "r") as file:
            public_key = file.read()

        # Read keys into variables if needed
        with open(f"{key_filename}", "r") as file:
            private_key = file.read()

        # Remove key material from machine
        os.remove(f"{key_filename}")
        os.remove(f"{key_filename}.pub")

    key_pair = ec2.KeyPair(resource_name=ec2_key_name, key_name=ec2_key_name, public_key=public_key)
    pulumi.export('publicKey', key_pair.public_key)

    pub_secret = secretsmanager.Secret("ec2-deployer-public-key",
                                       name="ec2-deployer-public-keys",
                                       description="public key for deployer EC2 key pair"
                                       )

    pub_secret_version = secretsmanager.SecretVersion("ec2-deployer-public-secret-version",
                                                  secret_id=pub_secret.id,
                                                  secret_string=public_key
                                                  )

    private_secret = secretsmanager.Secret("ec2-deployer-private-key",
                                           name="ec2-deployer-private-keys",
                                           description="Private key for deployer EC2 key pair"
                                           )

    private_secret_version = secretsmanager.SecretVersion("ec2-deployer-private-secret-version",
                                                  secret_id=private_secret.id,
                                                  secret_string=private_key
                                                  )

    return key_pair


def createSecurityGroup():
    # # Create a security group for the EC2 instances
    application_security_group = ec2.SecurityGroup("application_security_group",
                                                   description="Security group for web application EC2 instances",
                                                   vpc_id=vpc.id,
                                                   tags={"Name": "application_security_group"}
                                                   # Customize the tags as needed
                                                   )
    # Define ingress rules to allow TCP traffic on specified ports
    ingress_rules = [
        ec2.SecurityGroupIngressArgs(
            from_port=22,
            to_port=22,
            protocol="tcp",
            cidr_blocks=["0.0.0.0/0"],  # Customize the source IP range as needed
        ),
        ec2.SecurityGroupIngressArgs(
            from_port=80,
            to_port=80,
            protocol="tcp",
            cidr_blocks=["0.0.0.0/0"],  # Customize the source IP range as needed
        ),
        ec2.SecurityGroupIngressArgs(
            from_port=443,
            to_port=443,
            protocol="tcp",
            cidr_blocks=["0.0.0.0/0"],  # Customize the source IP range as needed
        ),
        ec2.SecurityGroupIngressArgs(
            from_port=8001,
            to_port=8001,
            protocol="tcp",
            cidr_blocks=["0.0.0.0/0"],  # Customize the source IP range as needed
        ),
    ]

    # # Attach the ingress rules to the security group
    for ingress_rule in ingress_rules:
        ec2.SecurityGroupRule(f"application-sg-rule-{ingress_rule.from_port} ",
                              security_group_id=application_security_group.id,
                              type="ingress",
                              from_port=ingress_rule.from_port,
                              to_port=ingress_rule.to_port,
                              protocol=ingress_rule.protocol,
                              cidr_blocks=ingress_rule.cidr_blocks,
                              )

    return application_security_group


# Create a new VPC
vpc = ec2.Vpc("my-vpc-1",
              cidr_block=vpc_cidr,
              enable_dns_support=True,
              enable_dns_hostnames=True,
              )

# # Create an Internet Gateway and attach it to the VPC
igw = ec2.InternetGateway("my-igw-1", vpc_id=vpc.id)

# # Create a public route table
public_route_table = ec2.RouteTable("public-route-table",
                                    vpc_id=vpc.id,
                                    )

# # Create a private route table
private_route_table = ec2.RouteTable("private-route-table",
                                     vpc_id=vpc.id,
                                     )

# # Create a route for the Internet Gateway in the public route table
public_route = ec2.Route("public-route",
                         route_table_id=public_route_table.id,
                         destination_cidr_block="0.0.0.0/0",
                         gateway_id=igw.id,
                         )

createSubnets()

application_security_group = createSecurityGroup()

ami_id = getLatestAMI()

key_pair = getKeyPair()

public_ec2_instances = []

for i, public_subnet in enumerate(public_subnets):
    # print(public_subnet)
    instance_name = f"public-instance-{i}"
    instance = ec2.Instance(instance_name,
                            ami=ami_id,
                            key_name=key_pair.key_name,
                            instance_type=instance_type,
                            subnet_id=public_subnet.id,
                            vpc_security_group_ids=[application_security_group.id],
                            root_block_device=ec2.InstanceRootBlockDeviceArgs(
                                volume_size=root_volume_size,
                                volume_type=root_volume_type,
                                delete_on_termination=True,
                            ),
                            tags={"Name": instance_name},
                            )
    public_ec2_instances.append(instance)

# # Export VPC ID, public subnets and private subnets IDs for reference in other stacks or scripts
pulumi.export("vpc_id", vpc.id)
pulumi.export("public_subnets_ids", [subnet.id for subnet in public_subnets])
pulumi.export("private_subnets_ids", [subnet.id for subnet in private_subnets])
pulumi.export("public_route_table_id", public_route_table.id)
pulumi.export("private_route_table_id", private_route_table.id)
pulumi.export("public_ec2_instance_ids", [instance.id for instance in public_ec2_instances])
pulumi.export("public_ec2_ip", [instance.public_ip for instance in public_ec2_instances])

