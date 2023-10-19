# """An AWS Python Pulumi program"""

import pulumi
from pulumi_aws import ec2, get_availability_zones
import ipaddress
import random
import json

# # Fetch the region from pulumi config
region = pulumi.Config("aws").require("region")
vpc_cidr = "10.0.0.0/"+ pulumi.Config("del-pulumi").require("vpcCidr")
instance_type = 't2.micro' 
ami_id = 'ami-08c92838631c75988'  
root_volume_size = 25
root_volume_type = 'gp2'

# Get availability zones in the current region
azs = get_availability_zones(state="available")

# Limit to 3 if more available
actual_az_count = min(len(azs.names), 3)

num_subnets = actual_az_count *2
subnet_prefix_length = int(vpc_cidr.split("/")[1]) + num_subnets

# Create a new VPChello
vpc = ec2.Vpc("my-vpc",
    cidr_block=vpc_cidr,
    enable_dns_support=True,
    enable_dns_hostnames=True,
)

# Create an Internet Gateway and attach it to the VPC
igw = ec2.InternetGateway("my-igw", vpc_id=vpc.id)

# Create a public route table
public_route_table = ec2.RouteTable("public-route-table",
    vpc_id=vpc.id,
)

# Create a private route table
private_route_table = ec2.RouteTable("private-route-table",
    vpc_id=vpc.id,
)

# Create a route for the Internet Gateway in the public route table
public_route = ec2.Route("public-route",
    route_table_id=public_route_table.id,
    destination_cidr_block="0.0.0.0/0",
    gateway_id=igw.id,
)

subnet_cidr_blocks = list(ipaddress.ip_network(vpc_cidr).subnets(new_prefix=subnet_prefix_length))
# Create public and private subnets in each AZ
public_subnets = []
private_subnets = []

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

# Create a security group for the EC2 instances
application_security_group = ec2.SecurityGroup("application_security_group",
    description="Security group for web application EC2 instances",
    vpc_id=vpc.id,
    tags={"Name": "application_security_group"},  # Customize the tags as needed
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

# Attach the ingress rules to the security group
for ingress_rule in ingress_rules:
    ec2.SecurityGroupRule(f"application-sg-rule{ingress_rule.from_port} ",
        security_group_id=application_security_group.id,
        type="ingress",
        from_port=ingress_rule.from_port,
        to_port=ingress_rule.to_port,
        protocol=ingress_rule.protocol,
        cidr_blocks=ingress_rule.cidr_blocks,
    )

public_ec2_instances= []

for  public_subnet in enumerate(public_subnets):
    print(json.dumps(public_subnet, indent=3))
    # instance= ec2.Instance (f"public-instance-{random.randint(1000, 9999)}",
    #     ami=ami_id,
    #     instance_type= instance_type,  # Update the instance type
    #     subnet_id=public_subnet.id,
    #     security_groups=[application_security_group.id],  # Attach the application security group
    #     root_block_device=ec2.InstanceRootBlockDeviceArgs(
    #         volume_size=root_volume_size,  # Update the root volume size
    #         volume_type=root_volume_type,  # Update the root volume type
    #         delete_on_termination=True,  # Ensure EBS volume is terminated with the EC2 instance
    #     ),
    #    # tags={"Name": f"public-instance-{i}"},  # Customize the tags as needed
    # )

    #public_ec2_instances.append(instance)
# Associate the security group with the public EC2 instances



# for instance in public_ec2_instances:
#     ec2.InstanceSecurityGroup(f"{instance.id}-sg",
#         instance_id=instance.id,
#         security_groups=[application_security_group.id],
#     )
# Export VPC ID, public subnets and private subnets IDs for reference in other stacks or scripts
pulumi.export("vpc_id", vpc.id)
pulumi.export("public_subnets_ids", [subnet.id for subnet in public_subnets])
pulumi.export("private_subnets_ids", [subnet.id for subnet in private_subnets])
pulumi.export("public_route_table_id", public_route_table.id)
pulumi.export("private_route_table_id", private_route_table.id)
pulumi.export("public_ec2_instance_ids", [instance.id for instance in public_ec2_instances])

# web = ec2.Instance("web",
#     ami=ami_id,
#     instance_type= instance_type,  # Update the instance type
#         subnet_id="subnet-0642ac6afd327f741",
#         security_groups=["sg-02ae4307467fd255c"],  # Attach the application security group
#         root_block_device=ec2.InstanceRootBlockDeviceArgs(
#             volume_size=root_volume_size,  # Update the root volume size
#             volume_type=root_volume_type,  # Update the root volume type
#             delete_on_termination=True,)
# )