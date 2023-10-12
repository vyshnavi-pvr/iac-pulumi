


import pulumi
import pulumi_aws as aws
from variables import Config as cfg
import ipaddress  

vpc_cidr_value= cfg.vpc_cidr_value
vpc_name = cfg.vpc_name
igw_name = cfg.igw_name
azs = cfg.azs
cidr_range_public = cfg.cidr_range_public

# config = pulumi.Config()
# vpc_cidr_value = config.require("vpc:cidr_value")
# vpc_name = config.require("vpc:name")
# igw_name = config.require("igw:name")
# azs = config.require_object("vpc:azs")
# cidr_range_public = config.require("vpc:cidr_range_public")


subnets_cidr_ranges = list(ipaddress.IPv4Network(vpc_cidr_value).subnets(prefixlen_diff=8))

vpc = aws.ec2.Vpc(
    vpc_name,
    cidr_block=vpc_cidr_value,
    enable_dns_hostnames=True,
    enable_dns_support=True,
    tags={
        'Name': 'Vpc_04'
    }
)

igw = aws.ec2.InternetGateway(igw_name, vpc_id=vpc.id)

public_subnets = []
private_subnets = []

for i, az in enumerate(azs):
    public_subnet = aws.ec2.Subnet(f"publicSubnet-{i}",
        vpc_id=vpc.id,
        cidr_block=str(subnets_cidr_ranges[i]),
        availability_zone=az,
        map_public_ip_on_launch=True
    )

    public_subnets.append(public_subnet.id)

    private_subnet = aws.ec2.Subnet(f"privateSubnet-{i}",
        vpc_id=vpc.id,
        cidr_block=str(subnets_cidr_ranges[i + 3]),  
        availability_zone=az
    )

    private_subnets.append(private_subnet.id)

    private_route_table = aws.ec2.RouteTable(f"privateRouteTable-{i}",
        vpc_id=vpc.id
    )

    
    aws.ec2.RouteTableAssociation(f"privateSubnetAssociation-{i}",
        subnet_id=private_subnet.id,
        route_table_id=private_route_table.id
    )

for i, public_subnet_id in enumerate(public_subnets):
    public_route_table = aws.ec2.RouteTable(f"publicRouteTable-{i}",
        vpc_id=vpc.id,
        routes=[
            aws.ec2.RouteTableRouteArgs(
                cidr_block=cidr_range_public,
                gateway_id=igw.id
            )
        ]
    )

    aws.ec2.RouteTableAssociation(f"publicSubnetAssociation-{i}",
        subnet_id=public_subnet_id,
        route_table_id=public_route_table.id
    )

pulumi.export("vpcID", vpc.id)
pulumi.export("publicSubnetIDs", public_subnets)
pulumi.export("privateSubnetIDs", private_subnets)







