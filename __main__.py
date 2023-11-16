# """An AWS Python Pulumi program"""

import pulumi
from pulumi_aws import ec2, get_availability_zones, iam, route53, autoscaling, lb, cloudwatch
import ipaddress
from pulumi_aws import ec2, secretsmanager,ssm
import subprocess
import os
import postgres_db
import base64



'''======================================'''
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
ec2_key_name= "ec2-deployer4"
public_subnets = []
private_subnets = []

db_user=pulumi.Config("iac-pulumi").require("dbuser")
db_pass=pulumi.Config("iac-pulumi").require("dbpass")
url=pulumi.Config("iac-pulumi").require("url")
# db_user="csye6225"
# db_pass="Laptop>300"

# Get availability zones in the current region
azs = get_availability_zones(state="available")

# Limit to 3 if more available
actual_az_count = min(len(azs.names), 3)

num_subnets = actual_az_count * 2
# subdomain="demo"

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
                                    "secretsmanager:DescribeSecret"
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

        public_secret = secretsmanager.get_secret_version(secret_id=pub_key_secret_name)
        private_secret = secretsmanager.get_secret_version(secret_id=private_key_secret_name)
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


def createLoadBalancerSecurityGroup():
    # Create a security group for the load balancer
    load_balancer_security_group = ec2.SecurityGroup(
        "loadBalancerSecurityGroup",
        description="Security group for the load balancer",
        vpc_id=vpc.id,
        ingress=[
            ec2.SecurityGroupIngressArgs(
                from_port=80,
                to_port=80,
                protocol="tcp",
                cidr_blocks=["0.0.0.0/0"],
            ),
            ec2.SecurityGroupIngressArgs(
                from_port=443,
                to_port=443,
                protocol="tcp",
                cidr_blocks=["0.0.0.0/0"],
            ),
        ],

        egress=[ # Allowing all outbound traffic
        ec2.SecurityGroupEgressArgs(
            protocol='-1',
            from_port=0,
            to_port=0,
            cidr_blocks=['0.0.0.0/0'],
        ),
        
    ],

        tags={"Name": "load_balancer_security_group"},
    )

    return load_balancer_security_group


def createSecurityGroup():
    # # Create a security group for the EC2 instances
    application_security_group = ec2.SecurityGroup("application_security_group",
        description="Security group for web application EC2 instances",
        vpc_id=vpc.id,

        ingress=[
        # SSH (Port 22)
        ec2.SecurityGroupIngressArgs(
            from_port=22,
            to_port=22,
            protocol="tcp",
            security_groups=[load_balancer_secrurity_group.id], # only allow traffic from the load balancer security group
        ),
        # Application Port (Port 8080)
        ec2.SecurityGroupIngressArgs(
            from_port=8001,
            to_port=8001,
            protocol="tcp",
            security_groups=[load_balancer_secrurity_group.id], # only allow traffic from the load balancer security group
        )
    ],

        egress=[
        {
            'protocol': '-1',
            'from_port': 0,
            'to_port': 0,
            'cidr_blocks': ['0.0.0.0/0'],
        },
    ],
        tags={"Name": "application_security_group"}
        # Customize the tags as needed   
        )


    return application_security_group

# Define the name of the security group
db_security_group_name = "database-security-group"

def createdbSecurityGroup():
    # Create a security group for the RDS instances
    db_security_group = ec2.SecurityGroup(
        db_security_group_name,
        description="Security group for RDS instances",
        vpc_id=vpc.id,  
        tags={"Name": "database_security_group"},
          
    )

    # Define the ingress rule to allow TCP traffic on port 5432 from the 'application security group'
    db_security_group_rule = ec2.SecurityGroupRule(
        "allow-postgres-ingress",
        type="ingress",
        from_port=5432,
        to_port=5432,
        protocol="tcp",
        security_group_id=db_security_group.id,
        source_security_group_id=application_security_group.id,  
    )

    
    return db_security_group




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

load_balancer_secrurity_group= createLoadBalancerSecurityGroup()

application_security_group = createSecurityGroup()

ami_id = getLatestAMI()

key_pair = getKeyPair()

database_security_group = createdbSecurityGroup()

encoded_user_data = base64.b64encode(get_userdata_script().encode()).decode()

db = postgres_db.Database(name="csye6225", username=db_user, password=db_pass,
                          security_group_id=database_security_group.id, private_subnets=private_subnets)

db_end_point = secretsmanager.Secret("db_end_point",
                                   name="csye2023_db_end_point",
                                   description="DB end point"
                                   )

pub_secret_version = secretsmanager.SecretVersion("db_end_point",
                                                  secret_id=db_end_point.id,
                                                  secret_string=db.rds_instance.endpoint
                                                  )

db_master_user = secretsmanager.Secret("db_master_user",
                                     name="db_master_user",
                                     description="DB username"
                                     )

db_user_secret_version = secretsmanager.SecretVersion("db_master_user",
                                                  secret_id=db_master_user.id,
                                                  secret_string=db_user
                                                  )

db_master_pass = secretsmanager.Secret("db_master_pass",
                                       name="db_master_pass",
                                       description="DB username"
                                       )

db_pass_secret_version = secretsmanager.SecretVersion("db_master_pass",
                                                  secret_id=db_master_pass.id,
                                                  secret_string=db_pass
                                                  )


'''To create EC2 instances in all public subnets'''
public_ec2_instances = []
instance_profile = getIAMInstanceRole()


# Create a load balancer
load_balancer = lb.LoadBalancer(
    "my-loadbalancer",
    internal = False,
    security_groups = [load_balancer_secrurity_group.id],
    subnets = [public_subnet.id for public_subnet  in public_subnets],
    load_balancer_type="application",
    enable_deletion_protection=False,
    tags={"Name": "LoadBalancer_CSYE6225"},
)

# Create a default target group to handle HTTP traffic on port 8080
target_group = lb.TargetGroup(
    "my-targetgroup",
    port = 8001,
    protocol = "HTTP",
    vpc_id = vpc.id,
    target_type="instance",
    health_check={
            "enabled": True,
            "path": "/healthz",  
            "protocol": "HTTP",
            "port": "8001",
            "interval": 30,
            "timeout": 5,
            "healthy_threshold": 2,
            "unhealthy_threshold": 2,
        },
        tags={
            "Name": "TargetGroup_CSYE6225",
        }
    )

listener = lb.Listener(
    "my-listener",
    load_balancer_arn = load_balancer.arn,
    port = 80,
    protocol="HTTP",
    default_actions = [lb.ListenerDefaultActionArgs(
        type="forward",
        target_group_arn=target_group.arn
    )]
)


hostedzone= route53.get_zone(name=url)
loadbalancerdnsname = load_balancer.dns_name


block_device_mappings=ec2.LaunchTemplateBlockDeviceMappingArgs(
    device_name="/dev/xvda",
    ebs=ec2.LaunchTemplateBlockDeviceMappingEbsArgs(
        volume_size=root_volume_size,
        volume_type=root_volume_type,
        delete_on_termination=True,
    )
)

tag_specifications= ec2.LaunchTemplateTagSpecificationArgs(
    resource_type="instance",
    tags={
        "Name": "autoScalingGroupInstance",
    }
)
# Create launch template
launch_template = ec2.LaunchTemplate(
    "web-app-launch-template",
    description="Launch template for web application instances",
    image_id=ami_id,  
    instance_type=instance_type,
    key_name=key_pair.key_name,  
    network_interfaces=[{
            "associate_public_ip_address": True,
            "security_groups": [application_security_group.id],
        }],
    iam_instance_profile=ec2.LaunchTemplateIamInstanceProfileArgs(
        name=instance_profile.name,  
    ),
    user_data=encoded_user_data, 
    block_device_mappings= [block_device_mappings],
    tag_specifications= [tag_specifications], 

)

# vpc_zone_identifiers = [public_subnet.id for public_subnet in public_subnets[:1]]
# public_subnets[0].id.apply(lambda id: id)
auto_scaling_group = autoscaling.Group("autoscalingGroup",
    desired_capacity=1,
    min_size=1,
    max_size=3, # Cap maximum size of the group
    default_cooldown=60,
    health_check_type="EC2",
    launch_template=autoscaling.GroupLaunchTemplateArgs(
        id=launch_template.id,
        version="$Latest",
    ),
    termination_policies=["OldestInstance"],
    vpc_zone_identifiers=[public_subnet.id for public_subnet in public_subnets], 
    tags=[autoscaling.GroupTagArgs(
        key="Name",
        value="web-asg-instance",
        propagate_at_launch=True
    )]
)
scale_down_policy = autoscaling.Policy("scale_down",
        scaling_adjustment=-1,
        adjustment_type="ChangeInCapacity",
        cooldown=60,
        autoscaling_group_name=auto_scaling_group.name,
        policy_type="SimpleScaling",
    )


scale_up_policy = autoscaling.Policy("scaleUpPolicy",
    autoscaling_group_name=auto_scaling_group.name,
    adjustment_type="ChangeInCapacity",
    scaling_adjustment=1,  
    cooldown=60,         
    policy_type="SimpleScaling",
)

# Create the scale up policy
cpu_utilization_high_alarm = cloudwatch.MetricAlarm("cpuUtilizationHighAlarm",
    metric_name="CPUUtilization",
    namespace="AWS/EC2",
    statistic="Average",
    comparison_operator="GreaterThanOrEqualToThreshold",
    evaluation_periods=2,
    period=120,
    alarm_description="This metric checks cpu utilization",
    alarm_actions=[scale_up_policy.arn],
    dimensions= { "AutoScalingGroupName": auto_scaling_group.name },
    threshold=5, 
    
)
cpu_utilization_low_alarm = cloudwatch.MetricAlarm("cpuUtilizationLowAlarm",
    metric_name="CPUUtilization",
    namespace="AWS/EC2",
    statistic="Average",
    comparison_operator="LessThanOrEqualToThreshold",
    evaluation_periods=2,
    period=120,
    alarm_description="This metric checks cpu utilization",
    alarm_actions=[scale_down_policy.arn],
    dimensions={ "AutoScalingGroupName": auto_scaling_group.name },
    threshold=3, 
    
)

# # register instances in the autoscaling group
# autoscaling_attachment = autoscaling.Attachment('autoscaling_attachment',
#     autoscaling_group_name=auto_scaling_group.name, 
#     lb_target_group_arn =target_group.arn
# )

# hostedzone= "Z0676186FVDWJZOR1MH4" #dev
# hostedzone='Z025470929G96ACB83BAB'#demo
# Create a Route53 Record Set
record_set = route53.Record("my-csye-record",
    zone_id=hostedzone.id,  
    name=url,  
    type="A",
    aliases=[
        route53.RecordAliasArgs(
            name=load_balancer.dns_name,
            zone_id=load_balancer.zone_id,
            evaluate_target_health=True
        )
    ]
)

# # Export VPC ID, public subnets and private subnets IDs for reference in other stacks or scripts
pulumi.export("vpc_id", vpc.id)
pulumi.export("public_subnets_ids", [subnet.id for subnet in public_subnets])
pulumi.export("private_subnets_ids", [subnet.id for subnet in private_subnets])
pulumi.export("public_route_table_id", public_route_table.id)
pulumi.export("private_route_table_id", private_route_table.id)
# pulumi.export("public_ec2_instance_ids", instance.id )
# pulumi.export("public_ec2_ip", instance.public_ip )
# pulumi.export("public_ec2_instance_ids", [instance.id for instance in public_ec2_instances])
# pulumi.export("public_ec2_ip", [instance.public_ip for instance in public_ec2_instances])
'''======================================'''

