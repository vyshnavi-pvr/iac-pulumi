import json
import subprocess
import pulumi
import pulumi_gcp as gcp
from pulumi_aws import ec2, get_availability_zones, iam, route53, autoscaling, lb, cloudwatch, sns, secretsmanager, dynamodb, lambda_
import ipaddress
from pulumi_aws import ec2, secretsmanager, ssm, acm
import postgres_db
import base64
import utils
from pulumi_command import local


'''======================================'''
is_debug = False
# # Fetch the region from pulumi config
region = pulumi.Config("aws").require("region")
vpc_cidr = "10.0.0.0/" + pulumi.Config("iac-pulumi").require("vpcCidr")
print(f"VPC cidr-{vpc_cidr}")
instance_type = pulumi.Config(
    "iac-pulumi").require("instance_type")  # 't2.micro'

root_volume_size = int(pulumi.Config(
    "iac-pulumi").require("volume_size"))  # 25
root_volume_type = pulumi.Config("iac-pulumi").require("volume_type")  # 'gp2'
subnet_prefix_length = int(pulumi.Config(
    "iac-pulumi").require("subnet_prefix_length"))  # 24
gcp_project_id = pulumi.Config("gcp").require("project")

public_subnets = []
private_subnets = []

db_user = pulumi.Config("iac-pulumi").require("dbuser")
db_pass = pulumi.Config("iac-pulumi").require("dbpass")
url = pulumi.Config("iac-pulumi").require("url")


if url.startswith("demo"):
    acm_cert_arn = ssm.get_parameter(name="/demo/vyshnavi2024/certificate")
    acm_cert_arn = acm_cert_arn.value
    pulumi.export("acm_cert_arn", acm_cert_arn)
else:
    # Create ACM Certificate
    certificate = acm.Certificate("dev-certificate",
                                  domain_name=url,
                                  validation_method="DNS",
                                  )
    acm_cert_arn= certificate.arn
    # AWS Route53 Zone for the domain
    zone = route53.get_zone(name=url)

    # Find the DNS validation records
    validation_records = route53.Record("certificate_validation_dns_records",
                                        records=[certificate.domain_validation_options[0].resource_record_value],
                                        name=certificate.domain_validation_options[0].resource_record_name,
                                        type=certificate.domain_validation_options[0].resource_record_type,
                                        ttl=60,
                                        zone_id=zone.id,
                                        )

    # Validate the ACM certificate
    validation = acm.CertificateValidation("certificate_validation",
                                           certificate_arn=certificate.arn,
                                           validation_record_fqdns=[
                                               validation_records.fqdn],
                                           )
    pulumi.export("Create ACM certificate", "No certificate found")


# Get availability zones in the current region
azs = get_availability_zones(state="available")

# Limit to 3 if more available
actual_az_count = min(len(azs.names), 3)

num_subnets = actual_az_count * 2


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


def calculate_subnets(vpc_cidr, subnet_prefix_length):
    """Calculate subnets based on VPC CIDR and desired subnet prefix length."""
    return [str(subnet) for subnet in ipaddress.ip_network(vpc_cidr).subnets(new_prefix=subnet_prefix_length)]


def createSubnets():
    print(
        f"Creating Subnets......using VPC CIDR {vpc_cidr} and length: {subnet_prefix_length}")

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

        egress=[
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

                                                       ec2.SecurityGroupIngressArgs(
                                                           from_port=22,
                                                           to_port=22,
                                                           protocol="tcp",
                                                           security_groups=[
                                                               load_balancer_secrurity_group.id],
                                                       ),

                                                       ec2.SecurityGroupIngressArgs(
                                                           from_port=8001,
                                                           to_port=8001,
                                                           protocol="tcp",
                                                           security_groups=[
                                                               load_balancer_secrurity_group.id],
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
                                                   tags={
                                                       "Name": "application_security_group"}

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

load_balancer_secrurity_group = createLoadBalancerSecurityGroup()

application_security_group = createSecurityGroup()

ami_id = getLatestAMI()
print(f"********* AMI ID: {ami_id}")
key_pair = utils.getKeyPair()

database_security_group = createdbSecurityGroup()

encoded_user_data = base64.b64encode(
    utils.get_userdata_script().encode()).decode()

db = postgres_db.Database(name="csye6225", username=db_user, password=db_pass,
                          security_group_id=database_security_group.id, private_subnets=private_subnets)

db_end_point = secretsmanager.Secret("db_end_point",
                                     name="csye2023_db_end_point",
                                     description="DB end point"
                                     )


db_url = db.rds_instance.address

db.rds_instance.endpoint
pub_secret_version = secretsmanager.SecretVersion("db_end_point",
                                                  secret_id=db_end_point.id,
                                                  secret_string=db.rds_instance.address
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
instance_profile = utils.getIAMInstanceRole()


# Create a load balancer
load_balancer = lb.LoadBalancer(
    "my-loadbalancer",
    internal=False,
    security_groups=[load_balancer_secrurity_group.id],
    subnets=[public_subnet.id for public_subnet in public_subnets],
    load_balancer_type="application",
    enable_deletion_protection=False,
    tags={"Name": "LoadBalancer_CSYE6225"},
)

# Create a default target group to handle HTTP traffic on port 8001
target_group = lb.TargetGroup(
    "my-targetgroup",
    port=8001,
    protocol="HTTP",
    vpc_id=vpc.id,
    target_type="instance",
    health_check={
        "enabled": True,
        "path": "/healthz",
        "protocol": "HTTP",
        "port": "8001",
        "interval": 15,
        "timeout": 15,
        "healthy_threshold": 2,
        "unhealthy_threshold": 2,
    },
    tags={
        "Name": "TargetGroup_CSYE6225",
    }
)


listener = lb.Listener(
    "my-listener",
    load_balancer_arn=load_balancer.arn,
    port=443,
    protocol="HTTPS",
    certificate_arn=acm_cert_arn,
    default_actions=[lb.ListenerDefaultActionArgs(
        type="forward",
        target_group_arn=target_group.arn
    )]
)

hostedzone = route53.get_zone(name=url)
loadbalancerdnsname = load_balancer.dns_name


block_device_mappings = ec2.LaunchTemplateBlockDeviceMappingArgs(
    device_name="/dev/xvda",
    ebs=ec2.LaunchTemplateBlockDeviceMappingEbsArgs(
        volume_size=root_volume_size,
        volume_type=root_volume_type,
        delete_on_termination=True,
    )
)

tag_specifications = ec2.LaunchTemplateTagSpecificationArgs(
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
    block_device_mappings=[block_device_mappings],
    tag_specifications=[tag_specifications],

)

pulumi.export("launch template id", launch_template.id)

launch_param = ssm.Parameter(resource_name="LaunchTemplateId",
                             name='LaunchTemplateId',
                             type="String",
                             value=launch_template.id)


auto_scaling_group = autoscaling.Group("autoscalingGroup",
                                       desired_capacity=1,
                                       min_size=1,
                                       max_size=3,
                                       default_cooldown=60,
                                       health_check_type="EC2",
                                       launch_template=autoscaling.GroupLaunchTemplateArgs(
                                           id=launch_template.id,
                                           version="$Latest",
                                       ),
                                       termination_policies=["OldestInstance"],
                                       vpc_zone_identifiers=[
                                           public_subnet.id for public_subnet in public_subnets],
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
                                                    alarm_actions=[
                                                        scale_up_policy.arn],
                                                    dimensions={
                                                        "AutoScalingGroupName": auto_scaling_group.name},
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
                                                   alarm_actions=[
                                                       scale_down_policy.arn],
                                                   dimensions={
                                                       "AutoScalingGroupName": auto_scaling_group.name},
                                                   threshold=3,

                                                   )


autoscaling_group_id = auto_scaling_group.name
tg_arn = target_group.arn

attach_target_group_command = local.Command('attachTargetGroup',
                                            create=f'aws autoscaling attach-load-balancer-target-groups --auto-scaling-group-name $AUTOSCALING_GROUP_ID --target-group-arn $TARGET_GROUP_ARN',
                                            environment={
                                                "AUTOSCALING_GROUP_ID": autoscaling_group_id,
                                                "TARGET_GROUP_ARN": tg_arn
                                            },
                                            triggers=[autoscaling_group_id]
                                            )

autoscaling_param = ssm.Parameter(resource_name="AutoScalingGroupName",
                                  name='AutoScalingGroupName',
                                  type="String",
                                  value=auto_scaling_group.name)

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


def serialize(obj):
    return obj.__str__


sns_topic = sns.Topic("csye_topic")


sns_topic_param = ssm.Parameter(resource_name="csye_topic",
                                name='csye_topic',
                                type="String",
                                value=sns_topic.arn)


service_account = gcp.serviceaccount.Account(resource_name='csye-service-account',
                                             project=gcp_project_id,
                                             account_id='csye-service-account',
                                             display_name='CSYE Service Account')


service_account_key = gcp.serviceaccount.Key(resource_name='csye-service-account-key',
                                             service_account_id=service_account.id)

bucket = gcp.storage.Bucket(resource_name="csye-mybucket",
                            name="csye-mybucket", location="us-east1", project=gcp_project_id)


member_email = "csye-service-account@abiding-cycle-406523.iam.gserviceaccount.com"

# Create a GCP IAM policy
bucket_iam = gcp.storage.BucketIAMBinding("bucketIAM",
                                          bucket=bucket.id,
                                          members=[pulumi.Output.concat(
                                              'serviceAccount:', service_account.email)],
                                          role="roles/storage.admin",
                                          )


# Store Google Service Account access keys in Secrets Manager
google_credentials = secretsmanager.Secret("gcs_cred",
                                           name="gcs_cred",
                                           description="gcp credentials",
                                           )

decoded_key = service_account_key.private_key.apply(
    lambda key: base64.b64decode(key).decode("utf-8") if key else None
)

gcp_cred_secret = secretsmanager.SecretVersion("gcs_cred",
                                               secret_id=google_credentials.id,
                                               secret_string=decoded_key
                                               )


# Create a DynamoDB table for the Lambda Function
dynamodb_table = dynamodb.Table('csye-email-table',
                                attributes=[{
                                    'name': 'id',
                                    'type': 'S',
                                }],
                                hash_key='id',
                                billing_mode='PAY_PER_REQUEST')

lambda_role = iam.Role('lambda-role',
                       assume_role_policy=iam.get_policy_document(statements=[{
                           'actions': ['sts:AssumeRole'],
                           'principals': [{
                               'identifiers': ['lambda.amazonaws.com'],
                               'type': 'Service',
                           }],
                       }]).json)

# Create an IAM policy that grants the Lambda function access to the necessary services
lambda_policy = iam.RolePolicy('lambda-policy',
                               role=lambda_role.id,
                               policy=pulumi.Output.all(dynamodb_table.name, google_credentials.arn).apply(
                                   lambda args: iam.get_policy_document(statements=[{
                                       'actions': [
                                           's3:ListBucket',
                                           's3:GetObject',
                                           's3:PutObject',
                                           'dynamodb:*',
                                           'cloudwatch:*',
                                           'secretsmanager:GetSecretValue',
                                       ],
                                       'resources': ["*"]

                                   }]).json
                               )
                               )


lambda_policy_cloudwatch = iam.RolePolicyAttachment("lambda-cloudwatch-policy",
                                                    role=lambda_role.name,
                                                    policy_arn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole")

# Create a Lambda layer from the S3 bucket object
lambda_layer = lambda_.LayerVersion(
    'lambda_layer',
    code=pulumi.FileArchive('./app_layers.zip'),
    layer_name='my-lambda-layer',
    compatible_runtimes=["python3.9"]
)
# Create the Lambda function
lambda_function = lambda_.Function('csye-lambda-function',
                                   role=lambda_role.arn,
                                   runtime='python3.9',
                                   handler='serverless.lambda_handler',
                                   code=pulumi.FileArchive('./app.zip'),
                                   timeout=30,
                                   environment={
                                       'variables': {
                                           'GOOGLE_CREDENTIALS_SECRET_ARN': google_credentials.arn,
                                           'BUCKET_NAME': bucket.name,
                                           'DYNAMODB_TABLE_NAME': dynamodb_table.name,

                                       }
                                   },
                                   layers=[lambda_layer.arn],
                                   )

# Lambda function subscription on the SNS Topic
sns_subscription = sns.TopicSubscription('snsSubscription',
                                         endpoint=lambda_function.arn,
                                         topic=sns_topic.arn,
                                         protocol='lambda'

                                         )

# Allow the SNS topic to trigger the Lambda function
lambda_permission = lambda_.Permission('my_lambda_permission',
                                       action='lambda:InvokeFunction',
                                       function=lambda_function.name,
                                       principal='sns.amazonaws.com',
                                       source_arn=sns_topic.arn,
                                       )

pulumi.export("vpc_id", vpc.id)
pulumi.export("public_subnets_ids", [subnet.id for subnet in public_subnets])
pulumi.export("private_subnets_ids", [subnet.id for subnet in private_subnets])
pulumi.export("public_route_table_id", public_route_table.id)
pulumi.export("private_route_table_id", private_route_table.id)

'''======================================'''
