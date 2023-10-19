class Config:
    aws_region = 'us-west-2'
    stack_name = 'my-stack'
    vpc_cidr_value = "10.0.0.0/16"
    vpc_name = "VPC-04-01"
    igw_name = "IGW-04-01"
    azs = ["us-east-1a", "us-east-1b", "us-east-1c"]
    cidr_range_public = "0.0.0.0/0"