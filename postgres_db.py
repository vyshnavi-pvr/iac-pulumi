import pulumi
import pulumi_aws as aws


class Database(pulumi.ComponentResource):
    def __init__(self, name: str, username: str, password: str, security_group_id: str,private_subnets, opts=None):
        super().__init__("custom:rds:DatabasePostgres", name, {}, opts)


        # Instantiate an RDS ParameterGroup
        self.parameter_group = aws.rds.ParameterGroup("csye6225-postgres-db-parameter-group",
            family="postgres15",
            description="CSYE6225 Postgres DB parameter group",
            parameters=[
                aws.rds.ParameterGroupParameterArgs(
                    name="application_name",
                    value="postgres_db_app"
                ),
            ],
            opts=pulumi.ResourceOptions(parent=self)
        )

        self.db_subnet_group = aws.rds.SubnetGroup("db-subnet-group",
    subnet_ids=[private_subnets[0].id, private_subnets[1].id],
)

        # Create a new rds instance
        self.rds_instance = aws.rds.Instance(
            name,
            engine="postgres",
            engine_version="15.3",
            instance_class="db.t3.micro",
            allocated_storage=20,
            storage_type="gp2",
            username=username, 
            password=password,
            vpc_security_group_ids=[security_group_id],  # replace with actual VPC security group ID(s)
            db_subnet_group_name=self.db_subnet_group.name,  # replace with actual DB Subnet group name
            parameter_group_name=self.parameter_group.id,
            delete_automated_backups=True, 
            skip_final_snapshot = True,
            deletion_protection=False,
        )

# # Export the name and address of the RDS instance
# pulumi.export("dbInstanceName", rds_instance.name)
# pulumi.export("dbInstanceAddress", rds_instance.address)

# # Export the parameter group ID for use in other resources or programs
# pulumi.export("parameter_group_id", parameter_group.id)