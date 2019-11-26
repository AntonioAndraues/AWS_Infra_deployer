import boto3
import logging
from botocore.exceptions import ClientError
import os
from time import sleep
import sys
import user
import requests
import os
import subprocess


""" 
DEFINICÃO DOS CLIENTES - regiao1
"""

ec2 = boto3.client('ec2', region_name=user.data["Region1"])
ec2_loadbalance = boto3.client('elbv2',region_name=user.data["Region1"])
autoscale = boto3.client('autoscaling', region_name=user.data["Region1"])


"""
VARIAVEIS - GERAIS:
"""
# Localizadas no aqruivo user.py


def delete_all_instances(region=user.data["Region1"]):
    ec2 = boto3.client('ec2', region_name=region)
    print("deletando instancias...")
    response = ec2.describe_instances()
    for reservation in response["Reservations"]:
        for instance in reservation["Instances"]:
            try:
                for tags in instance["Tags"]:
                    if(tags["Key"]=="Owner" and tags["Value"]==user.data["Owner"] ):
                        ec2.terminate_instances(
                            InstanceIds=[
                                instance["InstanceId"],
                            ],
                        )
                        # print("wait intance to terminate...")
                        waiter = client.get_waiter('instance_terminated')
                        waiter.wait(
                            InstanceIds=[
                                instance["InstanceId"],
                            ],
                        )
                        print("done...\n")

            except:
                # print("Não foi possivel deletar alguma intancia")
                pass
def delete_all_security_groups(region=user.data["Region1"]):
    ec2 = boto3.client('ec2', region_name=region)
    security_groups = ec2.describe_security_groups(Filters=[
            {'Name': 'tag:Owner', 'Values':[user.data["Owner"]]},
            ])
    while len(security_groups["SecurityGroups"])!=0:
        # tentativa de garantir a exclusão dos security groups
        for security_group in security_groups["SecurityGroups"]:
            for tag in security_group['Tags']:
                try:
                    if(tag["Key"]=="Owner" and tag["Value"]==user.data["Owner"]):
                        response = ec2.delete_security_group(
                            GroupId=security_group["GroupId"],
                        )
                except Exception as e:
                    # print(str(e))
                    pass
        sleep(2)
        print("Esperando dependencia para deletar security group...")
        security_groups = ec2.describe_security_groups(Filters=[
            {'Name': 'tag:Owner', 'Values':[user.data["Owner"]]},
        ])


    
def create_key_pair(name="Antoniojaj_aps", region=user.data["Region1"]):
    ec2 = boto3.client('ec2', region_name=region)
    try:
        describe_keys = ec2.describe_key_pairs()
        for key in describe_keys["KeyPairs"]:
            if key["KeyName"]==name:
                response = ec2.delete_key_pair(
                 KeyName=name,
                )

        response = ec2.create_key_pair(KeyName=name)
    except ClientError as e:
        logging.error(e)
        return None
    try:
        os.remove(name+".pem") 
    except:
        pass
    f = open(name+".pem", "w")
    f.write(response["KeyMaterial"])
    f.close()
    os.system("chmod 400 "+name+".pem")
    return name,response["KeyFingerprint"]

def create_secure_group(Name,Desc,VpcId,region=user.data["Region1"],db="0"):
    ec2 = boto3.client('ec2', region_name=region)
    try:
        security_group = ec2.create_security_group(
            Description=Desc,
            GroupName=Name,
            VpcId=VpcId
        ) 
        finalizou=0
        while finalizou != 1:
            try:
                print("esperando a criacao do security group")
                response_create = ec2.describe_security_groups(
                    GroupIds=[
                        security_group['GroupId'],
                    ],
                )
                if(len(response_create['SecurityGroups'])>0):
                    finalizou=1
                sleep(2)
            except:
                sleep(2)
                pass
        
        
        IpPermissions=[
            {
                    'FromPort': 22,
                    'IpProtocol': "tcp",
                    'IpRanges': [
                    {
                        'CidrIp': '0.0.0.0/0',
                        'Description': 'all'
                    },
                    ],
                    'ToPort': 22,
                },
                {
                    'FromPort': 5000,
                    'IpProtocol': "tcp",
                    'IpRanges': [
                    {
                        'CidrIp': '0.0.0.0/0',
                        'Description': 'all'
                    },
                    ],
                    'ToPort': 5000,
                }
        ]
        if (db == "1"):
            IpPermissions.append(
                {
                    'FromPort': 27017,
                    'IpProtocol': "tcp",
                    'IpRanges': [
                    {
                        'CidrIp': '0.0.0.0/0',
                        'Description': 'all'
                    },
                    ],
                    'ToPort': 27039,
                }
            )
        response = ec2.authorize_security_group_ingress(
            GroupName=Name,
            IpPermissions=IpPermissions,
        )
        tags = ec2.create_tags(
            Resources=[
                security_group['GroupId'],
            ],
            Tags=[
                {
                    'Key': 'Owner',
                    'Value': user.data["Owner"]
                },
            ]
        )
        return security_group["GroupId"]
    except ClientError as e:
        logging.error(e)
        print("Não foi possivel criar o security group")
        return None
def create_ec2_instance(image_id, instance_type, keypair_name, group_id,user_data,region=user.data["Region1"],instance_name="antoniojaj_aps3"):
    ec2 = boto3.client('ec2', region_name=region)
    try:
        response = ec2.run_instances(ImageId=image_id,
                                            InstanceType=instance_type,
                                            KeyName=keypair_name,
                                            MinCount=1,
                                            MaxCount=1,
                                            SecurityGroupIds=[
                                                group_id,
                                            ],
                                            UserData=user_data,
                                           
        )
        ec2.create_tags(Resources=[response['Instances'][0]["InstanceId"]], Tags=[{'Key':'Owner', 'Value':user.data["Owner"]},{'Key':'Name', 'Value':instance_name}])
        print("Esperando status running...")
        waiter = ec2.get_waiter('instance_running')
        waiter.wait(
            InstanceIds=[
                response["Instances"][0]["InstanceId"],
            ],
        )
        response= ec2.describe_instances(InstanceIds=[
        response["Instances"][0]["InstanceId"],
        ])
        
    except Exception as e:
        print(str(e))
        return None
    return response['Reservations'][0]['Instances'][0]
def create_auto_scale(group_id,image_id,vpc_id,subnet_ids,TargetGroupArn,user_data,instance_name="antoniojaj_aps3"):
    try:
        # Create launch Config
        asgLaunchConfig=autoscale.create_launch_configuration(
            LaunchConfigurationName=user.data["AutoBalance_ConfigName"],
            ImageId=image_id,
            KeyName=user.data["Chave_Nome"],
            SecurityGroups=[group_id],
            UserData=user_data,
            InstanceType=user.data["Instance_Type"],
            InstanceMonitoring={'Enabled': False },
            EbsOptimized=False,
            AssociatePublicIpAddress=True,
            
        )
        # Config of subnet_id format and wait for load balancer to be available
        s = ","
        subnet_ids = s.join(subnet_ids) 
        response= ec2_loadbalance.describe_load_balancers(
                Names=[
                    user.data["Load_Balancer_Name"],
                ]
            )
        waiter = ec2_loadbalance.get_waiter('load_balancer_available')
        waiter.wait(
            Names=[
                user.data["Load_Balancer_Name"],
            ]
        )
        # Creating auto scale group
        asGroup=autoscale.create_auto_scaling_group(
        AutoScalingGroupName=user.data["AutoScale_GroupName"],
        LaunchConfigurationName=user.data["AutoBalance_ConfigName"],
        MinSize=user.data["min_instances"],
        MaxSize=user.data["max_instances"],
        DesiredCapacity=user.data["desire_instances"],
        DefaultCooldown=120,
        HealthCheckType='EC2',
        HealthCheckGracePeriod=60,
        Tags=[{'Key':'Owner', 'Value':user.data["Owner"]},{'Key':'Name', 'Value': instance_name}],
        VPCZoneIdentifier=subnet_ids,
        )
        # response = autoscale.attach_load_balancers(
        #     AutoScalingGroupName=user.data["AutoScale_GroupName"],
        #     LoadBalancerNames=[
        #         user.data["Load_Balancer_Name"],
        #     ]
        # )
        response = autoscale.attach_load_balancer_target_groups(
            AutoScalingGroupName=user.data["AutoScale_GroupName"],
            TargetGroupARNs=[
                TargetGroupArn,
            ]
        )
        
        return asGroup
    except ClientError as e:
        logging.error(e)
        return None
def get_vpc_subnet(region=user.data["Region1"]):
    ec2 = boto3.client('ec2', region_name=region)
    try:
        vpcs = ec2.describe_vpcs(
            Filters=[
            {
                'Name' : 'isDefault',
                'Values' : [
                    'true',
                ],
            },
            ]
        )
        response = ec2.describe_subnets(
            Filters=[
                {
                    'Name': 'vpc-id',
                    'Values': [
                        vpcs["Vpcs"][0]["VpcId"],
                    ]
                },
            ]
        )
        subnet_ids=[]
        for subnet in response["Subnets"]:
            subnet_ids.append(subnet["SubnetId"])


        return vpcs["Vpcs"][0]["VpcId"],subnet_ids
        
    except Exception as e:
        print(str(e))
def create_load_balancer(subnet_ids,group_id,vpc_id):

    try:
        response = ec2_loadbalance.create_load_balancer(
        Name=user.data["Load_Balancer_Name"],
        Subnets=subnet_ids,
        SecurityGroups=[
            group_id,
        ],
        Tags=[
            {
                'Key': 'Owner',
                'Value': user.data["Owner"]
            },
        ]
        )
        response = ec2_loadbalance.create_target_group(
            Name=user.data["target_group"],
            Protocol='HTTP',
            Port=5000,
            VpcId=vpc_id,
        )


        response = ec2_loadbalance.describe_target_groups(
            Names=[
                user.data["target_group"],
            ],
        )
        response2= ec2_loadbalance.describe_load_balancers(
                Names=[
                    user.data["Load_Balancer_Name"],
                ]
            )



        listener = ec2_loadbalance.create_listener(
            LoadBalancerArn= response2["LoadBalancers"][0]["LoadBalancerArn"],
            Protocol='HTTP',
            Port=5000,
            DefaultActions=[
                {
                    'Type': 'forward',
                    'TargetGroupArn': response["TargetGroups"][0]["TargetGroupArn"]
                }
            ]
        )
        return response2["LoadBalancers"][0]["LoadBalancerArn"], response["TargetGroups"][0]["TargetGroupArn"]
    except Exception as e:
        print("format : {}".format(str(e)))

        # raise Exception
def crete_database(security_group_id):
        try:
            try:
                delete = db_client.delete_db_instance(
                    DBInstanceIdentifier=user.data["database_name"]
                )
                
                waiter = db_client.get_waiter('db_instance_deleted')
                waiter.wait(
                    DBInstanceIdentifier=user.data["database_name"]
                )
                print("Data Base Deletado")
            except Exception as e :
                print("Não foi possivel deletar db {}\n ERRO : {}".format(user.data["database_name"], str(e))) 
                pass
    
        
            database = db_client.create_db_instance(
                DBInstanceIdentifier=user.data["database_name"],
                AllocatedStorage=1,
                Engine="mysql",
                DBName=user.data["db_name"],
                DBInstanceClass="db.t2.micro",
                MasterUsername="root",
                MasterUserPassword="root1221",
                Port=1234,
                DBSecurityGroups=user.data["db_securitygroup_name"],
                VpcSecurityGroupIds=security_group_id,
            )
            waiter = client.get_waiter('db_instance_available')
            waiter.wait(
                DBInstanceIdentifier=user.data["database_name"]
            )
            print("database criado com sucesso")
            response = client.describe_db_instances(
                DBInstanceIdentifier=user.data["database_name"]
            )


            return response["DBInstances"][0]
        except Exception as e:
            print("Não foi possivel Criar db {}\n ERRO : {}".format(user.data["database_name"], str(e))) 
            # raise Exception
def create_db_security_group(db_client):
    try:
        try:
            delete = db_client.delete_db_security_group(
                DBSecurityGroupName=user.data["db_securitygroup_name"]
            )

        except Exception as e  :
            print("Não foi possivel deletar o {}  \n Erro: {}".format(user.data["db_securitygroup_name"],str(e)))
            pass
        security_group = db_client.create_db_security_group(
            DBSecurityGroupName=user.data["db_securitygroup_name"],
            DBSecurityGroupDescription="Antoniojaj-security-for-db",
            Tags=[
                {
                    'Key': 'Owner',
                    'Value': user.data["Owner"]
                },
            ]
        )
        return security_group["DBSecurityGroup"]["DBSecurityGroupArn"]
    except Exception as e:
        print("Não foi possivel criar o {}  \n Erro: {}".format(user.data["db_securitygroup_name"],str(e)))
def associate_ip_to_instance(instance_id,region=user.data["Region1"]):
    ec2 = boto3.client('ec2',region_name=region)
    try:
        address = ec2.describe_addresses(
            Filters=[
                {
                    'Name': 'tag:Owner',
                    'Values': [
                        user.data["Owner"],
                    ]
                },
            ],
        )
        for addr in address['Addresses']:
            print("deletando Elastic ip : {}".format(addr))
            response = ec2.release_address(AllocationId=addr['AllocationId'])
            print("Address deletado")            
        allocation = ec2.allocate_address(Domain='vpc')

        response = ec2.create_tags(
            Resources=[
                allocation['AllocationId'],
            ],
            Tags=[
                {
                    'Key': 'Owner',
                    'Value': user.data["Owner"]
                },
                {
                    'Key': 'Name',
                    'Value': user.data["Owner"]
                }
            ]
        )

        response = ec2.associate_address(AllocationId=allocation['AllocationId'],InstanceId=str(instance_id), AllowReassociation=True)
        ip = ec2.describe_addresses(
            AllocationIds=[
                allocation['AllocationId'],
            ],
        )

        print(ip['Addresses'][0]['PublicIp'])
        print("Reposta da associação do ip publico: {}".format(response))
        return ip['Addresses'][0]['PublicIp']
    except Exception as e:
        print("erro : {}".format(str(e)))

def delete_depencencies():
    # AUTOSCALE
    delete_auto_scale()
    
    # Loadbalancer
    delete_load_balances()

    # Target Group
    delete_target_group()

    
    

def delete_load_balances():
    try:
        loadbalancers= ec2_loadbalance.describe_load_balancers(
            Names=[
                user.data["Load_Balancer_Name"],
            ]
        )
        for loadbalancer in loadbalancers["LoadBalancers"]:
            print("loadbalancer : {}".format(loadbalancer["LoadBalancerName"]))
            delete = ec2_loadbalance.delete_load_balancer(
                LoadBalancerArn=loadbalancer["LoadBalancerArn"]
            )
        delete_loadbalancers= ec2_loadbalance.describe_load_balancers(
            Names=[
                user.data["Load_Balancer_Name"],
            ]
        )
        while len(delete_loadbalancers["LoadBalancers"])>0:
            print("deletando loadbalecer...")
            sleep(4)
        print("Load Balancer Deletado")
    except Exception as e :
        print(str(e))
        pass
def delete_auto_scale():
    try:
        
        wait_group = autoscale.describe_auto_scaling_groups(
            AutoScalingGroupNames=[user.data["AutoScale_GroupName"]],
        )

        wait_config = autoscale.describe_launch_configurations(
            LaunchConfigurationNames=[
                user.data["AutoBalance_ConfigName"]
            ]
        )
        if (len(wait_group["AutoScalingGroups"])):
            response = autoscale.delete_auto_scaling_group(
            AutoScalingGroupName=user.data["AutoScale_GroupName"],
            ForceDelete=True
            )
        if (len(wait_config["LaunchConfigurations"])):
            response2 = autoscale.delete_launch_configuration(
            LaunchConfigurationName=user.data["AutoBalance_ConfigName"]
            )
        finalizou=0
        while(finalizou!=1):
            wait_config = autoscale.describe_launch_configurations(
            LaunchConfigurationNames=[
                user.data["AutoBalance_ConfigName"]
            ]
            )
            wait_group = autoscale.describe_auto_scaling_groups(
            AutoScalingGroupNames=[user.data["AutoScale_GroupName"]],
            )
            if(len(wait_group["AutoScalingGroups"])==0 and len(wait_config["LaunchConfigurations"])==0):
                finalizou=1
            sleep(4)
            print("deletando autoscale...")
    

        print("Auto Scale deletado")
    except Exception as e:
        print(str(e))
        pass
def delete_target_group():
    try:

        response = ec2_loadbalance.describe_target_groups(
        Names=[
            user.data["target_group"],
        ],
        )
        for target in response["TargetGroups"]:
            print("deleting {}...".format(target["TargetGroupName"]))
            finalizou=0
            while finalizou !=1:
                print("esperando deletar o target group...")
                sleep(4)
                try:
                    delete_target = ec2_loadbalance.describe_target_groups(
                    Names=[
                        user.data["target_group"],
                    ],
                    )
                    response = ec2_loadbalance.delete_target_group(
                        TargetGroupArn=target["TargetGroupArn"]
                    )
                except:
                    finalizou=1
                    pass
    except Exception as e:
        print(str(e))
        pass
def configure_ingress_securitygroups(region=user.data["Region2"]):
    configure_sgs=[user.data["db_securitygroup_name"],user.data["security_web_server_db_name"],user.data["Secure_Group_Name_Gateway"]]
    IpPermissions=[
                    {
                            'FromPort': 22,
                            'IpProtocol': "tcp",
                            'IpRanges': [
                            {
                                'CidrIp': '0.0.0.0/0',
                                'Description': 'all'
                            },
                            ],
                            'ToPort': 22,
                        },
                        {
                            'FromPort': 5000,
                            'IpProtocol': "tcp",
                            'IpRanges': [
                            {
                                'CidrIp': '0.0.0.0/0',
                                'Description': 'all'
                            },
                            ],
                            'ToPort': 5000,
                        }
                ]
    ec2_resource = boto3.resource('ec2',region_name=region)
    ec2 = boto3.client('ec2',region_name=region)
    security_groups = ec2.describe_security_groups(Filters=[
            {'Name': 'tag:Owner', 'Values':[user.data["Owner"]]},
            ])
    for security_group in security_groups['SecurityGroups']:
        if(security_group['GroupName'] in configure_sgs):
            if(security_group['GroupName'] == user.data["security_web_server_db_name"]):
                sg = ec2_resource.SecurityGroup(security_group["GroupId"])
                response = sg.revoke_ingress(IpPermissions=IpPermissions)

                if(response['ResponseMetadata']['HTTPStatusCode']==200):
                    IpPermissions[1]["IpRanges"][0]["CidrIp"]=ip_publico_regiao1+"/32"
                    response = sg.authorize_ingress(IpPermissions=IpPermissions)
                    print(response)
                else:
                    response = sg.authorize_ingress(IpPermissions=IpPermissions)
                    print("Nao foi possivel configurar o acesso seguro")
                    raise Exception
            if(security_group['GroupName'] == user.data["db_securitygroup_name"]):
                sg = ec2_resource.SecurityGroup(security_group["GroupId"])
                IpPermissions.append(
                    {
                        'FromPort': 27017,
                        'IpProtocol': "tcp",
                        'IpRanges': [
                        {
                            'CidrIp': '0.0.0.0/0',
                            'Description': 'all'
                        },
                        ],
                        'ToPort': 27039,
                    }
                )
                response = sg.revoke_ingress(IpPermissions=IpPermissions)
                permition=IpPermissions.pop(1)
                if(response['ResponseMetadata']['HTTPStatusCode']==200):
                    IpPermissions[1]["IpRanges"][0]["CidrIp"]=ip_publico_regiao2+"/32"
                    response = sg.authorize_ingress(IpPermissions=IpPermissions)
                    IpPermissions.pop(1)
                    IpPermissions.append(permition)
                    print(response)
                else:
                    response = sg.authorize_ingress(IpPermissions=IpPermissions)
                    print("Nao foi possivel configurar o acesso seguro")
                    raise Exception

    # security_group = ec2_resource.SecurityGroup('id')
def wait_status_code(ip):
    print("Testando loadbalancer: \n Esperando status code 200...")
    r = requests.get(f'http://{ip}:5000/')
    while r.status_code != 200:
        print("Tentado conectar novamente :")
        sleep(5)
        r = requests.get(f'http://{ip}:5000/')
        print(f'Status code : {r.status_code}')


def get_load_balancer_dns():
    try:
        print(user.data["Load_Balancer_Name"])
        response = ec2_loadbalance.describe_load_balancers(
        Names=[
            user.data["Load_Balancer_Name"],
        ],
        )
        print(response["LoadBalancers"][0]["DNSName"])
        return response["LoadBalancers"][0]["DNSName"]
    except:
        print("wasn`t able to find loadbalancer dns! please check it manualy")
        raise Exception

def prepare_client(dns):
    try:
        f= open("dns.txt","w+")
        f.write(f'http://{dns}:5000/')
        f.close() 
        os.system("chmod +x script_export.sh")
        subprocess.call('source script_export.sh', shell=True)
        # os.system("source script_export.sh")
        subprocess.call('tarefa', shell=True)
        # os.system("tarefa")
        print(os.name)
        
    except:
        print("Problema ao tentar configurar o cliente!")
        print("Tente seguir o github")

def main_region1():
    print(ip_publico_regiao2)
    """ 
    REGIÃO 1
    """
    print("#"*50)
    print("REGIAO 1")
    print("#"*50)
    """ 
    CODE PART 
    """
    print("#"*50)
    print("Deletando instancias e security_groups e dependencias")
    print("#"*50)
    delete_all_instances()
    delete_depencencies()
    delete_all_security_groups(region=user.data["Region1"])
    print("#"*50)
    print("Criando LoadBalancer e novo security_group")
    print("#"*50)
    vpc_id, subnet_ids=get_vpc_subnet(region=user.data["Region1"]) #PEGA AS VPC_IDS DA REGIAO ASSIM COMO AS SUBNETS
    group_id = create_secure_group(Name=user.data["Secure_Group_Name"],Desc=user.data["Secure_Group_Desc"],VpcId=vpc_id) #CRIA SECURE GROUP
    group_id_gateway = create_secure_group(Name=user.data["Secure_Group_Name_Gateway"],Desc=user.data["Secure_Group_Desc"],VpcId=vpc_id) #CRIA SECURE GROUP
    LoadBalancerArn,TargetGroupArn=create_load_balancer(subnet_ids=subnet_ids,group_id=group_id,vpc_id=vpc_id) #CRIA LOADBALANCER COM TARGET_GROUP

    """
    CRIA GATEWAY COM A SEGUNDA REGIÃO
    """

    user_data_redirect_db = user.data["user_data_redirect_db"].replace("__ip_publico_regiao2__", ip_publico_regiao2)
    print("#"*50)
    print("Criando Gateway para segunda regiao")
    print("#"*50)
    name,key_id=create_key_pair("GATEWAY_KEY") 
    gateway = create_ec2_instance(image_id=user.data["Image_Id"],instance_type=user.data["Instance_Type"],keypair_name="GATEWAY_KEY",group_id=group_id_gateway,user_data=user_data_redirect_db,region=user.data["Region1"])


    ip_publico_regiao1 = associate_ip_to_instance(gateway['InstanceId'],region=user.data["Region1"])

    """
    CRIA CHAVE PRIVADA PARA ACESSO AS INSTANCIAS 
    """

    name,key_id=create_key_pair(user.data["Chave_Nome"]) 
    
    
    """ 
    CRIA AUTOSCALE GROUP  
    """
    user_data_redirect_gateway = user.data["user_data_redirect_gateway"].replace("__ip_publico_regiao1__",ip_publico_regiao1)
    print("#"*50)
    print("Criando Autoscale group")
    print("#"*50)
    group_autoscale=create_auto_scale(group_id=group_id,image_id=user.data["Image_Id"],vpc_id=vpc_id,subnet_ids=subnet_ids,TargetGroupArn=TargetGroupArn,user_data=user_data_redirect_gateway)
    return ip_publico_regiao1


   

def main_region2():
    print("#"*50)
    print("REGIAO 2")
    print("#"*50)

    """ 
    CODE PART 
    """
    print("#"*50)
    print("Deletando instancias e security_groups")
    print("#"*50)
    region1_image_id=user.data["Image_Id"]
    user.data["Image_Id"]=user.data["Image_Id_2"]
    delete_all_instances(region=user.data["Region2"])
    delete_all_security_groups(region=user.data["Region2"])
    vpc_id, subnet_ids=get_vpc_subnet(region=user.data["Region2"]) #PEGA AS VPC_IDS DA REGIAO ASSIM COMO AS SUBNETS
    print("#"*50)
    print("Criando security_groups web e db")
    print("#"*50)
    group_id_db = create_secure_group(Name=user.data["db_securitygroup_name"],Desc=user.data["Secure_Group_Desc"],VpcId=vpc_id,region=user.data["Region2"],db="1") #CRIA SECURE GROUP DB
    group_id_web = create_secure_group(Name=user.data["security_web_server_db_name"],Desc=user.data["Secure_Group_Desc"],VpcId=vpc_id,region=user.data["Region2"]) #CRIA SECURE GROUP WEB
    
    
    """
    CRIA CHAVE PRIVADA PARA ACESSO AS INSTANCIAS 
    """
    name_db,key_id=create_key_pair(user.data["chave_para_mongo"],user.data["Region2"]) 
    name_web,key_id=create_key_pair(user.data["chave_web_server"],user.data["Region2"]) 


    print("#"*50)
    print("Criando DB instance")
    print("#"*50)
    instanceDb=create_ec2_instance(image_id=user.data["Image_Id"],instance_type=user.data["Instance_Type"],keypair_name=name_db,group_id=group_id_db,user_data=user.data["user_data_db"],region=user.data["Region2"])

    public_IP_PORT = instanceDb["PublicIpAddress"] + " " + '27017'
    user_data_web_db = user.data["user_data_web_db"].replace("__public_IP_PORT__",public_IP_PORT)

    print("#"*50)
    print("Criando Web-db instance")
    print("#"*50)

    instanceWeb=create_ec2_instance(image_id=user.data["Image_Id"],instance_type=user.data["Instance_Type"],keypair_name=name_web,group_id=group_id_web,user_data=user_data_web_db,region=user.data["Region2"])
    ip_publico_regiao2 = associate_ip_to_instance(instanceWeb["InstanceId"],region=user.data["Region2"])
    # change AMI back to first
    user.data["Image_Id"]=region1_image_id
    return ip_publico_regiao2
    # instance_info = create_ec2_instance(image_id=user.data["Image_Id"],instance_type=user.data["Instance_Type"],keypair_name=user.data["Chave_Nome"], group_id=group_id,user_data=user_data)


if __name__ == "__main__":
   
    argumentos=sys.argv
    if(len(argumentos)>1):
        if(argumentos[1] == '1'):
            # debug region 
            ip_publico_regiao2='<IP_DE_TESTE>'
            ip_publico_regiao1=main_region1()
            print(ip_publico_regiao1)
        elif (argumentos[1] == '2') :
            # debug region 
            ip_publico_regiao1='<IP_DE_TESTE>'
            ip_publico_regiao2=main_region2()
            print(ip_publico_regiao2)
        elif (argumentos[1] == 'Client') :
            dns_load_balancer=get_load_balancer_dns()
            wait_status_code(dns_load_balancer)
            prepare_client(dns_load_balancer)
    else:
        print("AMBAS REGIOES")

        ip_publico_regiao2=main_region2()    
        ip_publico_regiao1=main_region1()
        print("Configuring security ingress")
        configure_ingress_securitygroups()
        dns_load_balancer=get_load_balancer_dns()
        wait_status_code(dns_load_balancer)
        prepare_client(dns_load_balancer)
        
       