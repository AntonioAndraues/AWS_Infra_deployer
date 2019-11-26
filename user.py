data = {
    "Owner" : "Antoniojaj",
    # VARIAVEIS PRIMEIRA REGIÃO - 
    "Region1" :  "us-east-1",
    "Image_Id" :  "ami-04b9e92b5572fa0d1",
    "Instance_Type" : 't2.micro',
    "AutoBalance_ConfigName" : "Autobalance_antonio",
    "AutoScale_GroupName" : "AutobalanceGroup_antonio",
    "Chave_Nome" : "Teste_projeto_antonio",
    "Secure_Group_Name" : "APS",
    "Secure_Group_Name_Gateway" : "Gateway security",
    "Secure_Group_Desc" : "APS3-antonio",
    "Load_Balancer_Name" : "ProjetoAntonio",
    "target_group" : "ProjetoAntonioTargetGroup",
    "min_instances" : 1,
    "max_instances" : 3,
    "desire_instances" : 2,
    # VARIAVEIS SEGUNDA REGIÃO - RDS e Server config
    "Region2" :  "us-east-2",
    "Image_Id_2" :  "ami-0d5d9d301c853a04a",
    "security_web_server_db_name" : "Antonio_web_serve_to_db",
    "database_name"  :  "Antonio_RDS",
    "db_name" : "Mysql-db",
    "db_securitygroup_name" :  "RDS_security",
    "chave_para_mongo" : "chave_mongo_db",
    "chave_web_server" : "chave_web_server",
    "user_data_db" : '''#!/bin/bash
apt-get update
apt-get upgrade
apt install python3-pip -y
echo "deb [ arch=amd64 ] https://repo.mongodb.org/apt/ubuntu bionic/mongodb-org/4.2 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-4.2.list
sudo apt-get update
sudo apt-get install -y mongodb-org
apt install python3-pip -y
pip3 install flask
pip3 install pymongo
mkdir data
mkdir data/db
apt install mongodb-server-core -y
mongod --bind_ip_all''',
    "user_data_redirect_db" : '''#!/bin/bash
apt-get update
apt-get upgrade
apt install python3-pip -y
pip3 install flask
pip3 install requests 
git clone https://github.com/AntonioAndraues/redirect_catch_all.git
cd redirect_catch_all
python3 app.py __ip_publico_regiao2__''',
    "user_data_redirect_gateway" : '''#!/bin/bash
apt-get update
apt-get upgrade
apt install python3-pip -y
pip3 install flask
pip3 install requests 
git clone https://github.com/AntonioAndraues/redirect_catch_all.git
cd redirect_catch_all
python3 app.py __ip_publico_regiao1__''',
    "user_data_web_db" : '''#!/bin/bash
apt-get update
apt-get upgrade
apt install python3-pip -y
pip3 install flask
pip3 install flask_restful
pip3 install pymongo 
git clone https://github.com/AntonioAndraues/Cloud-web-server-mongodb
cd Cloud-web-server-mongodb
python3 app.py __public_IP_PORT__'''
}