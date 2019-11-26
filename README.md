# AWS Infra deployer
O projeto tem como intuito inicializar um serviço de tarefas. 

Onde temos duas regiões distintas limitando o acesso ao banco de dados.

Consiste em:

`Cliente` - Aplicação

---
### Região 1
`Load balancer` que está configurado juntamente com um `Autoscale group` para suprir possivel demanda de requests

`N` instancias com serviço web (x)

`Gateway`- redireciona o fluxo das instancias para o acesso ao banco

---
### Região 2

`Firewall/Acesso ao banco`- Filtra os requests e execulta as query caso necessario

`Banco de dados`- onde as tarefas ficam alocadas



Imagem ilustrativa: 

![image](https://p70.f4.n0.cdn.getcloudapp.com/items/rRun807R/IMG_20191126_164919.png?v=8377b41a4cd991a3c023665213f07741)


## Script para inicialização de duas regiões:
 ---

 Primeiro é necessario configurar o seu acesso a AWS.

 `AWS configure`

 Após configurar basta rodar o seguinte arquivo python3

 `env/bin/python3 app.py`

Deve demorar alguns minutos e voce ja poderá testar seu sistema e visualiza-lo no console AWS

--- 
### Caso de erro ao configurar o cliente:

Basta rodar

 `source script_export.sh`

 E testar utilizando o comando:

 `tarefa`

### Caso queira somente uma das regiões:

Vá na definição da parte do `__main__`

E basta subistituir `<IP_DE_TESTE>` pelo ip do gateway ou do firewall:

`env/bin/python3 app.py 1 `- para rodar somente a região `1`

`env/bin/python3 app.py 2 `- para rodar somente a região `2`

