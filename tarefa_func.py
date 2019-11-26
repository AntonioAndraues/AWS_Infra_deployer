import sys
import argparse
import requests
import os
ip_server = os.environ['APS_SERVER'].replace('"',"")

tarefa_end_point = ip_server+"Tarefa/"
tarefas_end_point = ip_server+"Tarefas/"


def adiciona(args):
    # filtrando e formatando
    tarefas = args[2:]
    tarefas = (" ".join(tarefas))
    tarefas = tarefas.split(", ")
    # cada tarefa sendo adicionada
    for tarefa in tarefas:
        payload = {'tarefa': tarefa, 'ativo': "1"}
        r = requests.post(tarefas_end_point, json=payload)
        if(r.status_code == 201):
            print("#"*50)
            print("Tarefa : {} \n foi adicionada com sucesso. status code: {}".format(
                tarefa, r.text))
        else:
            print("Problema ao tentar adicionar a tarefa {}. status code: {}".format(
                tarefa, r.text))


def lista():
    print("Estas são suas tarefas: \n")
    r = requests.get(tarefas_end_point)
    tarefas = r.json()
    for tarefa in tarefas:
        print(tarefa)
    print(r.text)


def busca(args):
    tarefa_id = args[2]
    r = requests.get(tarefa_end_point + tarefa_id)
    print("Essa é a tarefa com id  {} : \n {}".format(tarefa_id, r.json()))
    print(r.text)


def apaga(args):
    print("Apagando: \n")
    tarefa_id = args[2]
    response=requests.delete(tarefa_end_point+"{}".format(tarefa_id))
    print("Tarefa: {} \n".format(tarefa_id))
    print(f'Resposta :{response.text}')


def atualiza(args):
    print("atualiza")
    tarefa_id = args[2]
    nova_tarefa = {"tarefa":args[3]}
    r = requests.put(tarefa_end_point+"{}".format(tarefa_id), json=nova_tarefa)
    print("Tarefa: {} \n atualizada para : {}".format(tarefa_id, nova_tarefa))
    print(r.text)


def main():
    actions = {
        "adicionar": (lambda x: adiciona(x)),
        "listar": (lambda x: lista()),
        "buscar": (lambda x: busca(x)),
        "apagar": (lambda x: apaga(x)),
        "atualizar": (lambda x: atualiza(x))}

    if(len(sys.argv) >= 2):
        if(sys.argv[1] in actions):
            try:
                actions[sys.argv[1]](sys.argv)
            except Exception as e:
                print("Algum problema ao tentar execultar {} \n ERRO: {} ".format(
                    sys.argv[1], e))
        else:
            print("ERRO: Não foi possivel encontrar seu argumento {}\n Para verificar os comandos não coloque argumento".format(
                sys.argv[1]))

    else:
        print("""Execute 'tarefa' \nParametros: \n\
            adicionar - Funciona para adicionar as tarefas. Pode separar diferentes tafefas utilizando a virgula \n\
                exemplo : adicionar levar cachorro para passiar, tirar o lixo\n\
            listar - Lista todas as tarefas ativas\n\
            buscar - Busca tarefa ativa pelo seu id  \n\
            apagar - Desativa tarefa (logicamente)  \n\
            atualizar - Atualiza o conteudo da terefa pelo id \n\
                exemplo: atualizar 1 nao levar o cachorro""")


if __name__ == '__main__':
    main()
