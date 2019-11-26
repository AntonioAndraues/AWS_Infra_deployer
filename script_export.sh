#!/bin/bash
pathtotarefa=$(pwd)
pathtarefa="'${pathtotarefa}/tarefa'"
echo $pathtarefa
alias tarefa=$pathtarefa
APS_SERVER=$(cat dns.txt)
echo $APS_SERVER
export APS_SERVER
PASTA=$(pwd)
export PATH="$PATH:$PASTA"
