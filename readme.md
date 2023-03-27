<h1> Estrutura </h1>
Primeiramente, as variáveis para medição do pacote são definidas. Em seguida, o socket é criado para obtermos as informações do fluxo de rede a partir do protocolo Ethernet.

Na função que roda em loop, a recepção dos pacotes é feita e a função que os avalia é chamada. Após, uma lógica simples verifica o tamanho menor, maior e médio dos pacotes e depois ordena as portas mais acessados de cada classificação (udp ou tcp) através de um qsort (cmpfuncPorta). Por fim, as estatísticas são exibidas.

Dentro do método de avaliação dos pacotes (countpacote), basicamente uma variável associada ao buffer aponta para o primeiro header Ethernet, identifica o seu tipo, incrementa a variável respectiva e passa a apontar para o próximo header, a fim de seguir com o processo.

<h1> Funcionamento </h1>
Para rodar o monitor de rede, o seguinte comando deve ser colocado no terminal dentro da pasta T1_LabRedes:

` sudo ./monitor`

Nomes: Clara D'Ávila, Louise Dornelles, Sofia Arend
