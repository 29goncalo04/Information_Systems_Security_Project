# Relatório do Trabalho Prático de Segurança de Sistemas Informáticos

![Foto](uminho.png)

#### Trabalho realizado por:
Gonçalo Monteiro Cunha - a104003  
Gonçalo Oliveira Cruz - a104346  
Nuno Miguel Matos Ribeiro - a104177  


#### Unidade Curricular de Segurança de Sistemas Informáticos

**Ano Letivo** 2024/25  
**Data:** 03/05/2025  



## Introdução

Este projeto apresenta o desenvolvimento de um sistema de cofres pessoais e de grupo para a gestão segura de ficheiros, suportado por primitivas criptográficas e por um protocolo de comunicação estruturado.  

Na fase inicial da conexão, cliente e servidor realizam uma troca de chaves *Diffie-Hellman* autenticada por certificados *X.509*, derivando-se daí uma chave simétrica.  

Quando um utilizador adiciona um ficheiro, o conteúdo é encriptado localmente com uma chave efémera *k_file*. Esta chave é encriptada com *RSA-OAEP* para cada destinatário pretendido, convertida em *base64* e incluída num *bundle* que percorre o canal seguro.  

Todos as informações essenciais (por exemplo ações como **ADD**, **READ** ou **DELETE** e argumentos passados no terminal) são organizados em dicionários, serializados em *BSON*, para uma transmissão binária eficiente, e agrupados em *byte-streams* com uma função `mkpair`.  

No servidor, cofres individuais e de grupo são representados em ficheiros *JSON*, onde se mantêm informações como o dono, os clientes e ficheiros que pertencem ao grupo, o caminho do ficheiro encriptado do cofre pessoal, etc.. Cada operação regista entradas de *log* para assinalar transações do servidor e pode efetuar a validação dos certificados, autorizar a operação, entre outros, conforme a operação em questão.  

Existe ainda um ficheiro *JSON* de informações do servidor, o `utils.json`, para tornar mais fácil a consulta de informações e obtenção de dados.  

A combinação de *JSON* para armazenamento das informações e *BSON* para mensagens de protocolo, aliada ao uso de *ChaCha20-Poly1305* e *RSA-OAEP* para encriptação, assegura comunicações seguras e impede o acesso indevido às informações que circulam na rede e aos ficheiros.  

Os mecanismos utilizados neste projeto garantem, simultaneamente **autenticidade**, **confidencialidade** e **integridade** de todas as informações trocadas.  



## Validação dos certificados

O processo de validação de um certificado *X.509* no sistema faz-se em vários passos sucessivos, cada um a conferir um dos requisitos que garantem que o certificado é autêntico, foi emitido pela Entidade Certificadora (EC), se encontra no período de validade e tem os atributos esperados.  

Antes da validação de um certificado de um cliente ou servidor, é verificado que o certificado da EC tem o `subject` correto (campo *OU* = “SSI VAULT SERVICE” e *PSEUDONYM* = “VAULT_CA”).  

Depois, confirma-se que a assinatura contida no certificado a validar foi efetivamente gerada pela EC. Se alguém tentou forjar o certificado, a assinatura não bate certo e dá erro.  

Verifica-se ainda a validade do certificado pois, se estivermos fora da janela (antes da data de início ou depois da data de expiração), é necessário lançar um erro.  

Caso se deseje validar um certificado de servidor:  
Verifica-se *OU* = “SSI VAULT SERVICE” e *PSEUDONYM* = “VAULT_SERVER”.  

Se se estiver a validar o de um cliente:  
Verifica-se *OU* = “SSI VAULT SERVICE”, extrai-se o pseudónimo (OID 2.5.4.65) e confirma-se que começa por “VAULT_CLI” seguido de dígitos.  

Isto garante que só participam no protocolo entidades cujo certificado foi emitido para a aplicação e cuja identidade (pseudónimo) tem o formato esperado.  

Se todas as etapas acima passam sem erro, a função `valida_certificado` devolve *True*. Qualquer falha, como assinatura inválida, fora de prazo ou *subject* inesperado, faz retornar *False* e a conexão é recusada.  



## Estruturação das mensagens com *BSON*

Em toda a aplicação, o *BSON* foi consistentemente usado como formato de serialização para todas as mensagens de metadados e para qualquer estrutura mais complexa (listas, dicionários de pares, etc.) antes de serem encriptadas e enviadas. Sempre que o cliente ou o servidor precisa de enviar um conjunto de campos (metadados), esses objetos são convertidos em *BSON*, o que gera um *blob* binário compacto e mantém os tipos originais.

Depois dessa serialização em *BSON*, o *blob* é agrupado (com `mkpair`, por vezes junto de outro *blob* binário) e passado pelo *ChaCha20‑Poly1305* para encriptação *AEAD*. No destino, após desencriptação, aplica‑se `BSON.decode()` para regressar ao dicionário ou lista original. Mesmo nos casos em que o servidor devolve apenas dois blocos (por exemplo, certificado e *k_file* encriptada), usa‑se `mkpair` para agrupar e, no cliente, `unpair` para separar os dois *blobs*, portanto nenhum *JSON* é enviado diretamente pelo canal, tudo é *BSON* ou *bytes* puros dentro de pares.

Em resumo, sempre que a aplicação precisa de transformar estruturas em *bytes* antes da encriptação (sejam metadados, listas ou *bundles* de, por exemplo, chaves), utiliza *BSON* como formato padrão de serialização.



## Estabelecimento da conexão entre cliente e servidor

Neste sistema, o handshake entre cliente e servidor segue um *Station-to-Station* (STS) autenticado por certificados *X.509*, de forma a obter uma chave simétrica partilhada.  

Quer o cliente quer o servidor extraem a chave privada *RSA* e o certificado da sua própria *keystore* *PKCS12*.  

No arranque, o servidor gera um par de parâmetros *Diffie-Hellman* (DH) de 2048 bits, isto é, escolhe aleatoriamente um número primo `p` e usa uma base `g` (igual a 2) e mantém este conjunto durante toda a execução.  

A cada nova ligação, o servidor instancia um *worker* que utiliza os parâmetros `p` e `g` para gerar a chave privada *DH* e, a partir desta, a chave pública *DH*, enviando-a ao cliente, juntamente com os parâmetros. O cliente responde com a sua chave pública *DH*, assim como o seu certificado e uma assinatura digital (RSA-PSS/SHA-256) sobre o par `((chaveDH_cliente | chaveDH_servidor) | parâmetros)`, garantindo assim **autenticidade** e **integridade**. O servidor verifica o certificado do cliente (não permitindo duas ligações com o mesmo pseudónimo, pois mantém no ficheiro `active_users.json` o registo dos clientes ligados) e valida a assinatura, sendo que após isto ele próprio assina o par de chaves *DH* e envia esta assinatura e o seu certificado ao cliente.  

Após o cliente validar o certificado do servidor e a assinatura recebida, garantindo que está a falar com o servidor legítimo (pois o campo *PSEUDONYM* deve ter o valor *VAULT_SERVER*), ambas as partes derivam então a mesma chave simétrica via *HKDF* sobre o segredo *DH* partilhado e usam *ChaCha20-Poly1305* para encriptar e autenticar todas as mensagens subsequentes.  

**Persistência e Controlo de Sessões**  
O servidor permanece em funcionamento contínuo até receber um pedido de encerramento explícito. Em `active_users.json` fica registado o pseudónimo e certificado dos clientes atualmente online, sendo atualizado a cada início e término de ligação, impedindo conexões duplicadas. Em paralelo, todos os clientes que já se ligaram desde o arranque da aplicação ficam arquivados em `certificates.json`, para consulta do histórico.  

**Invocação**  
Para arrancar o servidor, usa-se o seguinte comando:  

```bash
python3 Server.py VAULT_SERVER.p12
```

e para o cliente (passando o seu ficheiro P12) executa-se, por exemplo:  

```bash
python3 Client.py VAULT_CLI1.p12
```  

Nota: Se nenhum argumento for dado ao cliente, por omissão é usado o ficheiro P12 do cliente `CLI1`.  



## Envio de pedidos ao servidor

O cliente envia todos os pedidos ao servidor através de um único padrão de agrupamento e encriptação que garante **confidencialidade** e **integridade**. 

1. **Construção dos metadados**

    Primeiro, prepara‑se um dicionário de metadados que inclui sempre o campo *action* (a operação desejada) e os argumentos necessários (por exemplo, identificadores de grupo, nomes de ficheiro ou caminhos). Esse dicionário é convertido em *BSON*, produzindo uma sequência de *bytes* que preserva os tipos e a estrutura dos valores. 

2. **Criação do *bundle* + *payload***

    De seguida, cria‑se um *payload* ao juntar, através de `mkpair`, um possível *bundle* de dados binários e os metadados serializados:
    ```python
    payload = mkpair(b"", metadados_serializados)
    ``` 
    ou
    ```python
    payload = mkpair(bundle, metadados_serializados)
    ``` 

3. **Diferentes tipos de *bundle***

   O *bundle* por vezes contém apenas o caminho do ficheiro encriptado (por exemplo na `ask_replace`):
   ```python
   bundle = mkpair(novo_path.encode(), b"")
   ```  
   Outras vezes uma ou várias chaves de ficheiro já encriptadas e codificadas em *base64* (por exemplo na `add_user_group`): 
   ```python
   bundle = mkpair(b"", k_files_serializadas)
   ```  
   Ou ainda o caminho e as chaves em simultâneo (por exemplo na `add_file_personal_vault`):
   ```python
   bundle = mkpair(novo_path.encode(), encrypted_k_file_base64.encode())
   ```  

Terminada esta fase de agrupamento, gera‑se um *nonce* de 12 *bytes* aleatórios com `os.urandom(12)` e instancia‑se *ChaCha20-Poly1305* com a chave simétrica partilhada. O método `encrypt(nonce, payload, None)` produz o texto encriptado com *tag* de autenticação (*AEAD*), protegendo tanto o conteúdo como o contexto. Em seguida, junta‑se o *nonce* e o *ciphertext* num único bloco através da `mkpair`, obtendo-se a mensagem final a enviar. Essa mensagem é devolvida pela função do cliente e transmitida ao servidor. É importante referir que todas as mensagens trocadas entre cliente e servidor encontram-se não só encriptadas com a chave secreta mas também serializadas.



## Receção de pedidos do cliente

A cada mensagem que chega do cliente, a lógica é a seguinte:  

1. **Separação do *nonce* e do *ciphertext***  
   ```python
   nonce_chan, ciphertext_msg = unpair(msg)
   ```  
   O protocolo de transporte agrupou previamente o par `(nonce | ciphertext)` usando `mkpair`. Aqui o servidor usa `unpair` para extrair o *nonce* (12 *bytes*) e o *ciphertext* (restante).

2. **Desencriptação *AEAD* (ChaCha20-Poly1305)**  
   ```python
   aead = ChaCha20Poly1305(self.secret_key)
   payload = aead.decrypt(nonce_chan, ciphertext_msg, None)
   ```  
   Usando a chave simétrica `secret_key` derivada no *STS handshake*, o servidor invoca o *decrypter* *ChaCha20-Poly1305*.

3. **Extração do *bundle* e dos metadados**  
   ```python
   bundle, metadados_serializados = unpair(payload)
   ```  
   O *payload AEAD* contém dois blocos concatenados:  
   - ***bundle*** (o caminho do ficheiro encriptado, mais a(s) chave(s) do ficheiro encriptada(s) com a pública do(s) destinatário(s));  
   - **metadados_serializados** (a descrição da ação, como **ADD**, **READ**, entre outros, e os argumentos passados no terminal).  

   Usando `unpair` de novo, separa-se o *bundle* dos metadados binários.  

4. **Desserialização dos metadados**  
   ```python
   metadados_originais = BSON(metadados_serializados).decode()
   action = metadados_originais.get("action")
   ```  
   Os metadados foram enviados em *BSON* (*Binary JSON*). Aqui a biblioteca *BSON* converte a instância *BSON* novamente num dicionário, de onde se extrai o campo *action* para saber que operação o cliente solicitou (por exemplo, **ADD**, **READ FILE**, **GROUP ADD**, etc.).  

Deste modo, cada pedido do cliente chega encriptado e autenticado, é validado automaticamente pela *AEAD* e depois transformado em parâmetros estruturados (via *BSON*) que o servidor processa de forma segura.  



## Receção das respostas vindas do servidor

O cliente lida com as respostas do servidor através de três passos fundamentais:

1. **leitura dos *bytes* do *socket***

2. **desencriptação do conteúdo usando a chave secreta partilhada**

3. **interpretação da mensagem em função do seu prefixo ou do formato dos dados**

Inicialmente, o cliente obtém o bloco de *bytes* que o servidor enviou. Esse bloco chega na forma de um par (*nonce*, *ciphertext*) que representa o valor retornado pelo *ChaCha20‑Poly1305* do servidor. A função `receive_message` divide esse par, aplica o mesmo algoritmo e chave (*secret_key*) para desencriptar e devolve os *bytes* originais (ou uma *tag* de erro, caso a autenticação falhe).

De seguida, o cliente converte esses *bytes* numa *string* com `decode()`. Esse texto resultante pode começar por “Erro” (caso o servidor tenha detetado alguma condição anómala) ou então conter um valor simples, como “Concluído”, ou ainda dados serializados que representam a informação solicitada. Para distinguir erro de sucesso, o cliente verifica `msg_string.startswith("Erro")`. Se for verdade, apresenta imediatamente a mensagem de erro ao utilizador e interrompe o fluxo subsequente.  
Quando a mensagem não começa por “Erro”, o cliente assume que o pedido foi bem‑sucedido. Se a resposta for meramente de confirmação, como um identificador de ficheiro ou a palavra “Concluído”, converte o próprio texto em *string* e mostra uma mensagem de sucesso. Se, em alternativa, o servidor devolveu conteúdo estruturado (por exemplo, uma lista de grupos ou certificados), o cliente pega nos *bytes* desencriptados (antes do `.decode()`), aplica o respetivo método de desserialização (por exemplo, `BSON(...).decode()`) para recuperar objetos como listas de pares, e só depois converte cada campo em texto com `.decode()` quando necessário.

Este padrão de ler, desencriptar, converter em *string*, detetar erros e, em caso de sucesso, desserializar ou interpretar o conteúdo repete‑se em todas as operações.



## Formato dos ficheiros *JSON*

No servidor, a gestão de cofres e acessos assenta em vários ficheiros *JSON* que funcionam como base de dados. 

**cofres_individuais.json**

O ficheiro `cofres_individuais.json` armazena, para cada cliente, o nome do seu cofre (idêntico ao nome do cliente) e, dentro desse cofre, os ficheiros que aí residem, com o respetivo nome e caminho para a versão encriptada em disco.
```json
{
    "VAULT_CLI1": {
        "file_test1": {
            "file_path": "../file_test/file_test1.txt.enc"
        }
    },
    "VAULT_CLI2": {
        "file_test3": {
            "file_path": "../file_test/file_test3.txt.enc"
        }
    }
}
```
**cofres_grupos.json**

O ficheiro `cofres_grupos.json` mantém a estrutura dos cofres de cada grupo. Cada chave é o nome do cofre de grupo e o seu valor inclui o criador do grupo, a lista de clientes aí presentes com as suas permissões (“R”, “W” ou “RW”) e o conjunto de ficheiros no grupo, onde cada ficheiro vem identificado pelo nome, pelo caminho para o ficheiro encriptado e pelo *owner* (quem adicionou o ficheiro ao grupo).
```json
{
    "grupo_VAULT_CLI1:exemplo": {
        "criador": "VAULT_CLI1",
        "clientes": {
            "VAULT_CLI1": {
                "permissions": "RW"
            },
            "VAULT_CLI2": {
                "permissions": "R"
            }
        },
        "ficheiros": {
            "file_test2": {
                "file_path": "../file_test/file_test2.txt.enc",
                "owner": "VAULT_CLI1"
            }
        }
    }
}
```
**utils.json**

Em `utils.json` concentra-se toda a informação de apoio ao sistema de controlo de acessos. Há uma lista global de todos os caminhos para ficheiros encriptados existentes, entradas que associam cada ficheiro ao cofre onde se encontra (“localização”) e aos clientes com acesso, incluindo a chave simétrica encriptada (k_file) e as permissões de cada um. Paralelamente, para cada cliente, regista-se a que ficheiros tem acesso e com que permissões, bem como a que grupos pertence e as respetivas permissões nesses grupos. Este ficheiro é fundamental para validar rapidamente acessos sem percorrer os vários cofres.
```json
{
    "file_test1": {
        "localização": "VAULT_CLI1",
        "clientes com acesso": {
            "VAULT_CLI1": {
                "permissions": "RW",
                "encrypted_k_file": "EUz5XrlfQs7K44XkfyGvkCDKX1fMY6LM42mH8ZlpSg1uPdW5WlSeuwlBmMwu/Rrzqb8gtlt0n6lapwzruPXi2wODdZjMOSCRDPePvgapsN8c4UYwqVR0/JxHegPG6sNICp1e1ATn3nJpKKwfBVaInGUdhCchynWtv1fqEsRFXjthgBRMyQrrQQ8ZcJpXvg15Yd5l1M5VA58yPU+35V9SbTNM3UA/SpF3xvvcOpXrHl2aHuZm7y0N1DEwdwxpyCXJruU2WtdxvSktI+aFLw19SFfq0U8vTB2CVGtYxZSco5xPF85wrSdp/xGLmjGdSa7GGD1L1Cd+Wdt1svhbFSNneQ=="
            }
        }
    },
    "lista de paths": [
        "../file_test/file_test1.txt.enc",
        "../file_test/file_test2.txt.enc",
        "../file_test/file_test3.txt.enc"
    ],
    "VAULT_CLI1": {
        "ficheiros a que tem acesso": {
            "file_test1": {
                "permissions": "RW"
            },
            "file_test2": {
                "permissions": "RW"
            }
        },
        "grupos a que pertence": {
            "grupo_VAULT_CLI1:exemplo": {
                "permissions": "RW"
            }
        }
    },
    "VAULT_CLI2": {
        "grupos a que pertence": {
            "grupo_VAULT_CLI1:exemplo": {
                "permissions": "R"
            }
        },
        "ficheiros a que tem acesso": {
            "file_test2": {
                "permissions": "R"
            },
            "file_test3": {
                "permissions": "RW"
            }
        }
    },
    "file_test2": {
        "localização": "grupo_VAULT_CLI1:exemplo",
        "clientes com acesso": {
            "VAULT_CLI1": {
                "permissions": "RW",
                "encrypted_k_file": "snfebiLWccGqpVDlIgCwVV2ubh8RpR2vIPLqjbCMKrcTTAvHspURtZzxfsiFB+2oBaazVEDdnvr3iOprbfmktowM20zto8CB5lRwUhp40r/OY9vnia25BNtcfGIULfLPvUXMrSAdojUdJSwFuW0OSjP1uxYYlcRYaYWR1oGQg5/9t6UKpCaIhyzxpi3ejbkqXTdIKe3ZzuONSNEOet7gLcNpc1uxgoqkYUck+3+UHKJKg4bycbhMmPsbLiRIZol3By8g4VlLH+gvo1aBY8sp+NzUwYBNVqo5Pz+BLtpI7vcqcPwwU0IrNxSmMQaXF/cRn+vIy+F5WVqDapP0RDHxGA=="
            },
            "VAULT_CLI2": {
                "permissions": "R",
                "encrypted_k_file": "m7MfRtcOWbkv6W8L/qmJhhfgsAbvHF8T0UCMhheiErW2n73gqhBGLpePCq6X9vvWtmHtVAbnYqiY7WwgZZBm973zsM7zZoe8qVrlOJz/MO1aJMyu8PNMl08vW6629wk7vAGs9y7jrgEn2FuXUL6uBKyJHK/+wXqLoDY7LxUAeD+Cdbl9csbfs4spCH0oXCVIZ0WoBnedjmWfnnKqVv6Wgf+b8VBKC2MiQXdIV5lBIUzlhcA9k3rg5VT78y5B/ntYWi2AjCilS+LR9LB0dqLkdxLSAq/jpqHpjSOHTLxac6qHQvcUdzH7EsHfQrfakLB+j0A7v0P/AlwDvyqJUtp+jg=="
            }
        }
    },
    "file_test3": {
        "localização": "VAULT_CLI2",
        "clientes com acesso": {
            "VAULT_CLI2": {
                "permissions": "RW",
                "encrypted_k_file": "Xo+88lqnoigGtzvCcdXwTEgZfYHuv/oiS04IH4WKtbFNlpX48SUunkmW6bQerodwbNp8Lr0D9FnpWfu3sUyOSlj+Btq0n/rPQjKoTlAi3LmHgrtLA9NGrYLzrmnLrSxe49Lx3beam8d1WeIt5ypKpbZZQoahGH+p33NkCKGU/KZHBjd61RGN0Z66cbqSFk/tL42SOy9+xuSa8UBKaS7fQ3KSWr1G6wUuZtN9LtO5sDiMKYwqfKt+ymrnT/5OFN3XM2oP+ccpnF6i5VNug4OquqZQlnssPtcgxJQFZ1iaQYj4AsgO4rZpUUoQRfJQNwLXKLt/6Eg+17ubRvL21KiIPA=="
            }
        }
    }
}
```
**certificates.json** e **active_users.json**

O `certificates.json` funciona como repositório de cada certificado que cada cliente foi apresentando desde o início da aplicação. Cada entrada associa o nome de um cliente ao seu certificado em formato *PEM*, permitindo ao servidor reenviar esses certificados a outros clientes quando se requerem chaves públicas para encriptar a *k_file*. O `active_users.json` lista apenas os clientes atualmente conectados, guardando o nome de cada um e o respetivo certificado. Serve para o servidor saber quem está *online* e impedir que um utilizador se conecte duas vezes em simultâneo.
```json
{
  "utilizadores": {
    "VAULT_CLI1": "-----BEGIN CERTIFICATE-----\nMIIEBDCCAuygAwIBAgIUB8hTwkFZAyDw5ErChdTjElUUAZgwDQYJKoZIhvcNAQEL\nBQAwgZsxCzAJBgNVBAYTAlBUMQ4wDAYDVQQIDAVNaW5obzEOMAwGA1UEBwwFQnJh\nZ2ExHjAcBgNVBAoMFVVuaXZlcnNpZGFkZSBkbyBNaW5obzEaMBgGA1UECwwRU1NJ\nIFZBVUxUIFNFUlZJQ0UxHTAbBgNVBAMMFFNTSSBWQVVMVCBTRVJWSUNFIENBMREw\nDwYDVQRBDAhWQVVMVF9DQTAeFw0yNTAzMjMxNTQ0MzBaFw0yNTA3MDExNTQ0MzBa\nMIGkMQswCQYDVQQGEwJQVDEOMAwGA1UECAwFTWluaG8xDjAMBgNVBAcMBUJyYWdh\nMR4wHAYDVQQKDBVVbml2ZXJzaWRhZGUgZG8gTWluaG8xGjAYBgNVBAsMEVNTSSBW\nQVVMVCBTRVJWSUNFMSQwIgYDVQQDDBtVc2VyIDEgKFNTSSBWYXVsdCBDbGllbnQg\nMSkxEzARBgNVBEEMClZBVUxUX0NMSTEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw\nggEKAoIBAQC0iYz5dPM2htUeeTZKIJewVxn9eKH3TJE3E2gbT40TH16EGNcKnRhr\n0f0cu8lzpqu4NW+E1k87K1jC9DW8UAAJR9bKQDdF0eiLHxgZghgdqxiepcNJ832g\n+NU8i58k5egm2mrPxNN/OOjqR1KR3xXVVkA3XOoQV8s40O1Dk20QwEyu+E0Erw2Z\n6SQr63W3ERolqZWenKLwPhj3ppm+mpPkOLS6p4TrhxLzrkKXt5QX35ysP0Jt86up\nvQitY2OafC4iSNytnSZ2vjO917/rGSQvcGC6nC+gzdXd9rJ+o6Vj0Y6763V2BrWC\ndE++PHX75j/vUk9EV4ONqjwWhfUS8SzNAgMBAAGjNTAzMAwGA1UdEwEB/wQCMAAw\nDgYDVR0PAQH/BAQDAgbAMBMGA1UdJQQMMAoGCCsGAQUFBwMCMA0GCSqGSIb3DQEB\nCwUAA4IBAQBkcQKmWjvyq76xxmuGYHHOzlaIa/C///elCZgf1f0sMbRhPGafK71O\nW0xXyaRrZL8w7VjI7dGYI20pYNizhAWNObxxL+9PbjmVo0jw+rcB5Z/kT8fjN3t1\nQdC0+mFCC/eKYhwCPvAIy9kgXLS5Fe0IN9XDxr2CxdQgca3Z9VP6hBec1QzPp7+z\nl9y6gfvMCLgRYwRtRyuSvn05OEQUS2lBV81WpqlIS+FF9os+4v15capImeSBUUj4\nz9bqpns5sUMw3x7bPC1UEYYYcHDUhKkQBz2zqHFsM9nHWVVZgWj3orJXqESgjvJm\n4wnPBnU7rWd6LlCtWVGCE5IW7XWyrL1i\n-----END CERTIFICATE-----\n",
    "VAULT_CLI2": "-----BEGIN CERTIFICATE-----\nMIIEBDCCAuygAwIBAgIUNmUb4l52rLtCzYczXc24Ar00JlkwDQYJKoZIhvcNAQEL\nBQAwgZsxCzAJBgNVBAYTAlBUMQ4wDAYDVQQIDAVNaW5obzEOMAwGA1UEBwwFQnJh\nZ2ExHjAcBgNVBAoMFVVuaXZlcnNpZGFkZSBkbyBNaW5obzEaMBgGA1UECwwRU1NJ\nIFZBVUxUIFNFUlZJQ0UxHTAbBgNVBAMMFFNTSSBWQVVMVCBTRVJWSUNFIENBMREw\nDwYDVQRBDAhWQVVMVF9DQTAeFw0yNTAzMjMxNTQ0MzBaFw0yNTA3MDExNTQ0MzBa\nMIGkMQswCQYDVQQGEwJQVDEOMAwGA1UECAwFTWluaG8xDjAMBgNVBAcMBUJyYWdh\nMR4wHAYDVQQKDBVVbml2ZXJzaWRhZGUgZG8gTWluaG8xGjAYBgNVBAsMEVNTSSBW\nQVVMVCBTRVJWSUNFMSQwIgYDVQQDDBtVc2VyIDIgKFNTSSBWYXVsdCBDbGllbnQg\nMikxEzARBgNVBEEMClZBVUxUX0NMSTIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw\nggEKAoIBAQDGCNievV3moMNJRypOjD0U7h7PI7/QX+imy+bVjCnqViF0Jd5Y4x6r\n2dY/jKkg6yVB0cPrsEGyxIzAw2ccsePtjMWEH3F0hkfD+jvv9fFuc17LYH4BD8zV\nVoRmuGxHKDEIVdNpS1swyhl6cGhCZguYOiv5bIHIXC5mKGGnDQOWQ2xTxURbcB/i\nIV5yTk9NjTH5hiLH9gg6/H/Q0jSCYsN0yquV/t8AuU+TBwTY3j6W9SLIk1oKb6Wj\nNipe4M5Z8JrkWEikCt64Zp9Mcdf8JwlhI241cMpXsqW3QiEadaZv8hqSfdKWgnwA\ntvvvJukvjkUonerV+vyBlxdH/x0ITbevAgMBAAGjNTAzMAwGA1UdEwEB/wQCMAAw\nDgYDVR0PAQH/BAQDAgbAMBMGA1UdJQQMMAoGCCsGAQUFBwMCMA0GCSqGSIb3DQEB\nCwUAA4IBAQAsdmDVvgG1qcBH/FhCQNOoXik85YL+Bp9KGi9hVRDT2CPs5fW/yx8N\n7rVtyq9kCpd+4lN/legpqYds1tCYJ0RZpsa4aseTmqaGJr31v2zjP6HFyKMX4J86\nriXG96plwoGV8RRhNQ4A/LF6+p7ptG/bCr90tfucyt5eczpksRqj4cUi+HXETXmA\n9DVsbl7o3ZbPle4PqxoWroqXgeWDyObV6FcviYHXG+px7/fQi/MIzih5T8IFzFVA\nLawjTskOK0sw2u9dxVRg1bODypx1zyKnWqw2UxaJJRxLU2hta5gx8KDP3RK8kCDC\nqK/kOZ4LXp+jV8b01PnI8xVtnz3ShKEO\n-----END CERTIFICATE-----\n"
  }
}
```


## Formato do ficheiro de *logs*

**logs.txt**

O servidor mantém ainda um ficheiro de texto simples chamado `logs.txt` onde regista, em ordem cronológica, todas as atividades internas e eventos de protocolo. Sempre que um cliente se conecta ou se desconecta, essa ação é anotada. Cada pedido recebido – seja, por exemplo para verificar existência de ficheiro, adicionar utilizador a grupo, enviar certificados, criar grupo ou adicionar ficheiro, etc. – é escrito imediatamente nos logs com o pseudónimo do cliente e os parâmetros do pedido. Quando o servidor envia de volta uma confirmação ou uma mensagem de erro, essa resposta também fica registada, bem como a operação interna que o servidor executou (por exemplo, “Foi adicionado o ficheiro ‘file_test2’ ao cofre do grupo…”). Deste modo o `logs.txt` oferece detalhes de auditoria, incluindo quem fez o quê, e qual foi a resposta do servidor, servindo tanto para *debug* como para validação de segurança e conformidade.

```txt
O cliente 'VAULT_CLI1' conectou-se
O cliente 'VAULT_CLI1' perguntou se o ficheiro com o path '../file_test/file_test1.txt.enc' já existe no sistema
O ficheiro com path '../file_test/file_test1.txt.enc' ainda não existe no sistema
O cliente 'VAULT_CLI1' pediu para adicionar o ficheiro com o path '../file_test/file_test1.txt.enc' ao seu cofre
Foi adicionado o ficheiro 'file_test1' ao cofre do cliente 'VAULT_CLI1'
O cliente 'VAULT_CLI1' pediu para criar o grupo com nome 'exemplo'
Foi criado o grupo 'grupo_VAULT_CLI1:exemplo' pelo cliente 'VAULT_CLI1'
O cliente 'VAULT_CLI2' conectou-se
O cliente 'VAULT_CLI1 pediu o certificado do cliente 'VAULT_CLI2'
Devolvido o certificado do cliente 'VAULT_CLI2' e as k_files encriptadas que abrem cada ficheiro do cofre do grupo ao cliente 'VAULT_CLI1'
O cliente 'VAULT_CLI1 pediu para adicionar o user 'VAULT_CLI2' ao grupo 'grupo_VAULT_CLI1:exemplo'
Foi adicionado o user 'VAULT_CLI2' ao grupo 'grupo_VAULT_CLI1:exemplo'
O cliente 'VAULT_CLI1' perguntou se o ficheiro com o path '../file_test/file_test2.txt.enc' já existe no sistema
O ficheiro com path '../file_test/file_test2.txt.enc' ainda não existe no sistema
O cliente 'VAULT_CLI1' pediu os certificados dos membros do grupo 'grupo_VAULT_CLI1:exemplo'
Devolvidos os certificados dos clientes do grupo 'grupo_VAULT_CLI1:exemplo' ao cliente 'VAULT_CLI1'
O cliente 'VAULT_CLI1' pediu para adicionar o ficheiro com o path '../file_test/file_test2.txt.enc' ao cofre do grupo 'grupo_VAULT_CLI1:exemplo'
Foi adicionado o ficheiro 'file_test2' ao cofre do grupo 'grupo_VAULT_CLI1:exemplo'
O cliente 'VAULT_CLI2' perguntou se o ficheiro com o path '../file_test/file_test3.txt.enc' já existe no sistema
O ficheiro com path '../file_test/file_test3.txt.enc' ainda não existe no sistema
O cliente 'VAULT_CLI2' pediu para adicionar o ficheiro com o path '../file_test/file_test3.txt.enc' ao seu cofre
Foi adicionado o ficheiro 'file_test3' ao cofre do cliente 'VAULT_CLI2'

```



## Funcionalidades do sistema

Na aplicação cliente, o programa principal fica à espera de uma entrada do utilizador no terminal para saber que comandos executar, funcionando num estilo de interface em linha de comandos. O utilizador pode introduzir comandos como **ADD**, **READ**, **LIST**, **SHARE**, entre outros, seguidos dos respetivos argumentos.  

Caso o utilizador introduza um comando com argumentos inválidos, em falta, ou de forma incorreta, a própria aplicação atua como manual de instruções, imprimindo uma mensagem que explica o uso correto do comando. Isto inclui normalmente o nome do comando, a ordem e o significado dos argumentos obrigatórios e opcionais, ajudando o utilizador a corrigir o erro e tentar novamente.  



### Adicionar um ficheiro  

```
add <file-path>
```

A adição de um ficheiro ao cofre pessoal de um cliente envolve duas fases distintas. Primeiro, o cliente envia um pedido de autorização (“Can Add”) e depois envia o caminho do ficheiro encriptado. O canal simétrico estabelecido pelo handshake *STS* e a encriptação autónoma de cada ficheiro com uma chave simétrica gerada aleatoriamente para cada ficheiro e sempre encriptada com a chave pública do destinatário (designada por *k_file*) garantem a segurança dos dados e impedem que o servidor aceda ao conteúdo dos ficheiros, pois cada ficheiro é desencriptado com a sua *k_file* e esta por sua vez tem de ser desencriptada com a chave privada da correspondente chave pública que encriptou a *k_file*.  

Primeiro é necessário verificar se o *file_path* indicado existe de facto na máquina. Depois o cliente constrói o caminho do ficheiro encriptado, acrescentando “.enc”, de modo a não sobrescrever o original e a distinguir conteúdos originais de encriptados. Para o servidor saber o que se pretende, cria-se um dicionário que é convertido em *BSON* e enviado para o servidor:  

```json
metadados = {
  "action":"CAN ADD PERSONAL",
  "file_path": novo_path,
  "file_name": nome
}
```

A função `can_add_personal_server` do servidor consulta então o ficheiro `utils.json` e recusa a operação se detetar duplicação (caso o *file_path* desse ficheiro que virá a ser encriptado ou o identificador que será gerado já existam na aplicação), ou responde “Concluído” caso contrário.  

Depois de receber autorização, o cliente lê o ficheiro original em memória, gera uma chave simétrica única (*k_file*) e encripta o seu conteúdo localmente com *ChaCha20-Poly1305*, escrevendo no disco o ficheiro “.enc” que contém o *nonce* e o *ciphertext* agrupados. A *k_file* é depois protegida com *RSA-OAEP/SHA-256* usando a chave pública do próprio cliente que está a pedir a adição do ficheiro e convertida em *base64* para poder ser escrita no `utils.json` do servidor. O cliente constrói então um novo bundle que inclui o caminho do ficheiro encriptado e a chave do ficheiro encriptada, prepara um objeto de metadados com a ação **ADD** e o nome do ficheiro:  

```json
metadados = {
        "action": "ADD",
        "file_name": nome
}
```

Serializa esses metadados em *BSON* e repete o processo de agrupamento e encriptação no canal *AEAD*. 
Do lado do servidor, a função `add_file_personal_vault_server` regista, no `cofres_individuais.json`, o mapeamento (por exemplo):  

```json
"VAULT_CLI1": {
        "file_test1": {
            "file_path": "../file_test/file_test1.txt.enc"
        }
    }
```

Em `add_util_informations`, atualiza o ficheiro `utils.json` para incluir o novo ficheiro com o seu `path`, a localização (o cofre onde o ficheiro foi inserido), as permissões **RW** associadas ao criador do ficheiro e a chave do ficheiro encriptada para aquele utilizador. É também adicionado ao parâmetro do cofre do criador do ficheiro (neste caso `VAULT_CLI1`) o nome do ficheiro e as permissões **RW**. Na lista de *paths* é também adicionado o caminho do ficheiro encriptado. 

```json
{
    "file_test1": {
        "localização": "VAULT_CLI1",
        "clientes com acesso": {
            "VAULT_CLI1": {
                "permissions": "RW",
                "encrypted_k_file": "PNTMORTQGaGcKoyx+EJLg1n5ePb6oadZod/qiWrYRk577KVfivFDp4cvpRI6VUQMBVuaULEyUATTVWJrZreveZnBpcr6xoiQK3usAcjSE6EHGg+ILR9EqeF1EG49e5GD4yLPI2SvHIxsE055aIzblCW0A8alJFnbaBQmErsM4RWY830z9Q59bD6cIaCjX8Nak+Iv8KBYrQ0p+e/9kvnne0uwp57LYEA53j1XGKx57Gz22feQATuT8v6tT5BMC6KpOhbBaY8dg4kD2ftfVKixY2Q9a+vKaDAFdc7NFAucb9VI7JnpBB5G38zJqoxULHsuyYX9JzXV1MbN6Hjmfk+JmA=="
            }
        }
    },
    "lista de paths": [
        "../file_test/file_test1.txt.enc"
    ],
    "VAULT_CLI1": {
        "ficheiros a que tem acesso": {
            "file_test1": {
                "permissions": "RW"
            }
        }
    }
}
```

Finalmente, o servidor envia de volta o identificador criado para o ficheiro, encriptado no mesmo canal *AEAD*, e o cliente apresenta a confirmação ao utilizador.  

*Input* no terminal (exemplo a adicionar o ficheiro `file_test1` ao cofre do cliente `VAULT_CLI1`):
```
add ../file_test/file_test1.txt
```
*Output* esperado caso a operação tenha sido concluída com sucesso:
```
O ficheiro com id 'file_test1' foi adicionado ao seu cofre.
```



### Listar ficheiros de um utilizador ou de um grupo

```
list [-u user-id | -g group-id]
```

Para obter a listagem dos ficheiros de um utilizador ou grupo, o cliente constrói um dicionário de metadados com a ação desejada (**LIST FILES USER** ou **LIST FILES GROUP**) e o identificador (*user_id* ou *group_id*), conforme o comando recebido do utilizador, e serializa os metadados em *BSON* para enviar ao servidor (sem nunca esquecer o protocolo enunciado no tópico **Envio de pedidos ao servidor**).

Para listar os ficheiros de um utilizador, o servidor executa `list_files_user_server`, e abre o ficheiro `utils.json`, que mantém, para cada utilizador, o parâmetro "ficheiros a que tem acesso":  

```json
"VAULT_CLI1": {
    "ficheiros a que tem acesso": {
        "file_test1": {
            "permissions": "RW"
        }
    }
}
```

Seguidamente, extrai a lista de `file_ids`, converte cada string para *bytes* e agrupa numa instância *BSON* com campo "ficheiros". Esse *BSON* é devolvido ao cliente, ainda encriptado com *ChaCha20-Poly1305*.  

No caso de grupo, o servidor executa `list_files_group_server` e abre o `cofres_grupos.json`:  

```json
"grupo_VAULT_CLI1:ola": {
    "criador": "VAULT_CLI1",
    "clientes": {
        "VAULT_CLI1": {
            "permissions": "RW"
        }
    },
    "ficheiros": {
        "file_test2": {
            "file_path": "../file_test/file_test2.txt.enc",
            "owner": "VAULT_CLI1"
        }
    }
}
```

A seguir, recolhe as chaves em `dados[group_id]["ficheiros"]`, converte para `byte-strings`, agrupa num *BSON* idêntico ao anterior e envia. Se, em qualquer momento, não existir informação (utilizador ou grupo desconhecido ou sem ficheiros), o servidor lança um erro e retorna uma mensagem de erro encriptada.  

Quando o cliente lê a resposta, faz novamente *AEAD-decrypt*, obtém o *BSON* (caso não seja mensagem de erro) e desserializa. Se o resultado contiver um campo "Erro", imprime-o. Caso contrário, percorre a lista em `ficheiros` e apresenta cada `file_id` ao utilizador.  

*Input* no terminal (exemplo a listar os ficheiros que o cliente `VAULT_CLI1` tem acesso):
```
list -u VAULT_CLI1
```
*Output* esperado caso a operação tenha sido concluída com sucesso:
```
O utilizador 'VAULT_CLI1' tem acesso aos ficheiros:
	file_test1
```



### Partilhar um ficheiro com um utilizador

```
share <file-id> <user-id> <permission>
```

Quando o utilizador decide partilhar um ficheiro com outro utilizador (tem de pertencer ao seu cofre pessoal), a aplicação cliente inicia uma breve operação de obtenção do certificado (do cliente que receberá o ficheiro via partilha) e da chave do ficheiro encriptada (que o servidor guarda encriptada com a chave pública do dono do ficheiro). Para isso, o cliente constrói um pequeno dicionário de metadados com a ação **GET CERTIFICATE**, o identificador do ficheiro e o identificador do utilizador destino, e serializa-o em *BSON*, sendo, após isto, enviado para o servidor (sem nunca esquecer o protocolo enunciado no tópico **Envio de pedidos ao servidor**).

No servidor, ao chegar a mensagem de **GET CERTIFICATE**, a função `send_certificate` verifica que o ficheiro existe no cofre pessoal do remetente, carrega o certificado do destinatário (a partir do `certificates.json`) e serializa-o e lê do ficheiro `utils.json` a *k_file* previamente guardada (na fase de **ADD**) e serializa-a. Este par `(certificado do destinatário | k_file encriptada em base64)` é agrupado pela `mkpair` e devolvido na resposta, novamente encriptado.  

O cliente, valida o certificado e extrai a partir dele a chave pública do destinatário e depois desencripta a *k_file* com *RSA-OAEP/SHA-256*, usando a sua chave privada. No final, possui a chave simétrica do ficheiro original, o que lhe permite criar o *payload* de partilha.  

Para partilhar, o cliente gera um novo *bundle* em que inclui apenas a *k_file* encriptada com a pública do destinatário (em *base64*). Em seguida, constrói os metadados, com a ação **SHARE FILE**, o *file_id*, *user_id* e as *permissions* (R, W ou RW), serializa em *BSON* e envia ao servidor (sem nunca esquecer o protocolo enunciado no tópico **Envio de pedidos ao servidor**).  

No servidor, a função `share_file_server` verifica que o ficheiro pertence ao cofre do remetente e que as permissões são válidas, tendo então permissão para o partilhar. Depois abre o `utils.json` e adiciona, para o *user_id* de destino na entrada em "ficheiros a que tem acesso", o *file_id* com a permissão pedida, e regista, em "clientes com acesso", o novo cliente a ter acesso, a *k_file* encriptada para aquele novo user e as respetivas permissões. Finalmente devolve “Concluído” ao cliente, que apresenta confirmação ao utilizador caso tudo tenha corrido bem.  

Apresenta-se, de seguida, um exemplo em que o `VAULT_CLI1` partilhou o `file_test1` com o `VAULT_CLI2` com permissão de leitura:  

```json
    "file_test1": {
        "localização": "VAULT_CLI1",
        "clientes com acesso": {
            "VAULT_CLI1": {
                "permissions": "RW",
                "encrypted_k_file": "LgJEO0/0b9feu8yG2k1o0qj2MPT6UsHsja8ddzZSQb0PadacpjG9tOD1wRcfpAXDWo+mlW8hcJXiJC7hNWRXmdcsNBVr0hpsA4tWxq+ccKxeWRS3qPsUpGnvwWdCxLytN0iM0gxLZ1poVZ7pqEM2KPplv8a+uKc4fmQ4cGeZhreFdBsrgqeVilf8RuUIWNNudq1iRC5BisZA++TkVX4jVOosrZCctLATT5nGXPnctlE2fnCXb3ys3wKlliy49oAEQWEgGD6YxsGNjcfJOF08ggUtp6bwbXTazu+Vf26gX2MFy+OWzHQ11dBkuTFtesngPPA9+nh4ciraC1UDEQ5DFQ=="
            },
            "VAULT_CLI2": {
                "permissions": "R",
                "encrypted_k_file": "gRuedgZOYEUYgjV7NH3JBNnbaOdWxnGpQQDlPygnEcUwzP/B3YNLFLKzUzZsLu+d8cyCF4z2+j4pN6PjQeLfdQWvISi7jEUA3Pv8i/y4GfIPwOg8j+1Chagsz5RU8yj2BGMfo2uPooY/Z7VqQToLrcO4LSeKY+Kh6wGVRkncXaC2KwGc9B3H3h9ugDXVbbW9Xp9VFZDrHHoCrSVAWTsrGmqorDYNkkto03TQF78MIH0xF2aEAj9EiuLbzG8vRse3mG42LV6/2+AeLHnHYPDxigU09f/y2XWO863GX29pVPrvwTnanu0TKToGCMG6H1pFmH0SvxpU9pb1Np2TH0yNEQ=="
            }
        }
    }


    "VAULT_CLI2": {
        "ficheiros a que tem acesso": {
            "file_test1": {
                "permissions": "R"
            }
        }
    }
```

Assim, o protocolo transmite apenas metadados e a chave de ficheiro encriptada. A proteção da *k_file* com *RSA-OAEP* assegura que só o destinatário a pode usar para desencriptar o conteúdo real do ficheiro.  

*Input* no terminal (exemplo em que o cliente `VAULT_CLI1` partilha o ficheiro `file_test1` com o cliente `VAULT_CLI2` com permissões de leitura):
```
share file_test1 VAULT_CLI2 R
```
*Output* esperado caso a operação tenha sido concluída com sucesso:
```
O ficheiro 'file_test1' foi partilhado com o utilizador 'VAULT_CLI2'.
```



### Apagar um ficheiro

```
delete <file-id>
```

Se um utilizador pretender apagar um ficheiro, o cliente começa por invocar a função `delete_file`. Dentro dessa função, constrói um dicionário de metadados com a *action* **DELETE FILE** e o *file_id*, depois serializa-o em *BSON* e envia ao servidor (sem nunca esquecer o protocolo enunciado no tópico **Envio de pedidos ao servidor**).  

Quando o servidor verifica que deve fazer um **DELETE FILE**, invoca a função `delete_file_server`. O servidor abre primeiro o ficheiro `utils.json` e, se o *file_id* não existir nesta estrutura, lança um erro que também é enviado ao cliente. Em seguida, lê o valor da localização associado ao *file_id*, sendo que esta pode começar por "grupo" (ficheiro de cofre de grupo) ou corresponder ao pseudónimo de um cliente (cofre pessoal ou partilhado).  

**Cofre de grupo**  
Se a localização começa por “grupo”, o servidor abre o ficheiro de cofres de grupo (o `cofres_grupos.json`), procura qual o grupo que realmente contém o *file_id* e verifica se o cliente que pediu a remoção é o criador do grupo ou o dono do ficheiro. Se não o for, devolve erro. Caso a condição se verifique, o servidor regista o caminho antigo para o poder remover da sua lista de *paths*, apaga a entrada do ficheiro desse grupo e atualiza o *JSON* de grupos. Depois abre o *utils.json*, elimina a entrada com o *file_id*, remove cada *path* guardado em "lista de paths" e apaga a entrada correspondente em "ficheiros a que tem acesso" de cada cliente que lá constava. Atualiza, finalmente, o ficheiro `utils.json` e envia ao cliente a resposta “Concluído” encriptada.  

**Cofre pessoal do *owner***  
Caso a localização for exatamente o pseudónimo do cliente que solicitou a remoção, o servidor abre o *JSON* dos cofres individuais (o `cofres_individuais.json`), apaga a entrada desse *file_id* para o pseudónimo do cliente e atualiza também o `utils.json`, retirando o *path* da lista, eliminando a entrada com o *file_id* e removendo a referência em "ficheiros a que tem acesso" de todos os clientes que nele apareciam. Grava ambos os ficheiros e devolve ao cliente a mensagem “Concluído”.  

**Ficheiro partilhado**  
Se o ficheiro pertence a outro utilizador (a localização é o pseudónimo de alguém diferente de quem está a fazer o pedido de remoção), o servidor abre apenas o `utils.json`, elimina a entrada em `dados_utils[file_id]["clientes com acesso"][pseudonym]` (para remover o cliente que está a fazer *delete* da lista de "clientes com acesso" do ficheiro) e também a entrada em `dados_utils[pseudonym]["ficheiros a que tem acesso"][file_id]`. Desta forma o ficheiro deixa de aparecer para aquele cliente mas mantém-se no cofre do criador e disponível para outros clientes que tenham acesso. Atualiza o `utils.json` e devolve a mensagem de sucesso ao cliente.  

*Input* no terminal (exemplo em que o cliente `VAULT_CLI1` apaga o ficheiro `file_test1`):
```
delete file_test1
```
*Output* esperado caso a operação tenha sido concluída com sucesso:
```
O ficheiro com id 'file_test1' foi apagado.
```



### Substituir o conteúdo de um ficheiro

```
replace <file-id> <file-path>
```

A fim de substituir o conteúdo de um ficheiro, a aplicação cliente começa por invocar `ask_k_file`. Esta função verifica que o novo ficheiro existe localmente (se não existir, lança um erro e interrompe), cria o nome do ficheiro encriptado que virá a gerar e constrói um dicionário de metadados com a ação **ASK K FILE**, o identificador do ficheiro e o caminho onde o novo ficheiro encriptado ficará. Após isto, serializa estes metadados em *BSON* e envia ao servidor (sem nunca esquecer o protocolo enunciado no tópico **Envio de pedidos ao servidor**).

O servidor, ao receber o pedido “ASK K FILE”, invoca a função `ask_k_file_server`, que acede ao `utils.json` e confirma que o *file_id* lá consta, que o cliente que está a pedir o *replace* tem permissão “W” ou “RW” para o ficheiro com esse identificador e que o novo caminho ainda não está em uso. Se tudo estiver em ordem, retorna ao cliente a *k_file* encriptada em formato *base64*, extraída de `dados_utils[file_id]["clientes com acesso"][pseudonym]["encrypted_k_file"]`.  

O cliente, ao receber esta resposta, extrai o conteúdo retornado (`encrypted_k_file`). Depois, com a sua chave *RSA* privada, desencripta a *encrypted_k_file*, recuperando a chave simétrica que abre o ficheiro antigo. Agora, com essa *k_file*, invoca a `ask_replace`.  
Nesta função, o cliente lê o novo ficheiro em claro, gera um *nonce* de 12 *bytes* e encripta-o com *ChaCha20-Poly1305*, recorrendo à *k_file*. Depois, escreve localmente o ficheiro encriptado e, em seguida, agrupa o *bundle*, fazendo `mkpair(novo_path.encode(), b"")`, e constrói os metadados com a ação **ASK REPLACE** e *file_id*. Serializa em *BSON* e envia essa mensagem ao servidor (sem nunca esquecer o protocolo enunciado no tópico **Envio de pedidos ao servidor**).  

O servidor, recebendo essa mensagem, chama a função `replace_file_server`. Esta lê o `utils.json` para saber onde o ficheiro está guardado (campo “localização”). Se a localização for igual ao pseudónimo do cliente, significa que o cliente é o proprietário do ficheiro, por este estar no seu cofre pessoal. O servidor então abre o `cofres_individuais.json`, recolhe o antigo `path`, substitui a entrada `dados[owner][file_id]["file_path"]` pelo novo *path*, atualiza o *JSON* de cofres individuais, reabre o `utils.json`, remove o antigo *path* da lista, adiciona o novo caminho, atualiza esse ficheiro e termina devolvendo “Concluído”.  

Se a localização indicar um cofre de grupo (começa por “grupo”), o servidor abre o ficheiro `cofres_grupos.json`, obtém o grupo que contém o *file_id*, substitui `dados[grupo]["ficheiros"][file_id]["file_path"]` pelo novo *path*, grava o ficheiro, depois reabre o `utils.json`, remove o antigo *path*, acrescenta o novo e grava-o, respondendo, no final “Concluído”.

Por fim, se a localização for o pseudónimo de outro cliente (ou seja, é um ficheiro partilhado), o servidor abre o `cofres_individuais.json` para aquele *owner*, substitui o caminho antigo pelo novo e, depois, atualiza `utils.json` da mesma forma, removendo o antigo path da lista e adicionando o novo. Como habitual, devolve “Concluído”.  

*Input* no terminal (exemplo em que o cliente `VAULT_CLI1` substitui o conteúdo do ficheiro `file_test1` pelo conteúdo do ficheiro `file_test2`):
```
replace file_test1 ../file_test/file_test2.txt
```
*Output* esperado caso a operação tenha sido concluída com sucesso:
```
O ficheiro com id 'file_test1' foi subsituído pelo ficheiro com path '../file_test/file_test2.txt'.
```



### Listar os detalhes de um ficheiro

```
details <file-id>
```

Se se pretender listar detalhes de um ficheiro, inicialmente, no cliente, a função `get_details` cria um dicionário com:  

```python
{ "action": "GET DETAILS", 
   "file_id": file_id }
```

e converte-o em *BSON*, e envia ao servidor (sem nunca esquecer o protocolo enunciado no tópico **Envio de pedidos ao servidor**).  

No servidor, a função `get_details_server` abre o ficheiro `utils.json`. Se o `file_id` não existir no mesmo, lança um erro.
Para determinar o *owner*, o servidor verifica se a localização começa por “grupo”: nesse caso lê o ficheiro `cofres_grupos.json` para extrair o campo *owner* do ficheiro; caso contrário, o *owner* é o próprio pseudónimo guardado em "localização". Em paralelo, constrói uma lista de pares `(cliente_id | permissions)` percorrendo `dados_utils[file_id]["clientes com acesso"]`. Cada par é agrupado em binário com `mkpair(cliente_id.encode(), permissions.encode())` e essa lista de pares é inserida numa instância *BSON* sob a chave "lista".  

Finalmente, o servidor monta a mensagem de resposta em três fases. Primeiro, faz `mkpair(owner.encode() | lista_ser)`, onde `lista_ser` é o `BSON` com a lista de pares. Depois faz `mkpair` com `file_id.encode()` e o par obtido para incluir também o identificador do ficheiro no início. Por fim, devolve tudo encriptado com *ChaCha20-Poly1305*. 
No cliente, após este receber e desencriptar a mensagem recebida, um `unpair` concede o `file_name` e o par seguinte. Um segundo `unpair` extrai o *owner* e o *BSON* da lista e, finalmente, `BSON(lista_ser).decode()["lista"]` devolve o *array* de pares, em que a cada elemento é novamente feito um `unpair` para obter o *user* e as suas permissões em texto. 

*Input* no terminal (exemplo em que o cliente `VAULT_CLI1` consulta os detalhes do ficheiro `file_test1` depois de o ter partilhado com o cliente `VAULT_CLI2` com permissões de escrita):
```
details file_test1
```
*Output* esperado caso a operação tenha sido concluída com sucesso:
```
Nome do ficheiro: file_test1
Criador do ficheiro: VAULT_CLI1
Quem tem acesso ao ficheiro são os clientes:
	VAULT_CLI1 com as permissões 'RW'
	VAULT_CLI2 com as permissões 'R'
```



### Revogar as permissões de um utilizador a um ficheiro

```
revoke <file-id> <user-id>
```

Para este comando, o cliente invoca o método `revoke_permissions`. Inicialmente, esta função constrói um dicionário com três campos: a ação a executar, neste caso "REVOKE PERMISSIONS", o identificador do ficheiro cujo acesso vai ser alterado e o identificador do utilizador a quem as permissões vão ser retiradas. Este dicionário é convertido em *BSON* e, depois, enviado para o servidor (sem nunca esquecer o protocolo enunciado no tópico **Envio de pedidos ao servidor**).  

No servidor, quando a mensagem chega, a função `revoke_permissions_server` abre o ficheiro `utils.json`. Verifica então se o *file_id* e o *user_id* eistem, caso contrário retorna um erro que é enviado ao cliente.  

Antes de prosseguir, o servidor impede que alguém revogue as permissões a si próprio, comparando o *pseudonym* e o *user_id* (se estes forem iguais, lança um erro). Depois, consulta em `dados_utils[file_id]["localização"]` quem é o proprietário do ficheiro. Só o dono do ficheiro pode revogar permissões, por isso, se a localização indicar um grupo, o servidor rejeita o pedido. Se a localização for a do cofre de outro utilizador (sendo, portanto, um ficheiro partilhado), também é rejeitado, porque apenas o dono original pode revogar permissões.  

Se o pedido vier do proprietário correto, o servidor verifica se o *user_id* indicado no argumento realmente tinha acesso ao ficheiro pretendido, consultando `dados_utils[file_id]["clientes com acesso"]`. Caso tenha, o servidor define as permissões desse utilizador como "" (vazio), removendo todas as *flags* de leitura e/ou escrita. Em paralelo, faz também `dados_utils[user_id]["ficheiros a que tem acesso"][file_id]["permissions"]` ser igual a "", garantindo consistência nas informações.  

Finalmente, o servidor atualiza o ficheiro `utils.json` com as informações criadas e, depois, constrói a resposta simples “Concluído”, encripta-a com *ChaCha20-Poly1305* e devolve-a ao cliente.  

*Input* no terminal (exemplo em que o cliente `VAULT_CLI1` revoga as permissões do cliente `VAULT_CLI2` relativamente ao ficheiro `file_test1`):

```
revoke file_test1 VAULT_CLI2
```

*Output* esperado caso a operação tenha sido concluída com sucesso:

```
As permissões do utilizador 'VAULT_CLI2' sobre o ficheiro 'file_test1' foram revogadas
```



### Obter o conteúdo de um ficheiro

```
read <file-id>
```

Assim que é introduzido o comando de leitura, o cliente constrói internamente uma pequena estrutura de metadados com a *action* **READ FILE**. Este objeto é convertido para um formato binário (*BSON*) e depois enviado ao servidor (sem nunca esquecer o protocolo enunciado no tópico **Envio de pedidos ao servidor**).  

Quando o servidor recebe o pedido, valida se o ficheiro existe e se o utilizador tem acesso ao mesmo e com permissão de leitura ou leitura e escrita, recorrendo ao ficheiro `utils.json`. Se alguma das verificações falhar, o servidor cria uma mensagem de erro, encripta-a e envia-a para o cliente.  
Se, por outro lado, todas as condições estiverem satisfeitas, o servidor obtém o caminho para o ficheiro encriptado (através do identificador recebido e recorrendo ao `utils.json`) e a chave do ficheiro (*k_file*) associada a esse utilizador, encriptada em *base64*. Depois, junta esses dois itens (caminho e chave encriptada), recorrendo à `mkpair`, e envia o par resultante ao cliente.  

O cliente, recebendo estes dados, separa o caminho do ficheiro encriptado e a chave encriptada. Depois, desencripta a chave simétrica usando *RSA-OAEP* com a sua chave privada, para conseguir abrir o ficheiro encriptado presente localmente no disco. Usando *ChaCha20-Poly1305* com a *k_file* obtida, é desencriptado o conteúdo do ficheiro e validado, mais uma vez, o *MAC*, para garantir **integridade**. Finalmente, o texto em claro é apresentado ao utilizador, em conjunto com o nome do ficheiro.  

*Input* no terminal (exemplo em que o cliente `VAULT_CLI1` tenta ler o ficheiro `file_test1`):
```
read file_test1
```
*Output* esperado caso a operação tenha sido concluída com sucesso:
```
File name: file_test1
Conteúdo:
	Este é o primeiro ficheiro a testar
```



### Criar um grupo

```
group create <group name>
```

Para criar um grupo, o cliente começa por definir uma pequena estrutura de metadados com duas entradas: a ação **CREATE GROUP** e o nome escolhido para o grupo. De seguida, converte-a para *BSON*, e envia ao servidor (sem nunca esquecer o protocolo enunciado no tópico **Envio de pedidos ao servidor**).  

O servidor abre o ficheiro `cofres_grupo_.json` (criando-o se ainda não existir) e constrói um identificador único, combinando “grupo”, o pseudónimo do cliente e o nome do grupo (por exemplo “grupo_VAULT_CLI1:exemplo”). Se esse identificador já existir, aborta com um erro, que é enviado ao cliente. Caso contrário, insere no *JSON* uma nova entrada em que define o criador, inicializa o dicionário de clientes com o próprio criador com permissões “RW” e deixa a lista de ficheiros vazia.  
```json
{
    "grupo_VAULT_CLI1:exemplo": {
        "criador": "VAULT_CLI1",
        "clientes": {
            "VAULT_CLI1": {
                "permissions": "RW"
            }
        },
        "ficheiros": {}
    }
}
```

Em seguida o servidor abre o `utils.json` (ou cria-o), assegura que existe uma secção para o cliente em questão e acrescenta, para esse cliente, em “grupos a que pertence”, o novo *group_id* com permissões “RW”.

```json
{
    "VAULT_CLI1": {
        "grupos a que pertence": {
            "grupo_VAULT_CLI1:exemplo": {
                "permissions": "RW"
            }
        }
    }
}
```
Finalmente, envia ao cliente o próprio *group_id*, encriptado, como confirmação. 

*Input* no terminal (exemplo em que o cliente `VAULT_CLI1` cria o grupo `exemplo`):
```
group create exemplo
```
*Output* esperado caso a operação tenha sido concluída com sucesso:
```
O grupo com id 'grupo_VAULT_CLI1:exemplo' foi criado.
```



### Apagar um grupo

```
group delete <group-id>
```

Com o objetivo de apagar um grupo, o cliente constrói internamente um dicionário de metadados com dois campos: a ação **DELETE GROUP** e o identificador do grupo que se pretende eliminar. Esse dicionário é convertido em *BSON* e enviado da mesma forma que as outras mensagens entre cliente e servidor.  

No servidor, aquando da receção da mensagem, é invocada a função `delete_group_server`. Esta abre o ficheiro de cofres de grupos (`cofres_grupos.json`), sendo sinalizado um erro se este ficheiro não existir ou estiver vazio.  

O servidor verifica então se o `group_id` se encontra no ficheiro. Se não existir, devolve um erro informativo de que o grupo não existe. Em seguida, obtém o nome do criador guardado nesse grupo e compara com o pseudónimo do cliente que fez o pedido. Apenas o criador original pode apagar o grupo, pelo que, se outro cliente o tentar fazer, obtém um erro que informa que “Não é o dono do grupo”.  

Sendo o pedido autorizado, o servidor percorre a lista de ficheiros que pertencem ao grupo e acumula todos os caminhos onde esses ficheiros encriptados estão guardados. Em simultâneo, recolhe também a lista de clientes que tinham acesso ao grupo. A seguir, remove por completo a entrada do grupo de `cofres_grupos.json` e grava o ficheiro, assegurando que o grupo deixa de existir.  

Para manter a consistência global, o servidor abre o `utils.json` e, para cada caminho de ficheiro que pertencia ao grupo, remove essa entrada da lista global de *paths*, bem como, para cada ficheiro identificado, apaga a chave desse ficheiro no dicionário, eliminando também as subentradas em "clientes com acesso". Para cada cliente que fazia parte do grupo, remove também o *group_id* da sua secção "grupos a que pertence" e as referências a esses ficheiros em "ficheiros a que tem acesso". Se qualquer destes passos falhar, lança um erro e interrompe, erro esse que o cliente recebe e imprime ao utilizador.  

No fim deste processo, o servidor envia ao cliente uma mensagem “Concluído”, encriptada no mesmo canal *AEAD*, que o cliente desencripta, apresentando uma mensagem de confirmação de que o pedido foi efetuado.  

*Input* no terminal (exemplo em que o cliente `VAULT_CLI1` apaga o grupo `grupo_VAULT_CLI1:exemplo`):

```
group delete grupo_VAULT_CLI1:exemplo
```
*Output* esperado caso a operação tenha sido concluída com sucesso:
```
O grupo com id 'grupo_VAULT_CLI1:exemplo' foi apagado.
```



### Adicionar um utilizador a um grupo

```
group add-user <group-id> <user-id> <permissions>
```

Quando o objetivo é adicionar um utilizador a um grupo, o cliente emite um pedido **GET CERTIFICATE ADD USER** para obter o certificado *X.509* desse utilizador e, em simultâneo, as *k_file* (as chaves simétricas de cada ficheiro do grupo) encriptadas previamente com a chave pública do cliente que está a invocar o comando.  

O comando traduz-se num dicionário com três campos: a ação **GET CERTIFICATE ADD USER**, o identificador do grupo e o identificador do utilizador a adicionar. Esse dicionário é convertido para *BSON* e enviado ao servidor (sem nunca esquecer o protocolo enunciado no tópico **Envio de pedidos ao servidor**).  

No servidor, ao receber esse pedido, verifica-se que o grupo existe e que quem faz o pedido é mesmo o criador (apenas o *owner* pode adicionar clientes ao grupo). Em seguida, o servidor recolhe o certificado do utilizador a adicionar, a partir do *certificates.json*, e agrupa-o com todas as *k_file* usadas pelo dono do grupo para desencriptar os ficheiros presentes no mesmo (chaves essas que estão encriptadas com a pública do cliente (no caso, o dono do grupo) e são obtidas a partir de `utils.json`). A lista destas *k_file* é serializada em *BSON* e retornada, num `mkpair` com o certificado do cliente a adicionar, ao cliente que está a efetuar o pedido.

Quando o cliente recebe o certificado e as *k_file*, valida o certificado do cliente a adicionar ao grupo, extrai a chave pública do mesmo e usa a sua própria chave privada *RSA-OAEP* para desencriptar cada *k_file*.

Após esse passo, cada uma dessas *k_file* é encriptada com a chave pública do cliente que está a ser adicionado ao grupo e é transformada em *base64*. A lista resultante de *k_file* encriptadas é serializada em *BSON*. Esse *BSON* é o *bundle* que será agrupado com o dicionário de metadados para formar o *payload*.

Internamente, o cliente prepara um dicionário de metadados com quatro campos: a ação **GROUP ADD-USER**, o identificador do grupo, o identificador do utilizador a adicionar e as permissões (“R”, “W” ou “RW”). Esse dicionário é convertido para *BSON* e enviado ao servidor (sem nunca esquecer o protocolo enunciado no tópico **Envio de pedidos ao servidor**).

Do lado do servidor, se o grupo não existir ou se as permissões não forem válidas, é devolvido imediatamente um erro. Em seguida, este verifica se o cliente que fez o pedido é efetivamente o criador do grupo e, caso não o seja, devolve um erro.

Com o proprietário validado, o servidor extrai do *bundle* o conjunto de *k_files* encriptadas para cada ficheiro já existente no grupo. O servidor insere então no cofre do grupo o novo *user_id* no dicionário `dados[group_id]["clientes"]` com as permissões indicadas e no `utils.json` altera duas estruturas: acrescenta, sob o novo utilizador, na secção “grupos a que pertence”, o identificador do grupo e as permissões corretas, e na secção "ficheiros a que tem acesso" os ficheiros que se encontram no grupo, e regista ainda, para cada ficheiro do grupo no campo “clientes com acesso”, a nova entrada (*user_id* e *permissions*), acompanhada da respetiva *k_file* encriptada em *base64*.

Por fim, o servidor envia ao cliente uma simples confirmação (“Concluído”) encriptada pelo mesmo canal *AEAD*.

*Input* no terminal (exemplo em que o cliente `VAULT_CLI1` adiciona o utilizador `VAULT_CLI2` ao grupo `grupo_VAULT_CLI1:exemplo` com permissões de escrita):

```
group add-user grupo_VAULT_CLI1:exemplo VAULT_CLI2 W
```

*Output* esperado caso a operação tenha sido concluída com sucesso:

```
O utilizador com id 'VAULT_CLI2' foi adicionado ao grupo 'grupo_VAULT_CLI1:exemplo'.
```


### Remover um utilizador de um grupo

```
group delete-user <group-id> <user-id>
```

No cliente, a fim de remover um utilizador de um grupo, a função `remove_user_group` começa por construir um dicionário de metadados com três campos: a *action* **REMOVE USER GROUP**, o identificador do grupo e o identificador do utilizador a remover. Este dicionário é depois convertido para *BSON* e é aplicado o mesmo protocolo que nas outras mensagens de envio para o servidor.

Do lado do servidor, este acede ao ficheiro `cofres_grupos.json`. Caso o grupo não exista, o utilizador indicado não pertença ao grupo ou o cliente se esteja a tentar remover a si próprio, lança um erro com a mensagem adequada. Do mesmo modo, só se o pseudónimo coincidir com o criador do grupo é que a remoção prossegue.

A remoção traduz‑se em eliminar o utilizador da lista de clientes do grupo do ficheiro *JSON* referido. De seguida, o servidor abre ainda o ficheiro `utils.json` e, para cada ficheiro associado ao grupo, retira o utilizador das listas de acesso. Remove‑se igualmente o grupo da lista de grupos do utilizador e os próprios ficheiros do seu registo de acessos. Por fim o servidor envia a confirmação ao cliente de que a remoção foi concluida, confirmação essa que o cliente imprime no terminal para o utilizador ver.

*Input* no terminal (exemplo em que o cliente `VAULT_CLI1` remove o utilizador `VAULT_CLI2` do grupo `grupo_VAULT_CLI1:exemplo`):

```
group delete-user grupo_VAULT_CLI1:exemplo VAULT_CLI2
```

*Output* esperado caso a operação tenha sido concluída com sucesso:

```
O user 'VAULT_CLI2' foi removido do grupo 'grupo_VAULT_CLI1:exemplo'.
```



### Listar grupos aos quais o utilizador pertence

```
group list
```

Se se quiser ver quais os grupos em que o utilizador está inserido e as respetivas permissões, começa-se por, no cliente, criar um dicionário de metadados que identifica unicamente a ação como sendo **GROUP LIST**. Este dicionário é convertido em *BSON* e enviado para o servidor com o mesmo protocolo utilizado até aqui. 

O servidor lê o ficheiro `utils.json` e verifica se existe informação para o pseudónimo do utilizador que está a efetuar o pedido e se nele consta a entrada “grupos a que pertence”. Se faltar qualquer dado, lança um erro apropriado. Caso contrário, percorre cada grupo associado ao pseudónimo, obtém as permissões armazenadas e constrói uma lista de pares `(grupo | permissões)`, agrupando-a de novo em *BSON*, sob um campo “lista”. Esse bloco *BSON* é então devolvido ao cliente, que o desencripta, obtendo a lista de pares `(identificador do grupo | permissões)`. Por fim, imprime em texto simples cada grupo com as respetivas permissões.

*Input* no terminal (exemplo em que o cliente `VAULT_CLI2` lista os grupos a que ele próprio pertence, após ter sido adicionado ao grupo `grupo_VAULT_CLI1:exemplo` pelo cliente `VAULT_CLI1` com permissões de escrita e criado o grupo `outro_exemplo`):

```
group list
```

*Output* esperado caso a operação tenha sido concluída com sucesso:

```
Pertence aos grupos:
	grupo_VAULT_CLI1:exemplo com as permissões 'W'
	grupo_VAULT_CLI2:outro_exemplo com as permissões 'RW'
```


### Adicionar um ficheiro a um grupo

```
group add <group-id> <file-path>
```

Por fim, para se adicionar um ficheiro a um grupo, no cliente, verifica‑se primeiro a existência do ficheiro local com caminho `file_path` e extrai‑se o nome e a extensão para construir um novo caminho com sufixo “.enc”, de modo a simular o caminho para o ficheiro futuramente encriptado, e prepara‑se um pedido **CAN ADD GROUP** em *BSON*, que segue agrupado e encriptado com *ChaCha20‑Poly1305*, antes de ser enviado para o servidor para este confirmar se o ficheiro ainda não existe no sistema.  

O servidor verifica então, a partir do ficheiro `utils.json`, se o caminho do ficheiro encriptado recebido já existe. Caso exita, lança um erro e envia-o ao cliente. Caso contrário, prossegue a execução e o cliente envia um pedido **GET CERTIFICATES** para recolher os certificados de todos os membros do grupo. O servidor confirma que o pedido vem de um membro com permissão de escrita no grupo em questão, carrega os certificados do grupo e devolve-os ao cliente, encriptados como habitual.  

O cliente, por sua vez, valida cada certificado recebido e obtém a chave pública de cada membro do grupo a partir destes. De seguida, gera uma chave simétrica única para encriptar o ficheiro, encripta o conteúdo com essa chave, recorrendo a *ChaCha20‑Poly1305*, e grava o ficheiro encriptado localmente. A chave do ficheiro é então encriptada individualmente com cada chave pública recebida no passo anterior e codificada em *base64*, sendo essas chaves serializadas em *BSON* num *bundle* que inclui o caminho do ficheiro encriptado.  

Finalmente, o cliente envia um pedido **GROUP ADD** em que o *payload* combina o *bundle* com metadados (identificador do grupo e nome do ficheiro), igualmente encriptado, e espera pela resposta do servidor.  

O servidor assegura a existência do grupo, regista o novo ficheiro no *JSON* de cofres de grupos, atualiza o `utils.json` para incluir a localização, o caminho, as permissões de cada cliente e as chaves encriptadas e devolve ao cliente o identificador do ficheiro para confirmar o sucesso da operação.

*Input* no terminal (exemplo em que o cliente `VAULT_CLI1` adiciona ao grupo `grupo_VAULT_CLI1:exemplo` o ficheiro `file_test3`):

```
group add grupo_VAULT_CLI1:exemplo ../file_test/file_test3.txt
```

*Output* esperado caso a operação tenha sido concluída com sucesso:
```
O ficheiro com id 'file_test3' foi adicionado ao cofre de grupo.
```



### Terminar a execução dos programas

```
exit
```

Existe ainda o comando `exit` que termina a execução tanto do programa cliente como do servidor.  



## Garantia dos três princípios  

Para garantir continuamente **confidencialidade**, **integridade** e **autenticidade** em todo o decorrer do programa, o sistema assenta em duas camadas de encriptação *AEAD* (*ChaCha20‑Poly1305*) e num esquema de encriptação assimétrica das chaves de ficheiro (*k_file*). 

Na fase de estabelecimento de conexão, cliente e servidor possuem uma chave simétrica (*secret_key*) que nunca circula em claro.

As informações que circulam no canal são agrupadas com um *nonce* único de 12 *bytes* e encriptadas com a *secret_key* *ChaCha20‑Poly1305*. O uso de *AEAD* assegura que, se alguma mensagem for alterada, a *tag* de autenticação não bate certo e a desencriptação falha, garantindo, assim, a **integridade** e a **autenticidade** da origem, pois só quem conhece a *secret_key* pode produzir um *ciphertext* com *tag* válida.

Quanto ao conteúdo dos ficheiros, cada ficheiro é encriptado localmente pelo cliente com uma chave simétrica única (*k_file*), também usando *ChaCha20‑Poly1305*. O caminho desse ficheiro encriptado (.enc) é enviado ao servidor, mas o servidor nunca recebe a *k_file* em claro. Em vez disso, o cliente encripta a *k_file* individualmente com as chaves públicas de cada destinatário (*RSA‑OAEP*), codifica cada resultado em *base64* e envia ao servidor.  
O servidor armazena apenas o ficheiro encriptado e as *k_file* encriptadas em *base64*, sem nunca possuir as chaves privadas correspondentes para as desencriptar.

Quando um cliente mais tarde solicita o ficheiro, o servidor devolve-lhe o *path* encriptado e a *k_file* encriptada. O cliente usa a sua chave privada para desencriptar a *k_file*, depois usa a *k_file* para desencriptar o ficheiro real, garantindo que só ele consegue aceder ao conteúdo. A **integridade** do ficheiro também se mantém pela tag *AEAD* em *ChaCha20‑Poly1305*, de modo que qualquer alteração do .enc é imediatamente detetada no momento da desencriptação.

A **confidencialidade** assegura‑se pelo duplo nível de encriptação (canal e ficheiro) e a **integridade** e **autenticidade** pelo *AEAD* em cada mensagem e ficheiro, sendo que o servidor funciona apenas como armazenador de *blobs* encriptados, sem poder aceder às chaves necessárias para ler o conteúdo dos ficheiros.



## Aspetos a melhorar

1. ***Overhead* criptográfico causado pela estratégia das *k_file***

    No desenho atual do nosso projeto, cada ficheiro é protegido por uma chave simétrica única (*k_file*), o que é uma boa prática para garantir a **confidencialidade** dos dados em repouso no servidor. Contudo, reconhecemos que a forma como fazemos a partilha dessas *k_file* se revela pouco escalável: para cada destinatário (seja um utilizador individual ou todos os membros de um grupo), encripta-se a *k_file* com chave pública deste. 

    Num contexto de partilha com 100 clientes, por exemplo, isto implicaria gerar 100 encriptações *RSA‑OAEP* distintas e enviar 100 blocos separados. Sempre que um novo membro se juntasse ao grupo, teríamos de voltar a encriptar a *k_file* para o novo conjunto.
    
    Esta abordagem funciona, mas tem uma fraqueza:  
    **Escalabilidade**: o custo de *CPU* e o tamanho da mensagem crescem linearmente com o número de destinatários.

2. **Revogar permissões a um cliente / remover um cliente de um grupo**

    Para revogar permissões e remover um utilizador de um grupo, considerámos que não é necessário gerar uma nova *k_file* para cada ficheiro. 

    No nosso modelo, as *k_file* originais (isto é, as chaves simétricas que encriptam o conteúdo dos ficheiros) encontram‑se exclusivamente armazenadas no servidor, sempre encriptadas com a chave pública de cada cliente que deve ter acesso ao ficheiro. 
    
    Os clientes nunca têm acesso direto à *k_file* em claro, apenas a recebem, mediante pedido, encriptada com a sua chave pública, o que lhes permite desencriptar localmente o ficheiro (após desencriptar a *k_file* com a sua chave privada). Assim, quando removemos um utilizador de um grupo (com `group delete-user`), basta eliminar as suas *k_file* que abriam os ficheiros a que este tinha acesso: o servidor deixa de devolver essa cópia ao utilizador revogado, bloqueando o seu acesso futuro aos ficheiros (o mesmo acontece na `revoke`). Desta forma, não é necessário voltar a encriptar o ficheiro ou gerar uma nova *k_file*, pois o ex‑membro não pode obter a *k_file* antiga a partir do servidor.

    Reconhecemos, porém, que esta abordagem não impede o utilizador revogado de ler localmente qualquer ficheiro que já tenha desencriptado anteriormente, nem protege contra a partilha não autorizada da *k_file* que já possa estar armazenada localmente, no dispositivo do utilizador.  
    Para alcançar uma revogação completa, garantindo que o utilizador removido não consiga ler os ficheiros antigos usando a *k_file* que conhecia, poderíamos adotar uma estratégia de regeneração da *k_file*: gerar uma nova *k_file* para cada ficheiro sempre que mudanças de permissão ocorram e reencriptar o ficheiro com essa chave. De seguida, enviaríamos a nova *k_file* para cada cliente ainda autorizado (encriptada com a sua chave pública). Só após receberem a nova *k_file* encriptada é que os clientes poderiam desencriptar novamente o ficheiro, assegurando que quem tenha perdido permissões não dispõe da chave adequada para aceder ao conteúdo do mesmo. 
    
    Esta abordagem, apesar de mais correta em termos de controlo de acessos indevidos aos ficheiros, também implicaria um *overhead* maior, por se ter de reenviar uma nova *k_file* para cada cliente aquando da remoção de um ficheiro ou alteração de permissões.



## Valorização da geração dos próprios certificados

Para suportar a componente da geração de certificados na nossa aplicação, seria necessário assumir o papel de uma autoridade certificadora (CA) interna. Embora esta funcionalidade não tenha sido implementada, por limitações de tempo, consideramos compreender consideravelmente bem o processo e que seria relativamente simples de integrar, usando a biblioteca *cryptography*.

O processo começaria com a geração de um certificado da CA autoassinado, que serviria como raiz de confiança para toda a aplicação. Este certificado incluiria um par de chaves assimétricas (pública e privada), sendo que a chave privada da CA seria usada exclusivamente para assinar certificados dos clientes e servidor. Depois, cada cliente (ou servidor) geraria o seu próprio par de chaves e criaria um ficheiro `CSR` (*Certificate Signing Request*) contendo a sua chave pública e informação de identificação (`OU / PSEUDONYM / CN`, etc.). Este `CSR` seria então enviado para a CA interna, que o assinaria usando a sua chave privada, emitindo assim um certificado digital válido para esse cliente ou servidor.

Todos os participantes na comunicação segura confiariam apenas nos certificados que fossem assinados por esta CA interna. Durante o processo de autenticação (por exemplo, na fase de estabelecimento da `secret_key`), cada parte validaria o certificado do outro, garantindo que foi de facto emitido por uma entidade de confiança (a CA). Esta verificação permitiria garantir a **autenticidade**.

Para finalizar, apesar de não termos implementado esta componente, compreendemos a sua importância e reconhecemos que seria uma melhoria para a segurança global do sistema. O uso de uma CA interna permitiria gerir de forma controlada todos os certificados usados na aplicação e reforçaria os princípios de **autenticidade** e **integridade**.