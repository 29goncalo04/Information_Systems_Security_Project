import asyncio, sys
from bson import BSON
from certificados import *
from utils import *
from client_functions import *
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import load_pem_parameters



conn_port = 7777
max_msg_size = 9999


class Client:
    """ Classe que implementa a funcionalidade de um CLIENTE. """
    def __init__(self, sckt=None, private_key=None, certificado=None):
        """ Construtor da classe. """
        self.sckt = sckt
        self.msg_cnt = 0
        self.private_key = private_key
        self.certificado = certificado
        self.private_key_DH = None
        self.public_key_DH = None
        self.public_key_server = None
        self.public_key_DH_server = None
        self.secret_key = None
        
    async def process(self, reader, writer, msg=b""):
        """ Processa uma mensagem (`bytestring`) enviada pelo SERVIDOR.
            Retorna a mensagem a transmitir como resposta (`None` para
            finalizar ligação) """
        self.msg_cnt +=1
        # envia a mensagem apenas para o server saber da existência do cliente
        if self.msg_cnt == 1:
            return b'ola'
        # recebe o par (chave pública DH do server, parameters)
        elif self.msg_cnt == 2:
            self.public_key_DH_server, parameters_bytes = unpair(msg)
            parameters = load_pem_parameters(parameters_bytes)
            self.private_key_DH = parameters.generate_private_key()
            self.public_key_DH = self.private_key_DH.public_key().public_bytes(
                                encoding=serialization.Encoding.PEM, 
                                format=serialization.PublicFormat.SubjectPublicKeyInfo)
            # chave pública DH do server serializada
            public_key_DH_server_serialized, parameters_bytes = unpair(msg)
            # cria par (chave pública DH cliente, chave pública DH server)
            par_chavesDH = mkpair(self.public_key_DH, public_key_DH_server_serialized)
            # cria par (chaves DH, parameters)
            par_chavesDH_and_parameters_bytes = mkpair(par_chavesDH, parameters_bytes)
            # assina o par (chaves DH, parameters)
            signature = self.private_key.sign(
                par_chavesDH_and_parameters_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            # serializa o certificado
            certificado_bytes = self.certificado.public_bytes(
                encoding=serialization.Encoding.PEM
            )
            cert_and_signature = mkpair(certificado_bytes, signature)
            pkDH_and_cert_and_signature = mkpair(self.public_key_DH, cert_and_signature)
            return pkDH_and_cert_and_signature  # (chave DH cliente, (certificado, assinatura de ((chave DH cliente, chave DH server), parameters)))
        elif self.msg_cnt == 3:
            # recebe o certificado do server, juntamente com a assinatura do par de chaves
            certificado_server, signature_server = unpair(msg)
            # valida o certificado do server
            if valida_certificado(certificado_server, True):
                # extrai a chave pública do server
                self.public_key_server = extract_public_key(certificado_server)
                par_chavesDH = mkpair(self.public_key_DH, self.public_key_DH_server)
                # verifica a assinatura do par de chaves DH feita pelo server
                try:
                    self.public_key_server.verify(
                        signature_server,
                        par_chavesDH,
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA256()
                    )
                    # calcula a shared_key
                    shared_key = self.private_key_DH.exchange(serialization.load_pem_public_key(self.public_key_DH_server))
                    # calcula a secret_key
                    self.secret_key = HKDF(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=None,
                        info=b'handshake data',
                    ).derive(shared_key)
                    print("Conexão com o servidor estabelecida. Pode começar a invocar métodos.")
                except:
                    print("Assinatura de chaves inválida")
                    return None
            else:
                # termina a conexão se o certificado do server for inválido
                print("Certificado do server inválido")
                return None

        while True:
            new_msg = input("\nComando >  ")
            if new_msg == "exit":
                return None
            argumentos = new_msg.strip().split()

            if len(argumentos) == 0: print("Comando inválido")

            elif argumentos[0] == "add":  # add <file_path>
                if len(argumentos) == 2:
                    try:
                        encrypted_msg = can_add_personal(argumentos[1], self.secret_key)
                        writer.write(encrypted_msg)
                        await writer.drain()
                        msg = await reader.read(max_msg_size)
                        msg_decrypted = receive_message(self.secret_key, msg)
                        msg_string = msg_decrypted.decode()
                        if msg_string.startswith("Erro"):
                            print(msg_string)
                        else:
                            encrypted_msg = add_file_personal_vault(
                                argumentos[1],
                                self.secret_key,
                                extract_public_key(self.certificado.public_bytes(encoding=serialization.Encoding.PEM))
                            )
                            writer.write(encrypted_msg)
                            await writer.drain()
                            msg = await reader.read(max_msg_size)
                            msg_decrypted = receive_message(self.secret_key, msg)
                            msg_string = msg_decrypted.decode()
                            if msg_string.startswith("Erro"):
                                print(msg_string)
                            else:
                                print(f"O ficheiro com id '{msg_string}' foi adicionado ao seu cofre.") # é o file_id
                    except Exception as e:
                        print(f"Ocorreu um erro a adicionar o ficheiro: {e}")
                else:
                    print ("O uso do comando 'add' é o seguinte: add <file_path>")

            elif argumentos[0] == "list":
                if len(argumentos) > 1:
                    if argumentos [1] == "-u":
                        if len(argumentos) == 3:
                            try:
                                encrypted_msg = list_files_user(argumentos[2], self.secret_key)
                                writer.write(encrypted_msg)
                                await writer.drain()
                                msg = await reader.read(max_msg_size)
                                msg_decrypted = receive_message(self.secret_key, msg)
                                if msg_decrypted.decode().startswith("Erro"):
                                    print(msg_decrypted.decode())
                                else:
                                    print(f"O utilizador '{argumentos [2]}' tem acesso aos ficheiros:")
                                    for file in BSON(msg_decrypted).decode()["ficheiros"]:
                                        print(f"\t{file.decode()}")
                            except Exception as e:
                                print(f"Ocorreu um erro ao listar os ficheiros do utilizador: {e}")
                        else:
                            print ("O uso do comando 'list' é o seguinte: list [-u user-id | -g group-id]")
                    elif argumentos[1] == "-g":
                        if len(argumentos) == 3:
                            try:
                                encrypted_msg = list_files_group(argumentos[2], self.secret_key)
                                writer.write(encrypted_msg)
                                await writer.drain()
                                msg = await reader.read(max_msg_size)
                                msg_decrypted = receive_message(self.secret_key, msg)
                                if msg_decrypted.decode().startswith("Erro"):
                                    print(msg_decrypted.decode())
                                else:
                                    print(f"O grupo '{argumentos [2]}' contém os seguintes ficheiros:")
                                    for file in BSON(msg_decrypted).decode()["ficheiros"]:
                                        print(f"\t{file.decode()}")
                            except Exception as e:
                                print(f"Ocorreu um erro ao listar os ficheiros do grupo: {e}")
                        else:
                            print ("O uso do comando 'list' é o seguinte: list [-u user-id | -g group-id]")
                    else: print("O uso do comando 'list' é o seguinte: list [-u user-id | -g group-id]")
                else: print("O uso do comando 'list' é o seguinte: list [-u user-id | -g group-id]")

            elif argumentos[0] == "share":
                if len(argumentos) == 4:
                    try:
                        encrypted_msg = get_certificate_client(argumentos[1], argumentos[2], self.secret_key)
                        writer.write(encrypted_msg)
                        await writer.drain()
                        msg = await reader.read(max_msg_size)
                        msg_decrypted = receive_message(self.secret_key, msg)
                        try: # deu erro
                            print(msg_decrypted.decode())
                        except:
                            certificado, encrypted_k_file = unpair(msg_decrypted)
                            if not valida_certificado(certificado, False):
                                raise ValueError("Certificado inválido.")
                            public_key = extract_public_key(certificado)
                            k_file = self.private_key.decrypt(
                                base64.b64decode(encrypted_k_file),
                                padding.OAEP(
                                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                    algorithm=hashes.SHA256(),
                                    label=None
                                )
                            )

                            encrypted_msg = share_file(
                                argumentos[1],
                                argumentos[2],
                                argumentos[3],
                                self.secret_key,
                                public_key,
                                k_file
                            )
                            writer.write(encrypted_msg)
                            await writer.drain()
                            msg = await reader.read(max_msg_size)
                            msg_decrypted = receive_message(self.secret_key, msg)
                            msg_string = msg_decrypted.decode()
                            if msg_string.startswith("Erro"):
                                print(msg_string)
                            else:
                                print(f"O ficheiro '{argumentos[1]}' foi partilhado com o utilizador '{argumentos[2]}'.")
                    except Exception as e:
                        print(f"Ocorreu um erro ao partilhar o ficheiro: {e}")
                else:
                    print ("O uso do comando 'share' é o seguinte: share <file-id> <user-id> <permission>")
            
            elif argumentos[0] == "delete": 
                if len(argumentos) == 2:
                    try:
                        encrypted_msg = delete_file(argumentos[1], self.secret_key)
                        writer.write(encrypted_msg)
                        await writer.drain()
                        msg = await reader.read(max_msg_size)
                        msg_decrypted = receive_message(self.secret_key, msg)
                        msg_string = msg_decrypted.decode()
                        if msg_string.startswith("Erro"):
                            print(msg_string)
                        else:
                            print(f"O ficheiro com id '{argumentos[1]}' foi apagado.")
                    except Exception as e:
                        print(f"Ocorreu um erro ao apagar o ficheiro: {e}")
                else:
                    print ("O uso do comando 'delete' é o seguinte: delete <file-id>")
            
            elif argumentos[0] == "replace": 
                if len(argumentos) == 3:
                    try:
                        encrypted_msg = ask_k_file(argumentos[1], argumentos[2], self.secret_key)
                        writer.write(encrypted_msg)
                        await writer.drain()
                        msg = await reader.read(max_msg_size)
                        msg_decrypted = receive_message(self.secret_key, msg)
                        if msg_decrypted.decode().startswith("Erro"):
                            print(msg_decrypted.decode())
                        else:
                            k_file = self.private_key.decrypt(
                                base64.b64decode(msg_decrypted),
                                padding.OAEP(
                                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                    algorithm=hashes.SHA256(),
                                    label=None
                                )
                            )
                            encrypted_msg = ask_replace(argumentos[1], argumentos[2], k_file, self.secret_key)
                            writer.write(encrypted_msg)
                            await writer.drain()
                            msg = await reader.read(max_msg_size)
                            msg_decrypted = receive_message(self.secret_key, msg)
                            msg_string = msg_decrypted.decode()
                            if msg_string.startswith("Erro"):
                                print(msg_string)
                            else:
                                print(f"O ficheiro com id '{argumentos[1]}' foi subsituído pelo ficheiro com path '{argumentos[2]}'.")
                    except Exception as e:
                        print(f"Ocorreu um erro ao fazer replace do ficheiro: {e}")
                else:
                    print ("O uso do comando 'replace' é o seguinte: replace <file-id> <file-path>")

            elif argumentos[0] == "details": 
                if len(argumentos) == 2:
                    try:
                        encrypted_msg = get_details(argumentos[1], self.secret_key)
                        writer.write(encrypted_msg)
                        await writer.drain()
                        msg = await reader.read(max_msg_size)
                        msg_decrypted = receive_message(self.secret_key, msg)
                        if msg_decrypted.decode().startswith("Erro"):
                            print(msg_decrypted.decode())
                        else:
                            file_name, owner_and_lista_ser = unpair(msg_decrypted)
                            print(f"Nome do ficheiro: {file_name.decode()}")
                            owner, lista_ser = unpair(owner_and_lista_ser)
                            print(f"Criador do ficheiro: {owner.decode()}")
                            print("Quem tem acesso ao ficheiro são os clientes:")
                            for elem in BSON(lista_ser).decode()["lista"]:
                                user, permissoes = unpair(elem)
                                print(f"\t{user.decode()} com as permissões '{permissoes.decode()}'")
                    except Exception as e:
                        print(f"Ocorreu um erro ao obter os detalhes do ficheiro: {e}")
                else:
                    print ("O uso do comando 'details' é o seguinte: details <file-id>")
            
            elif argumentos[0] == "revoke": 
                if len(argumentos) == 3:
                    try:
                        encrypted_msg = revoke_permissions(argumentos[1], argumentos[2], self.secret_key)
                        writer.write(encrypted_msg)
                        await writer.drain()
                        msg = await reader.read(max_msg_size)
                        msg_decrypted = receive_message(self.secret_key, msg)
                        msg_string = msg_decrypted.decode()
                        if msg_string.startswith("Erro"):
                            print(msg_string)
                        else:
                            print(f"As permissões do utilizador '{argumentos[2]}' sobre o ficheiro '{argumentos[1]}' foram revogadas")
                    except Exception as e:
                        print(f"Ocorreu um erro ao revogar as permissões: {e}")
                else:
                    print ("O uso do comando 'revoke' é o seguinte: revoke <file-id> <user-id>")
            
            elif argumentos[0] == "read": 
                if len(argumentos) == 2:
                    try:
                        encrypted_msg = read_file(argumentos[1], self.secret_key)
                        writer.write(encrypted_msg)
                        await writer.drain()
                        msg = await reader.read(max_msg_size)
                        msg_decrypted = receive_message(self.secret_key, msg)
                        if msg_decrypted.decode().startswith("Erro"):
                            print(msg_decrypted.decode())
                        else:
                            encrypted_file_path, encrypted_k_file = unpair(msg_decrypted)
                            k_file = self.private_key.decrypt(
                                base64.b64decode(encrypted_k_file),
                                padding.OAEP(
                                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                    algorithm=hashes.SHA256(),
                                    label=None
                                )
                            )
                            conteudo_ficheiro_encriptado = ler_ficheiro(encrypted_file_path.decode())
                            nonce_file, ciphertext_file = unpair(conteudo_ficheiro_encriptado)
                            aead_file = ChaCha20Poly1305(k_file)
                            file = aead_file.decrypt(nonce_file, ciphertext_file, None)
                            file_str = file.decode()
                            print(f"File name: {argumentos[1]}")
                            print("Conteúdo:")
                            print(f"\t{file_str}")
                    except Exception as e:
                        print(f"Ocorreu um erro ao ler o ficheiro: {e}")
                else:
                    print ("O uso do comando 'read' é o seguinte: read <file-id>")
            
            elif argumentos[0] == "group" and len(argumentos) > 1:

                if argumentos[1] == "create":
                    if len(argumentos) == 3:
                        try:
                            encrypted_msg = create_group(argumentos[2], self.secret_key)
                            writer.write(encrypted_msg)
                            await writer.drain()
                            msg = await reader.read(max_msg_size)
                            msg_decrypted = receive_message(self.secret_key, msg)
                            msg_string = msg_decrypted.decode()
                            if msg_string.startswith("Erro"):
                                print(msg_string)
                            else:
                                print(f"O grupo com id '{msg_string}' foi criado.") # é o group_id
                        except Exception as e:
                            print(f"Ocorreu um erro a criar o grupo: {e}")
                    else:
                       print ("O uso do comando 'group create' é o seguinte: group create <group name>") 
                       
                elif argumentos[1] == "add":
                    if len(argumentos) == 4:
                        try:
                            encrypted_msg = can_add_group(argumentos[2], argumentos[3], self.secret_key)
                            writer.write(encrypted_msg)
                            await writer.drain()
                            msg = await reader.read(max_msg_size)
                            msg_decrypted = receive_message(self.secret_key, msg)
                            msg_string = msg_decrypted.decode()
                            if msg_string.startswith("Erro"):
                                print(msg_string)
                            else:
                                encrypted_msg = get_certificates_clients(argumentos[2], self.secret_key)
                                writer.write(encrypted_msg)
                                await writer.drain()
                                msg = await reader.read(max_msg_size)
                                msg_decrypted = receive_message(self.secret_key, msg)
                                try: # deu erro
                                    print(msg_decrypted.decode())
                                except:
                                    public_keys = []

                                    certificados = BSON(msg_decrypted).decode()["certificados"]
                                    for cert in certificados:
                                        if not valida_certificado(cert, False):
                                            raise ValueError("Certificado inválido.")
                                        pk = extract_public_key(cert)
                                        public_keys.append(pk)

                                    encrypted_msg = add_file_group_vault(
                                        argumentos[2],
                                        argumentos[3],
                                        self.secret_key,
                                        public_keys
                                    )
                                    writer.write(encrypted_msg)
                                    await writer.drain()
                                    msg = await reader.read(max_msg_size)
                                    msg_decrypted = receive_message(self.secret_key, msg)
                                    msg_string = msg_decrypted.decode()
                                    if msg_string.startswith("Erro"):
                                        print(msg_string)
                                    else:
                                        print(f"O ficheiro com id '{msg_string}' foi adicionado ao cofre de grupo.") # é o file_id
                            
                        except Exception as e:
                            print(f"Ocorreu um erro a adicionar um ficheiro ao grupo: {e}")
                    else:
                       print ("O uso do comando 'group add' é o seguinte: group add <group-id> <file-path>") 
                       
                elif argumentos[1] == "add-user":
                    if len(argumentos) == 5:
                        try:
                            encrypted_msg = get_certificate_client_add_user(argumentos[2], argumentos[3], self.secret_key)
                            writer.write(encrypted_msg)
                            await writer.drain()
                            msg = await reader.read(max_msg_size)
                            msg_decrypted = receive_message(self.secret_key, msg)
                            try: # deu erro
                                print(msg_decrypted.decode())
                            except:
                                certificado, encrypted_k_files_ser = unpair(msg_decrypted)
                                if not valida_certificado(certificado, False):
                                    raise ValueError("Certificado inválido.")
                                public_key = extract_public_key(certificado)
                                k_files = []
                                encrypted_k_files = BSON(encrypted_k_files_ser).decode()["keys"]
                                for encrypted_k_file in encrypted_k_files:
                                    k_file = self.private_key.decrypt(
                                        base64.b64decode(encrypted_k_file),
                                        padding.OAEP(
                                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                            algorithm=hashes.SHA256(),
                                            label=None
                                        )
                                    )
                                    k_files.append(k_file)

                                encrypted_msg = add_user_group(
                                    argumentos[2],
                                    argumentos[3],
                                    argumentos[4],
                                    self.secret_key,
                                    public_key,
                                    k_files
                                )
                                writer.write(encrypted_msg)
                                await writer.drain()
                                msg = await reader.read(max_msg_size)
                                msg_decrypted = receive_message(self.secret_key, msg)
                                msg_string = msg_decrypted.decode()
                                if msg_string.startswith("Erro"):
                                    print(msg_string)
                                else:
                                    print(f"O utilizador com id '{argumentos[3]}' foi adicionado ao grupo '{argumentos[2]}'.")
                            
                        except Exception as e:
                            print(f"Ocorreu um erro a adicionar o utilizador ao grupo: {e}")
                    else:
                       print ("O uso do comando 'group add-user' é o seguinte: group add-user <group-id> <user-id> <permissions>")
                       
                elif argumentos[1] == "delete":
                    if len(argumentos) == 3:
                        try:
                            encrypted_msg = delete_group(argumentos[2], self.secret_key)
                            writer.write(encrypted_msg)
                            await writer.drain()
                            msg = await reader.read(max_msg_size)
                            msg_decrypted = receive_message(self.secret_key, msg)
                            msg_string = msg_decrypted.decode()
                            if msg_string.startswith("Erro"):
                                print(msg_string)
                            else:
                                print(f"O grupo com id '{argumentos[2]}' foi apagado.")
                        except Exception as e:
                            print(f"Ocorreu um erro a apagar grupo: {e}")
                    else:
                       print ("O uso do comando 'group delete' é o seguinte: group delete <group-id>")
                
                elif argumentos[1] == "delete-user":
                    if len(argumentos) == 4:
                        try:
                            encrypted_msg = remove_user_group(argumentos[2], argumentos[3], self.secret_key)
                            writer.write(encrypted_msg)
                            await writer.drain()
                            msg = await reader.read(max_msg_size)
                            msg_decrypted = receive_message(self.secret_key, msg)
                            msg_string = msg_decrypted.decode()
                            if msg_string.startswith("Erro"):
                                print(msg_string)
                            else:
                                print(f"O user '{argumentos[3]}' foi removido do grupo '{argumentos[2]}'.")
                        except Exception as e:
                            print(f"Ocorreu um erro a remover o user do grupo: {e}")
                    else:
                       print ("O uso do comando 'group delete-user' é o seguinte: group delete-user <group-id> <user-id>")
                
                elif argumentos[1] == "list":
                    if len(argumentos) == 2:
                        try:
                            encrypted_msg = get_group_list(self.secret_key)
                            writer.write(encrypted_msg)
                            await writer.drain()
                            msg = await reader.read(max_msg_size)
                            msg_decrypted = receive_message(self.secret_key, msg)
                            if msg_decrypted.decode().startswith("Erro"):
                                print(msg_decrypted.decode())
                            else:
                                print("Pertence aos grupos:")
                                for elem in BSON(msg_decrypted).decode()["lista"]:
                                    group, permissoes = unpair(elem)
                                    print(f"\t{group.decode()} com as permissões '{permissoes.decode()}'")
                        except Exception as e:
                            print(f"Ocorreu um erro a listar os grupos aos quais pertence: {e}")
                    else:
                       print ("O uso do comando 'group list' é o seguinte: group list")
                else:
                    print("Comando inválido")
            else:
                print ("Comando inválido")



async def tcp_echo_client(p12_path):
    private_key, certificado, _ = get_userdata(p12_path)
    reader, writer = await asyncio.open_connection('127.0.0.1', conn_port)
    addr = writer.get_extra_info('peername')
    client = Client(sckt=addr, private_key=private_key, certificado=certificado)
    msg = await client.process(reader, writer)
    while msg:
        writer.write(msg)
        await writer.drain()
        msg = await reader.read(max_msg_size)
        if msg :
            msg = await client.process(reader, writer, msg)
        else:
            break
    writer.write(b'\n')
    print('Socket closed!')
    writer.close()



def run_client():
    if len(sys.argv) == 1:
        p12_path = "VAULT_CLI1.p12"
    elif len(sys.argv) != 2:
        print("Uso: python3 Client.py <ficheiro.p12>")
        sys.exit(1)
    else: 
        p12_path = sys.argv[1]
    loop = asyncio.get_event_loop()
    loop.run_until_complete(tcp_echo_client(p12_path))


run_client()