from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from bson import BSON
from utils import *
from ficheiro import *
import os



COFRES_INDIVIDUAIS = "../JSONS_Server/cofres_individuais.json"
COFRES_GRUPOS = "../JSONS_Server/cofres_grupos.json"
UTILS = "../JSONS_Server/utils.json"



def send_message(secret_key, mensagem):
    nonce = os.urandom(12)
    chacha = ChaCha20Poly1305(secret_key)
    ciphertext = chacha.encrypt(nonce, mensagem, None)
    encrypted_msg = mkpair(nonce, ciphertext)
    return encrypted_msg



def can_add_personal_server(metadados, pseudonym):
    file_path = metadados.get("file_path")
    nome = metadados.get("file_name")
    escrever_ficheiro_logs(f"O cliente '{pseudonym}' perguntou se o ficheiro com o path '{file_path}' já existe no sistema")
    try:
        with open(UTILS, 'r', encoding='utf-8') as f:
            dados_utils = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        dados_utils = {}
    if "lista de paths" in dados_utils:
        if (file_path in dados_utils["lista de paths"]) or (nome in dados_utils):
            raise ValueError(f"Erro: O ficheiro já existe.")
    


def can_add_group_server(metadados, pseudonym):
    file_path = metadados.get("file_path")
    nome = metadados.get("file_name")
    grupo = metadados.get("grupo")
    escrever_ficheiro_logs(f"O cliente '{pseudonym}' perguntou se o ficheiro com o path '{file_path}' já existe no sistema")
    try:
        with open(UTILS, 'r', encoding='utf-8') as f:
            dados_utils = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        dados_utils = {}
    if "lista de paths" in dados_utils:
        if (file_path in dados_utils["lista de paths"]) or (nome in dados_utils):
            raise ValueError(f"Erro: O ficheiro já existe.")
    


def add_file_personal_vault_server(metadados, bundle, pseudonym):
    file_path_bytes, _ = unpair(bundle)
    file_path = file_path_bytes.decode()
    escrever_ficheiro_logs(f"O cliente '{pseudonym}' pediu para adicionar o ficheiro com o path '{file_path}' ao seu cofre")
    file_id = metadados.get("file_name")
    # Verifica se o ficheiro já existe
    try:
        with open(COFRES_INDIVIDUAIS, 'r', encoding='utf-8') as f:
            dados = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        dados = {}

    # Garante que o cofre existe
    if pseudonym not in dados:
        dados[pseudonym] = {}

    if file_id in dados[pseudonym]:
        raise ValueError(f"Erro: O ficheiro '{file_id}' já existe no cofre do utilizador '{pseudonym}'.")

    # Adiciona ou atualiza o ficheiro no cofre
    dados[pseudonym][file_id] = {
        "file_path": file_path,
    }

    # Guarda novamente o ficheiro
    with open(COFRES_INDIVIDUAIS, 'w', encoding='utf-8') as f:
        json.dump(dados, f, ensure_ascii=False, indent=4)
    return file_id, file_path



def create_group_server(metadados, pseudonym):
    group_name = metadados.get("group_name")
    group_id = f"grupo_{pseudonym}:{group_name}"
    escrever_ficheiro_logs(f"O cliente '{pseudonym}' pediu para criar o grupo com nome '{group_name}'")
    try:
        with open(COFRES_GRUPOS, 'r', encoding='utf-8') as f:
            dados = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        dados = {}

    if group_id in dados:
        raise ValueError(f"Erro: O grupo '{group_name}' já existe.")

    dados[group_id] = {
        "criador": pseudonym,
        "clientes": {
            pseudonym: {
                "permissions": "RW"
            }
        },
        "ficheiros": {}
    }

    with open(COFRES_GRUPOS, 'w', encoding='utf-8') as f:
        json.dump(dados, f, ensure_ascii=False, indent=4)

    try:
        with open(UTILS, 'r', encoding='utf-8') as f:
            dados_utils = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        dados_utils = {}
    if pseudonym not in dados_utils:
        dados_utils[pseudonym] = {}
    if "grupos a que pertence" not in dados_utils[pseudonym]:
        dados_utils[pseudonym]["grupos a que pertence"] = {}
    dados_utils[pseudonym]["grupos a que pertence"][group_id] = {
        "permissions": "RW"
    }
    with open(UTILS, 'w', encoding='utf-8') as f:
        json.dump(dados_utils, f, ensure_ascii=False, indent=4)

    return group_id



def add_util_informations(bundle, pseudonym, file_id, file_path):
    _, encrypted_k_file = unpair(bundle)
    try:
        with open(UTILS, 'r', encoding='utf-8') as f:
            dados = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        dados = {}

    if file_id not in dados:
        dados[file_id] = {}
    if "localização" not in dados[file_id]:
        dados[file_id]["localização"] = {}
    if "lista de paths" not in dados:
        dados["lista de paths"] = []
    if "clientes com acesso" not in dados[file_id]:
        dados[file_id]["clientes com acesso"] = {}
    if pseudonym not in dados:
        dados[pseudonym] = {}
    if "ficheiros a que tem acesso" not in dados[pseudonym]:
        dados[pseudonym]["ficheiros a que tem acesso"] = {}

    dados[file_id]["localização"] = pseudonym
    dados["lista de paths"].append(file_path)
    dados[file_id]["clientes com acesso"][pseudonym] = {
        "permissions": "RW",
        "encrypted_k_file": encrypted_k_file.decode()
    }
    dados[pseudonym]["ficheiros a que tem acesso"][file_id] = {
        "permissions": "RW"
    }
    
    with open(UTILS, 'w', encoding='utf-8') as f:
        json.dump(dados, f, ensure_ascii=False, indent=4)



def send_certificates(metadados, pseudonym):
    group_id = metadados.get("group_id")
    escrever_ficheiro_logs(f"O cliente '{pseudonym}' pediu os certificados dos membros do grupo '{group_id}'")
    try:
        with open(COFRES_GRUPOS, 'r', encoding='utf-8') as f:
            dados = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        raise ValueError("Erro: Não foi possível obter os certificados dos membros do grupo")
    if group_id not in dados:
        raise ValueError(f"Erro: O grupo '{group_id}' não existe.")
    if pseudonym not in dados[group_id]["clientes"]:
        raise ValueError(f"Erro: O cliente '{pseudonym}' não faz parte do grupo '{group_id}'")
    permissions = dados[group_id]["clientes"][pseudonym]["permissions"]
    if "W" in permissions:
        certificados = []
        clients_and_certificates = load_certificates()
        clientes = list(dados[group_id]["clientes"].keys())
        for cli in clientes:
            certificados.append(clients_and_certificates[cli].encode())
        certificates = BSON.encode({"certificados": certificados})
        escrever_ficheiro_logs(f"Devolvidos os certificados dos clientes do grupo '{group_id}' ao cliente '{pseudonym}'")
        return certificates
    else:
        raise ValueError(f"Erro: Não possui permissões de escrita nesse grupo.")
    


def add_file_group_vault_server(metadados, bundle, pseudonym):
    group_id = metadados.get("group_id")
    try:
        with open(COFRES_GRUPOS, 'r', encoding='utf-8') as f:
            dados = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        raise ValueError("Erro: Não foi possível obter o cofre do grupo")
    if group_id not in dados:
        raise ValueError(f"Erro: O grupo '{group_id}' não existe.")
    permissions = dados[group_id]["clientes"][pseudonym]["permissions"]
    if "W" in permissions:
        file_path_bytes, encrypted_k_files_bytes = unpair(bundle)
        encrypted_k_files = BSON(encrypted_k_files_bytes).decode()["encrypted_k_files"]
        file_path = file_path_bytes.decode()
        escrever_ficheiro_logs(f"O cliente '{pseudonym}' pediu para adicionar o ficheiro com o path '{file_path}' ao cofre do grupo '{group_id}'")
        file_name = metadados.get("file_name")
        file_id = file_name

        if file_id in dados[group_id]["ficheiros"]:
            raise ValueError(f"Erro: O ficheiro '{file_name}' já existe no cofre do grupo '{group_id}'.")

        # Adiciona ou actualiza o ficheiro no cofre
        dados[group_id]["ficheiros"][file_id] = {
            "file_path": file_path,
            "owner": pseudonym,
        }

        clientes_permissoes = [
            (cliente_id, info["permissions"]) 
            for cliente_id, info in dados[group_id]["clientes"].items()
        ]

        # Guarda novamente o ficheiro
        with open(COFRES_GRUPOS, 'w', encoding='utf-8') as f:
            json.dump(dados, f, ensure_ascii=False, indent=4)

        try:
            with open(UTILS, 'r', encoding='utf-8') as f:
                dados = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            dados = {}
        if file_id not in dados:
            dados[file_id] = {}
        if "localização" not in dados[file_id]:
            dados[file_id]["localização"] = {}
        if "lista de paths" not in dados:
            dados["lista de paths"] = []
        if "clientes com acesso" not in dados[file_id]:
            dados[file_id]["clientes com acesso"] = {}

        for cliente, permissao in clientes_permissoes:
            if cliente not in dados:
                dados[cliente] = {}
            if "ficheiros a que tem acesso" not in dados[cliente]:
                dados[cliente]["ficheiros a que tem acesso"] = {}
            if file_id not in dados[cliente]["ficheiros a que tem acesso"]:
                dados[cliente]["ficheiros a que tem acesso"][file_id] = {}
            dados[cliente]["ficheiros a que tem acesso"][file_id]["permissions"] = permissao
        dados[file_id]["localização"] = group_id
        dados["lista de paths"].append(file_path)
        for (cliente, permissao), k in zip(clientes_permissoes, encrypted_k_files):
            dados[file_id]["clientes com acesso"][cliente] = {
                "permissions": permissao,
                "encrypted_k_file": k.decode()
            }

        with open(UTILS, 'w', encoding='utf-8') as f:
            json.dump(dados, f, ensure_ascii=False, indent=4)

        return file_id
    else:
        raise ValueError(f"Erro: Não possui permissões de escrita nesse grupo.")
    


def send_certificate_add_user(metadados, pseudonym):
    group_id = metadados.get("group_id")
    escrever_ficheiro_logs(f"O cliente '{pseudonym} pediu o certificado do cliente '{metadados.get("user_id")}'")
    try:
        with open(COFRES_GRUPOS, 'r', encoding='utf-8') as f:
            dados = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        raise ValueError("Erro: Não foi possível obter o cofre do grupo")
    if group_id not in dados:
        raise ValueError(f"Erro: O grupo '{group_id}' não existe.")
    owner = dados[group_id]["criador"]
    if pseudonym == owner:
        user_id = metadados.get("user_id")
        clients_and_certificates = load_certificates()
        try:
            certificado = clients_and_certificates[user_id].encode()
        except:
            raise ValueError(f"Erro: O user '{user_id} não existe.'")
        encrypted_k_files = []
        ficheiros = list(dados[group_id]["ficheiros"].keys())
        with open(UTILS, 'r', encoding='utf-8') as f1:
                dados_utils = json.load(f1)
        for file in ficheiros:
            encrypted_k_files.append(dados_utils[file]["clientes com acesso"][pseudonym]["encrypted_k_file"].encode())
        encrypted_k_files_ser = BSON.encode({"keys": encrypted_k_files})
        escrever_ficheiro_logs(f"Devolvido o certificado do cliente '{user_id}' e as k_files encriptadas que abrem cada ficheiro do cofre do grupo ao cliente '{pseudonym}'")
        return mkpair(certificado, encrypted_k_files_ser)
    else:
        raise ValueError(f"Erro: Não é o dono desse grupo.")
    


def add_user_group_server(metadados, bundle, pseudonym):
    group_id = metadados.get("group_id")
    escrever_ficheiro_logs(f"O cliente '{pseudonym} pediu para adicionar o user '{metadados.get("user_id")}' ao grupo '{group_id}'")
    user_id = metadados.get("user_id")
    permissoes = metadados.get("permissions")
    if permissoes not in {"R", "W", "RW"}:
        raise ValueError("Erro: Permissões inválidas. Só são permitidas 'R', 'W' ou 'RW'.")
    try:
        with open(COFRES_GRUPOS, 'r', encoding='utf-8') as f:
            dados = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        raise ValueError("Erro: Não foi possível obter o cofre do grupo")
    if group_id not in dados:
        raise ValueError(f"Erro: O grupo '{group_id}' não existe.")
    owner = dados[group_id]["criador"]
    if pseudonym == owner:
        _, encrypted_k_files_bytes = unpair(bundle)
        encrypted_k_files = BSON(encrypted_k_files_bytes).decode()["encrypted_k_files"]

        if user_id in dados[group_id]["clientes"]:
            raise ValueError(f"Erro: O user '{user_id}' já faz parte do grupo '{group_id}'.")

        dados[group_id]["clientes"][user_id] = {
            "permissions": permissoes
        }

        ficheiros = list(dados[group_id]["ficheiros"].keys())
        # Guarda novamente o ficheiro
        with open(COFRES_GRUPOS, 'w', encoding='utf-8') as f:
            json.dump(dados, f, ensure_ascii=False, indent=4)

        try:
            with open(UTILS, 'r', encoding='utf-8') as f:
                dados = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            dados = {}
        if user_id not in dados:
            dados[user_id] = {}
        if "grupos a que pertence" not in dados[user_id]:
            dados[user_id]["grupos a que pertence"] = {}
        if group_id not in dados[user_id]["grupos a que pertence"]:
            dados[user_id]["grupos a que pertence"][group_id] = {}
        dados[user_id]["grupos a que pertence"][group_id]["permissions"] = permissoes
        if "ficheiros a que tem acesso" not in dados[user_id]:
            dados[user_id]["ficheiros a que tem acesso"] = {}
        for file_id in ficheiros:
            if file_id not in dados[user_id]["ficheiros a que tem acesso"]:
                dados[user_id]["ficheiros a que tem acesso"][file_id] = {}
            dados[user_id]["ficheiros a que tem acesso"][file_id]["permissions"] = permissoes
        for file_id, k in zip(ficheiros, encrypted_k_files):
            dados[file_id]["clientes com acesso"][user_id] = {
                "permissions": permissoes,
                "encrypted_k_file": k.decode()
            }

        with open(UTILS, 'w', encoding='utf-8') as f:
            json.dump(dados, f, ensure_ascii=False, indent=4)

    else:
        raise ValueError(f"Erro: Não possui permissões de escrita nesse grupo.")



def delete_group_server(metadados, pseudonym):
    group_id = metadados.get("group_id")
    escrever_ficheiro_logs(f"O cliente '{pseudonym}' pediu para eliminar o grupo '{group_id}'")
    try:
        with open(COFRES_GRUPOS, 'r', encoding='utf-8') as f:
            dados = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        raise ValueError(f"Erro: Não foi possível aceder aos cofres dos grupos.")

    if group_id not in dados:
        raise ValueError(f"Erro: O grupo '{group_id}' não existe.")
    owner = dados[group_id]["criador"]
    if pseudonym == owner:
        ficheiros = list(dados[group_id]["ficheiros"].keys())
        lista_paths = []
        for ficheiro in ficheiros:
            file_path = dados[group_id]["ficheiros"][ficheiro]["file_path"]
            lista_paths.append(file_path)

        clientes = list(dados[group_id]["clientes"].keys())
        del dados[group_id]
        with open(COFRES_GRUPOS, 'w', encoding='utf-8') as f:
            json.dump(dados, f, ensure_ascii=False, indent=4)

        try:
            with open(UTILS, 'r', encoding='utf-8') as f:
                dados_utils = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            raise ValueError("Erro.")
        try:
            if "lista de paths" in dados_utils:
                for path in lista_paths:
                    if path in dados_utils["lista de paths"]:
                        dados_utils["lista de paths"].remove(path)
            for file in ficheiros:
                if file in dados_utils: del dados_utils[file]
            for cliente in clientes:
                del dados_utils[cliente]["grupos a que pertence"][group_id]
                for file in ficheiros:
                    if file in dados_utils[cliente]["ficheiros a que tem acesso"]: del dados_utils[cliente]["ficheiros a que tem acesso"][file]
        except:
            raise ValueError(f"Erro: Não foi possível remover por completo os ficheiros pertencentes ao grupo '{group_id}'")
        with open(UTILS, 'w', encoding='utf-8') as f:
            json.dump(dados_utils, f, ensure_ascii=False, indent=4)
    else:
        raise ValueError(f"Erro: Não é o dono do grupo '{group_id}'")



def remove_user_group_server(metadados, pseudonym):
    group_id = metadados.get("group_id")
    user_id = metadados.get("user_id")
    escrever_ficheiro_logs(f"O cliente '{pseudonym}' pediu para remover o utilizador '{user_id}' do grupo '{group_id}'")
    try:
        with open(COFRES_GRUPOS, 'r', encoding='utf-8') as f:
            dados = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        raise ValueError(f"Erro: Não foi possível aceder aos cofres dos grupos.")
    
    if group_id not in dados:
        raise ValueError(f"Erro: O grupo '{group_id}' não existe.")
    owner = dados[group_id]["criador"]

    if user_id not in dados[group_id]["clientes"]:
        raise ValueError(f"Erro: O utilizador '{user_id}' não pertence ao grupo '{group_id}'.")
    
    if user_id == pseudonym:
        raise ValueError("Erro: Não é possível remover-se a si próprio de um grupo")

    if pseudonym == owner:
        ficheiros = list(dados[group_id]["ficheiros"].keys())
        del dados[group_id]["clientes"][user_id]
        with open(COFRES_GRUPOS, 'w', encoding='utf-8') as f:
            json.dump(dados, f, ensure_ascii=False, indent=4)

        try:
            with open(UTILS, 'r', encoding='utf-8') as f:
                dados_utils = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            raise ValueError("Erro.")
        try:
            for file in ficheiros:
                if file in dados_utils: 
                    if user_id in dados_utils[file]["clientes com acesso"]: del dados_utils[file]["clientes com acesso"][user_id]
            del dados_utils[user_id]["grupos a que pertence"][group_id]
            for file in ficheiros:
                if file in dados_utils[user_id]["ficheiros a que tem acesso"]: del dados_utils[user_id]["ficheiros a que tem acesso"][file]
        except:
            raise ValueError(f"Erro: Não foi possível remover por completo os ficheiros pertencentes ao grupo '{group_id}' para o utilizador '{user_id}'")
        with open(UTILS, 'w', encoding='utf-8') as f:
            json.dump(dados_utils, f, ensure_ascii=False, indent=4)
    else:
        raise ValueError(f"Erro: Não é o dono do grupo '{group_id}'")
    


def get_group_list_server(metadados, pseudonym):
    escrever_ficheiro_logs(f"O cliente '{pseudonym}' pediu a listagem dos grupos a que pertence e as respetivas permissões.")
    try:
        with open(UTILS, 'r', encoding='utf-8') as f:
            dados_utils = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        raise ValueError("Erro: Não existem informações de grupos no servidor")
    
    if pseudonym not in dados_utils:
        raise ValueError("Erro.")
    
    if "grupos a que pertence" not in dados_utils[pseudonym]:
        raise ValueError(f"Erro: O utilizador '{pseudonym}' não pertence a nenhum grupo")
    
    grupos = list(dados_utils[pseudonym]["grupos a que pertence"].keys())
    if not grupos:
        raise ValueError(f"Erro: O utilizador '{pseudonym}' não pertence a nenhum grupo")

    grupos_permissoes = []
    for grupo in grupos:
        grupo_id = grupo
        permissoes = dados_utils[pseudonym]["grupos a que pertence"][grupo]["permissions"]
        grupos_permissoes.append(mkpair(grupo_id.encode(), permissoes.encode()))
    grupos_permissoes_ser = BSON.encode({"lista": grupos_permissoes})
    return grupos_permissoes_ser



def list_files_user_server(metadados, pseudonym):
    user_id = metadados.get("user_id")
    escrever_ficheiro_logs(f"O cliente '{pseudonym}' pediu a listagem dos ficheiros a que o '{user_id}' tem acesso.")
    try:
        with open(UTILS, 'r', encoding='utf-8') as f:
            dados_utils = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        raise ValueError("Erro: Não existem informações no servidor")
    
    if user_id not in dados_utils:
        raise ValueError(f"Erro: Não existem informações sobre '{user_id}' no servidor")
    
    if "ficheiros a que tem acesso" not in dados_utils[user_id]:
        raise ValueError(f"Erro: O utilizador '{user_id}' não tem acesso a nenhum ficheiro")
    
    ficheiros = list(dados_utils[user_id]["ficheiros a que tem acesso"].keys())
    if not ficheiros:
        raise ValueError(f"Erro: O utilizador '{user_id}' não tem acesso a nenhum ficheiro")
    
    ficheiros_bytes = []
    for ficheiro in ficheiros:
        ficheiros_bytes.append(ficheiro.encode())
    ficheiros_bytes_ser = BSON.encode({"ficheiros": ficheiros_bytes})
    return ficheiros_bytes_ser



def list_files_group_server(metadados, pseudonym):
    group_id = metadados.get("group_id")
    escrever_ficheiro_logs(f"O cliente '{pseudonym}' pediu a listagem dos ficheiros que pertencem ao grupo '{group_id}'.")
    try:
        with open(COFRES_GRUPOS, 'r', encoding='utf-8') as f:
            dados = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        raise ValueError("Erro: Não existem informações no servidor")
    
    if group_id not in dados:
        raise ValueError(f"Erro: Não existem informações sobre '{group_id}' no servidor")
    
    if "ficheiros" not in dados[group_id]:
        raise ValueError(f"Erro: Não existem ficheiros no grupo '{group_id}'")
    
    ficheiros = list(dados[group_id]["ficheiros"].keys())
    if not ficheiros:
        raise ValueError(f"Erro: Não existem ficheiros no grupo '{group_id}'")
    
    ficheiros_bytes = []
    for ficheiro in ficheiros:
        ficheiros_bytes.append(ficheiro.encode())
    ficheiros_bytes_ser = BSON.encode({"ficheiros": ficheiros_bytes})
    return ficheiros_bytes_ser



def send_certificate(metadados, pseudonym):
    file_id = metadados.get("file_id")
    user_id = metadados.get("user_id")
    escrever_ficheiro_logs(f"O cliente '{pseudonym} pediu o certificado do cliente '{metadados.get("user_id")}'")
    try:
        with open(COFRES_INDIVIDUAIS, 'r', encoding='utf-8') as f:
            dados = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        raise ValueError("Erro: Não foi possível obter o cofre do cliente")
    if pseudonym not in dados:
        raise ValueError(f"Erro: O cofre do cliente '{pseudonym}' não existe.")
    if file_id in dados[pseudonym]:
        clients_and_certificates = load_certificates()
        try:
            certificado = clients_and_certificates[user_id].encode()
        except:
            raise ValueError(f"Erro: O user '{user_id} não existe.'")
        with open(UTILS, 'r', encoding='utf-8') as f1:
            dados_utils = json.load(f1)
        encrypted_k_file = (dados_utils[file_id]["clientes com acesso"][pseudonym]["encrypted_k_file"].encode())
        escrever_ficheiro_logs(f"Devolvido o certificado do cliente '{user_id}' e a k_file encriptada que abre o ficheiro '{file_id}'")
        return mkpair(certificado, encrypted_k_file)
    else:
        raise ValueError(f"Erro: O ficheiro '{file_id}' não existe no cofre pessoal do cliente '{pseudonym}'.")
    


def share_file_server(metadados, bundle, pseudonym):
    file_id = metadados.get("file_id")
    escrever_ficheiro_logs(f"O cliente '{pseudonym} pediu para partilhar o ficheiro '{file_id}' com o utilizador '{metadados.get("user_id")}'")
    user_id = metadados.get("user_id")
    permissoes = metadados.get("permissions")
    if permissoes not in {"R", "W", "RW"}:
        raise ValueError("Erro: Permissões inválidas. Só são permitidas 'R', 'W' ou 'RW'.")
    try:
        with open(COFRES_INDIVIDUAIS, 'r', encoding='utf-8') as f:
            dados = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        raise ValueError("Erro: Não foi possível obter o cofre do cliente")
    if pseudonym not in dados:
        raise ValueError(f"Erro: O cofre do cliente '{pseudonym}' não existe.")
    if file_id in dados[pseudonym]:
        _, encrypted_k_file = unpair(bundle)

        try:
            with open(UTILS, 'r', encoding='utf-8') as f:
                dados = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            dados = {}
        if user_id not in dados:
            dados[user_id] = {}
        if "ficheiros a que tem acesso" not in dados[user_id]:
            dados[user_id]["ficheiros a que tem acesso"] = {}
        if file_id not in dados[user_id]["ficheiros a que tem acesso"]:
            dados[user_id]["ficheiros a que tem acesso"][file_id] = {}
            dados[user_id]["ficheiros a que tem acesso"][file_id]["permissions"] = permissoes
        else:
            raise ValueError(f"Erro: O utilizador '{user_id}' já tinha acesso ao ficheiro '{file_id}'")
        dados[file_id]["clientes com acesso"][user_id] = {
            "permissions": permissoes,
            "encrypted_k_file": encrypted_k_file.decode()
        }

        with open(UTILS, 'w', encoding='utf-8') as f:
            json.dump(dados, f, ensure_ascii=False, indent=4)

    else:
        raise ValueError(f"Erro: O ficheiro '{file_id}' não existe no cofre pessoal do cliente '{pseudonym}'.")



def delete_file_server(metadados, pseudonym):
    file_id = metadados.get("file_id")
    escrever_ficheiro_logs(f"O cliente '{pseudonym}' pediu para eliminar o ficheiro '{file_id}'")
    try:
        with open(UTILS, 'r', encoding='utf-8') as f:
            dados_utils = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        raise ValueError("Erro: não existem informações no servidor.")
    if file_id not in dados_utils:
        raise ValueError(f"Erro: o ficheiro '{file_id}' não existe.")
    localizacao = dados_utils[file_id]["localização"]
    lista_paths = []
    if localizacao.startswith("grupo"):
        try:
            with open(COFRES_GRUPOS, 'r', encoding='utf-8') as f:
                dados = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            raise ValueError(f"Erro: Não foi possível aceder aos cofres dos grupos.")
        
        encontrou = False
        for grupo in dados.keys():
            files = list(dados[grupo]["ficheiros"].keys())
            if file_id in files:
                encontrou = True
                if (dados[grupo]["ficheiros"][file_id]["owner"] == pseudonym) or (dados[grupo]["criador"] == pseudonym):
                    lista_paths.append(dados[grupo]["ficheiros"][file_id]["file_path"])
                    del dados[grupo]["ficheiros"][file_id]
                    clientes = list(dados[grupo]["clientes"].keys())
                    with open(COFRES_GRUPOS, 'w', encoding='utf-8') as f:
                        json.dump(dados, f, ensure_ascii=False, indent=4)
                elif dados[grupo]["criador"] != pseudonym:
                    raise ValueError(f"Erro: O cliente '{pseudonym}' não é criador do grupo nem dono do ficheiro.")
        if not encontrou:
            raise ValueError(f"Erro: O ficheiro '{file_id}' não pertence a nenhum grupo.")
        
        with open(UTILS, 'r', encoding='utf-8') as f:
            dados_utils = json.load(f)
            del dados_utils[file_id]
            for path in lista_paths:
                dados_utils["lista de paths"].remove(path)
            for cliente in clientes:
                del dados_utils[cliente]["ficheiros a que tem acesso"][file_id]
        with open(UTILS, 'w', encoding='utf-8') as f:
            json.dump(dados_utils, f, ensure_ascii=False, indent=4)
    else:
        try:
            with open(COFRES_INDIVIDUAIS, 'r', encoding='utf-8') as f:
                dados = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            raise ValueError("Erro: Não foi possível aceder aos cofres dos clientes")
        with open(UTILS, 'r', encoding='utf-8') as f1:
            dados_utils = json.load(f1)

        owner = localizacao
        if (owner not in dados) or (file_id not in dados[owner]):
            raise ValueError(f"Erro: O ficheiro '{file_id}' não existe.")
        if owner == pseudonym:
            # file_path = dados[owner][file_id]["file_path"]
            lista_paths.append(dados[owner][file_id]["file_path"])
            del dados[owner][file_id]
            for path in lista_paths:
                dados_utils["lista de paths"].remove(path)
            # os.remove(file_path)
            clientes = list(dados_utils[file_id]["clientes com acesso"].keys())
            del dados_utils[file_id]
            for cliente in clientes:
                del dados_utils[cliente]["ficheiros a que tem acesso"][file_id]
        else:
            try:
                del dados_utils[file_id]["clientes com acesso"][pseudonym]
                del dados_utils[pseudonym]["ficheiros a que tem acesso"][file_id]
            except:
                raise ValueError(f"Erro: O cliente '{pseudonym}' não tem acesso ao ficheiro '{file_id}'")

        with open(UTILS, 'w', encoding='utf-8') as f1:
            json.dump(dados_utils, f1, ensure_ascii=False, indent=4)

        with open(COFRES_INDIVIDUAIS, 'w', encoding='utf-8') as f:
            json.dump(dados, f, ensure_ascii=False, indent=4)



def ask_k_file_server(metadados , pseudonym):
    file_id = metadados.get("file_id")
    escrever_ficheiro_logs(f"O cliente '{pseudonym}' pediu a chave encriptada do ficheiro '{file_id}'")
    try:
        with open(UTILS, 'r', encoding='utf-8') as f:
            dados_utils = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        raise ValueError("Erro: não existem informações no servidor.")
    if file_id not in dados_utils:
        raise ValueError(f"Erro: o ficheiro '{file_id}' não existe.")
    if pseudonym not in dados_utils[file_id]["clientes com acesso"]:
        raise ValueError(f"Erro: o cliente '{pseudonym}' não tem acesso ao ficheiro '{file_id}'.")
    if dados_utils[file_id]["clientes com acesso"][pseudonym]["permissions"] not in {"W", "RW"}:
        raise ValueError(f"Erro: o cliente '{pseudonym}' não tem permissões para substituir o ficheiro '{file_id}'.")
    file_path = metadados.get("file_path")
    if file_path in dados_utils["lista de paths"]:
        raise ValueError(f"Erro: o ficheiro com path '{file_path}' já existe no sistema.")
    return dados_utils[file_id]["clientes com acesso"][pseudonym]["encrypted_k_file"].encode()



def replace_file_server(metadados, bundle, pseudonym):
    file_path_bytes, _ = unpair(bundle)
    file_path = file_path_bytes.decode()
    file_id = metadados.get("file_id")
    escrever_ficheiro_logs(f"O cliente '{pseudonym}' pediu para substituir o ficheiro com o id '{file_id}' pelo ficheiro com o path '{file_path}'.")
    with open(UTILS, 'r', encoding='utf-8') as f:
        dados_utils = json.load(f)
    localizacao = dados_utils[file_id]["localização"]
    if localizacao == pseudonym: # é o owner
        with open(COFRES_INDIVIDUAIS, 'r', encoding='utf-8') as f2:
            dados = json.load(f2)
        old_path = dados[localizacao][file_id]["file_path"]
        dados[localizacao][file_id] = {
            "file_path": file_path,
        }
        with open(COFRES_INDIVIDUAIS, 'w', encoding='utf-8') as f2:
            json.dump(dados, f2, ensure_ascii=False, indent=4)
        with open(UTILS, 'r', encoding='utf-8') as f2:
            dados = json.load(f2)
        dados["lista de paths"].remove(old_path)
        dados["lista de paths"].append(file_path)
        with open(UTILS, 'w', encoding='utf-8') as f2:
            json.dump(dados, f2, ensure_ascii=False, indent=4)
    elif localizacao.startswith("grupo"): # ficheiro pertence a grupo
        with open(COFRES_GRUPOS, 'r', encoding='utf-8') as f1:
            dados = json.load(f1)
        old_path = dados[localizacao]["ficheiros"][file_id]["file_path"]
        dados[localizacao]["ficheiros"][file_id]["file_path"] = file_path
        with open(COFRES_GRUPOS, 'w', encoding='utf-8') as f1:
            json.dump(dados, f1, ensure_ascii=False, indent=4)
        with open(UTILS, 'r', encoding='utf-8') as f2:
            dados = json.load(f2)
        dados["lista de paths"].remove(old_path)
        dados["lista de paths"].append(file_path)
        with open(UTILS, 'w', encoding='utf-8') as f2:
            json.dump(dados, f2, ensure_ascii=False, indent=4)
    
    else:  # ficheiro foi partilhado
        with open(COFRES_INDIVIDUAIS, 'r', encoding='utf-8') as f2:
            dados = json.load(f2)
        old_path = dados[localizacao][file_id]["file_path"]
        dados[localizacao][file_id] = {
            "file_path": file_path,
        }
        with open(COFRES_INDIVIDUAIS, 'w', encoding='utf-8') as f2:
            json.dump(dados, f2, ensure_ascii=False, indent=4)
        with open(UTILS, 'r', encoding='utf-8') as f2:
            dados = json.load(f2)
        dados["lista de paths"].remove(old_path)
        dados["lista de paths"].append(file_path)
        with open(UTILS, 'w', encoding='utf-8') as f2:
            json.dump(dados, f2, ensure_ascii=False, indent=4)



def get_details_server(metadados, pseudonym):
    file_id = metadados.get("file_id")
    escrever_ficheiro_logs(f"O cliente '{pseudonym}' pediu os detalhes do ficheiro '{file_id}'.")
    try:
        with open(UTILS, 'r', encoding='utf-8') as f:
            dados_utils = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        raise ValueError("Erro: Não existem informações do ficheiro no servidor")
    
    if file_id not in dados_utils:
        raise ValueError(f"Erro: O ficheiro '{file_id} não existe'")
    clientes_permissoes = [
        (cliente_id, info["permissions"]) 
        for cliente_id, info in dados_utils[file_id]["clientes com acesso"].items()
    ]
    localizacao = dados_utils[file_id]["localização"]
    if localizacao.startswith("grupo"):
        with open(COFRES_GRUPOS, 'r', encoding='utf-8') as f1:
            dados = json.load(f1)
        owner = dados[localizacao]["ficheiros"][file_id]["owner"]
    else:
        owner = localizacao

    clientes_permissoes_lista = []
    for cliente, permissao in clientes_permissoes:
        clientes_permissoes_lista.append(mkpair(cliente.encode(), permissao.encode()))
    clientes_permissoes_lista_ser = BSON.encode({"lista": clientes_permissoes_lista})
    msg = mkpair(file_id.encode(), mkpair(owner.encode(), clientes_permissoes_lista_ser))
    return msg



def revoke_permissions_server(metadados, pseudonym):
    file_id = metadados.get("file_id")
    user_id = metadados.get("user_id")
    escrever_ficheiro_logs(f"O cliente '{pseudonym}' pediu para revogar as permissões do '{user_id}' sobre o ficheiro '{file_id}'.")
    try:
        with open(UTILS, 'r', encoding='utf-8') as f:
            dados_utils = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        raise ValueError("Erro: Não existem informações no servidor")
    if file_id not in dados_utils:
        raise ValueError(f"Erro: O ficheiro '{file_id}' não existe")
    if user_id not in dados_utils:
        raise ValueError(f"Erro: O utilizador '{user_id}' não existe")
    if pseudonym == user_id:
        raise ValueError("Erro: Não é possível remover permissões do próprio cliente.")
    if pseudonym == dados_utils[file_id]["localização"]:
        if user_id not in dados_utils[file_id]["clientes com acesso"]:
            raise ValueError(f"Erro: O utilizador '{user_id}' não tem acesso ao ficheiro '{file_id}'")
        else:
            dados_utils[file_id]["clientes com acesso"][user_id]["permissions"] = ""
        dados_utils[user_id]["ficheiros a que tem acesso"][file_id]["permissions"] = ""
        with open(UTILS, 'w', encoding='utf-8') as f2:
            json.dump(dados_utils, f2, ensure_ascii=False, indent=4)
    elif dados_utils[file_id]["localização"].startswith("grupo"):
        raise ValueError(f"Erro: O ficheiro '{file_id}' não pertence a um cofre pessoal")
    else:
        raise ValueError(f"Erro: O utilizador '{pseudonym}' não é o dono do ficheiro '{file_id}'")
    


def read_file_server(metadados, pseudonym):
    file_id = metadados.get("file_id")
    escrever_ficheiro_logs(f"O cliente '{pseudonym}' pediu para ler o ficheiro '{file_id}'.")
    try:
        with open(UTILS, 'r', encoding='utf-8') as f:
            dados_utils = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        raise ValueError("Erro: Não existem informações no servidor")
    if file_id not in dados_utils:
        raise ValueError(f"Erro: O ficheiro '{file_id}' não existe")
    if pseudonym not in dados_utils[file_id]["clientes com acesso"]:
        raise ValueError(f"Erro: O utilizador '{pseudonym}' não tem acesso ao ficheiro '{file_id}'")
    if dados_utils[file_id]["clientes com acesso"][pseudonym]["permissions"] not in {"R", "RW"}:
        raise ValueError(f"Erro: O utilizador '{pseudonym}' não tem permissão para ler o ficheiro '{file_id}'")
    encrypted_k_file = dados_utils[file_id]["clientes com acesso"][pseudonym]["encrypted_k_file"].encode()
    localizacao = dados_utils[file_id]["localização"]
    if localizacao.startswith("grupo"):
        with open(COFRES_GRUPOS, 'r', encoding='utf-8') as f:
            dados_grupos = json.load(f)
        file_path = dados_grupos[localizacao]["ficheiros"][file_id]["file_path"].encode()
    else:
        with open(COFRES_INDIVIDUAIS, 'r', encoding='utf-8') as f:
            dados_cofres = json.load(f)
        file_path = dados_cofres[localizacao][file_id]["file_path"].encode()
    msg = mkpair(file_path, encrypted_k_file)
    return msg