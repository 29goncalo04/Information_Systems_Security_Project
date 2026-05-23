import json, os



ACTIVE_FILE = "active_users.json"
LOGS = "../JSONS_Server/logs.txt"
CERTIFICATES = "../JSONS_Server/certificates.json"



def load_active():
    try:
        with open(ACTIVE_FILE, "r") as f:
            data = json.load(f)
            return data.get("utilizadores_conectados", {})
    except FileNotFoundError:
        return {}



def save_active(active_dict):
    with open(ACTIVE_FILE, "w") as f:
        json.dump({"utilizadores_conectados": active_dict}, f, indent=2)



def ler_ficheiro(caminho):
    """ Lê o conteúdo de um ficheiro e retorna os dados em bytes. """
    with open(caminho, 'rb') as f:
        return f.read()
    


def escrever_ficheiro(caminho, dados):
    """ Escreve os dados (em bytes) num ficheiro no caminho indicado. """
    with open(caminho, 'wb') as f:
        f.write(dados)



def escrever_ficheiro_logs(dados):
    with open(LOGS, 'a', encoding='utf-8') as f:
        f.write(dados + "\n")



def load_certificates():
    try:
        with open(CERTIFICATES, "r") as f:
            data = json.load(f)
            return data.get("utilizadores", {})
    except FileNotFoundError:
        return {}



def upload_certificates(active_dict):
    with open(CERTIFICATES, "w") as f:
        json.dump({"utilizadores": active_dict}, f, indent=2)