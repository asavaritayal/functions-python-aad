import logging
import azure.functions as func
import os
import json
import requests

# My Python Azure Function for adding employees

# Where to start with the queue message
def main(msg: func.QueueMessage) -> None:
    logging.info('Python firstline request made: %s',
                 msg.get_body().decode('utf-8'))
    user = json.loads(msg.get_body().decode('utf-8'))
    
    # Authenticate with the Microsoft Graph
    authenticate()
    
    # Add user to Azure AD
    id = addUser(user)

    # Add employee to AD groups
    addUserToGroup(id)

authenticated = False
def authenticate() -> bool:
    global authenticated
    # Leverage AAD
    if not authenticated:
        global access_token
        logging.info('authenticating...')
        r = requests.post(f'https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token',
                        data = { 
                            'client_id': client_id, 
                            'scope': 'https://graph.microsoft.com/.default',
                            'client_secret': client_secret,
                            'grant_type': 'client_credentials'})
        access_token = r.json()['access_token']
        # logging.info(f'Got token: {access_token}')
        authenticated = True
    return authenticated

def addUser(user: dict) -> str:
    # Add user to graph
    logging.info('adding user: ' + user['firstname'])
    r = requests.post('https://graph.microsoft.com/v1.0/users', json= {
        'accountEnabled': True,
        'userPrincipalName': f'{user["firstname"]}@{fqdn}',
        'displayName': f'{user["firstname"]} {user["lastname"]}',
        'mailNickname': user['firstname'],
        'givenName': user['firstname'],
        'surname': user['lastname'],
        'passwordProfile': {
            'password': '@#This%&',
            'forceChangePasswordNextSignIn': True
        }
    }, headers = {
        'Authorization': f'Bearer {access_token}',
    })
    logging.info(r.text)
    return r.json()['id']

def addUserToGroup(id: str) -> bool:
    # Add user to group
    logging.info('adding user to firstline groups...')
    r = requests.post(f'https://graph.microsoft.com/v1.0//groups/{groupId}/members/$ref', json= {
        '@odata.id': f'https://graph.microsoft.com/v1.0/directoryObjects/{id}'
    }, headers = {
        'Authorization': f'Bearer {access_token}',
    })
    return True


tenant = os.environ['tenant']
client_id = os.environ['client_id']
client_secret = os.environ['client_secret']
access_token = ''
groupId = os.environ['groupId']
fqdn = os.environ['fqdn']