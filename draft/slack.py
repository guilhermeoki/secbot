import requests,json,os

host=os.environ.get('SLACK_HOST')
cookie=os.environ.get('SLACK_COOKIE')
headers = {
    'origin': host,
    'accept-encoding': 'gzip, deflate, br',
    'accept-language': 'pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7',
    'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36',
    'accept': '*/*',
    'authority': host.replace('https://',''),
    'cookie': cookie,
    'x-slack-version-ts': '1523583774',
}
token=requests.get(host+'/admin',headers=headers).text.split('api_token: "')[1].split('",')[0].strip()
if len(token) < 5: 
    exit("Error in config")
def invite(email):
    files={'email': (None, email), 'source': (None, 'invite_modal'),'mode': (None, 'manual'),'channels': (None, ''),'token': (None, token),'set_active': (None, 'true')}
    response = requests.post(host+'/api/users.admin.invite', headers=headers, files=files)
    return response.text

def del_invite(email):
    r=requests.get(host+'/admin/invites',headers=headers)
    try:
        crumb=r.text.split('boot_data.crumb_key = "')[1].split('";')[0]
        data = json.loads(r.text.split('boot_data.pending_invites =')[1].split(';')[0])
    except IndexError:
        exit('ValueError')
    for invites in data:
        if email == invites['email']:
            url=host+'/admin/invites?revoke={}&{}'.format(invites['id'],crumb)
            r=requests.get(url,headers=headers)
            if "revoked" in r.text:
                return "Your invitation to {} has been revoked.".format(email)
            else:
                return "Error"
    return "Invitation not found"

def del_user(email):
    files={'query': (None, '{"type":"is","value":"user"}'), 'sort': (None, 'email'),'count': (None, '1000'),'include_bots': (None, '0'),'exclude_slackbot': (None, 'true'),'token': (None, token),'set_active': (None, 'true')}
    req=requests.post(host+'/api/users.admin.fetchTeamUsers',headers=headers, files=files)
    for users in req.json()['items']:
        if email == users['profile']['email']:
            files={'user': (None, users['id']),'token': (None, token),'set_active': (None, 'true')}
            r=requests.post(host+'/api/users.admin.setInactive',headers=headers,files=files)
            return r.text
    return "User not found"

if __name__ == "__main__":
    import sys
    try:
        if sys.argv[1] == "-i":
            print (invite(sys.argv[2]))
        elif sys.argv[1] == "-ri":
            print (del_invite(sys.argv[2]))
        elif sys.argv[1] == "-d":
            print (del_user(sys.argv[2]))
        else:
            exit('Usage: python3 '+sys.argv[0]+' -i | -ri | -d email@email.com')
    except IndexError:
        exit('Usage: python3 '+sys.argv[0]+' -i | -ri | -d email@email.com')
