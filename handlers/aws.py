import re
from handlers.base import BaseHandler
import boto3
import os

class Handler(BaseHandler):

    name = 'AWS'

    prefix = 'aws'

    patterns = [
        (['{prefix} (?P<command>list accounts)'], 'Obtém a lista de contas'),
        (['{prefix} (?P<command>list regions)'], 'Obtém a lista de regiões'),
        (['{prefix} (?P<account>\S+) (?P<region>\S+) (?P<command>list instances)'], 'Obtém a lista das instâncias e suas roles'),
        (['{prefix} (?P<account>\S+) (?P<region>\S+) (?P<command>whoisip) (?P<address>\S+)'], 'Obtém a role da máquina <address>'),
        (['{prefix} (?P<account>\S+) (?P<region>\S+) (?P<command>whois) (?P<name>\S+)'], 'Obtém os IPs das máquinas com a role <name>'),
        (['{prefix} (?P<command>findip) (?P<address>\S+)'], 'Obtém a role da máquina <address> em todas as regiões de todas as contas'),
        (['{prefix} (?P<command>find) (?P<name>\S+)'], 'Obtém os IPs das máquinas com a role <name> em todas as regiões de todas as contas'),
        (['{prefix} (?P<account>\S+) (?P<region>\S+) (?P<command>waf block) (?P<addresses>.*)'], 'Bloqueia IPs no WAF'),
        (['{prefix} (?P<account>\S+) (?P<region>\S+) (?P<command>waf unblock) (?P<addresses>.*)'], 'Desbloqueia IPs no WAF'),
        (['{prefix} (?P<account>\S+) (?P<region>\S+) (?P<command>waf list)'], 'Lista os IPs bloqueados no WAF'),
    ]


    def __init__(self, bot, slack):
        super().__init__(bot, slack)

        self.directed = True

        os.environ['AWS_DEFAULT_REGION'] = 'us-east-1'
        os.environ['AWS_DEFAULT_PROFILE'] = 'prod'

        self.credentials = boto3.Session().available_profiles
        self.regions = boto3.Session().get_available_regions('ec2')

        self.client = boto3.client('ec2')


    def list_instances(self, session):
        instances = {}
        instances_reverse = {}

        obj = session.client('ec2').describe_instances()

        for res in obj['Reservations']:
            for instance in res['Instances']:
                name = [x.get('Value') for x in instance.get('Tags', []) if x.get('Key') == 'Name']
                for net in instance['NetworkInterfaces']:
                    try:
                        if name:
                            if not name[0] in instances_reverse:
                                instances_reverse[name[0]] = []
                            instances_reverse[name[0]].append(net['PrivateIpAddress'])
                        if name:
                            instances[net['PrivateIpAddress']] = name[0]
                        else:
                            instances[net['PrivateIpAddress']] = 'UNNAMED'
                    except:
                        continue

        return instances, instances_reverse

    def process(self, channel, user, ts, message, at_bot, command, **kwargs):
        if at_bot:
            handle = self.get_user_handle(user)
            text = None

            if command == 'list accounts':
                self.post_message(channel, '@{} Contas disponíveis:\n{}'.format(handle, '\n'.join(self.credentials)))

            elif command == 'list regions':
                self.post_message(channel, '@{} Regiões disponíveis:\n{}'.format(handle, '\n'.join(self.regions)))

            elif command == 'findip':
                self.post_message(channel, text='@{} Procurando em `{}` contas com `{}` regiões cada'.format(handle, len(self.credentials), len(self.regions)))
                found = False
                for account in self.credentials:
                    for region in self.regions:
                        session = boto3.Session(region_name=region, profile_name=account)

                        instances, instances_reverse = self.list_instances(session)
                        if 'address' in kwargs:
                            for addr in kwargs['address'].split():
                                if addr in instances:
                                    self.post_message(channel, text='@{} A máquina `{}` está na conta `{}`, região `{}` e possui a role `{}`'.format(handle, addr, account, region, instances[addr]))
                                    found = True
                if not found:
                    self.post_message(channel, text='@{} Máquina desconhecida: `{}`'.format(handle, addr))

            elif command == 'find':
                self.post_message(channel, text='@{} Procurando em `{}` contas com `{}` regiões cada'.format(handle, len(self.credentials), len(self.regions)))

                found = False
                for account in self.credentials:
                    for region in self.regions:
                        session = boto3.Session(region_name=region, profile_name=account)

                        instances, instances_reverse = self.list_instances(session)
                        if 'name' in kwargs:
                            for name in kwargs['name'].split():
                                for key in instances_reverse.keys():
                                    if name in key.lower():
                                        self.post_message(channel, text='@{} A role `{}` está na conta `{}`, região `{}` e possui os IPs `{}`'.format(handle, key, account, region, instances_reverse[key]))
                                        found = True
                if not found:
                    self.post_message(channel, text='@{} Role desconhecida: `{}`'.format(handle, name))

            else:

                account = kwargs['account']

                region = kwargs['region']

                if account not in self.credentials:
                    self.post_message(channel, '@{} Credencial não encontrada: `{}`'.format(handle, account))
                    return

                if region not in self.regions:
                    self.post_message(channel, '@{} Região não encontrada: `{}`'.format(handle, region))
                    return

                session = boto3.Session(region_name=region, profile_name=account)

                if command == 'list instances':
                    instances, instances_reverse = self.list_instances(session)
                    msg = '@{}\n'.format(handle)
                    for instance in instances.keys():
                        msg += '{} - {}\n'.format(instance, instances[instance])
                    self.post_message(channel, text=msg)

                elif command == 'waf block':
                    if not self.authorized(handle, 'WAF'):
                        self.set_job_status('Unauthorized')
                        self.post_message(channel=channel, text='@{} Unauthorized'.format(handle))
                        return False
                    else:

                        session = boto3.Session(region_name=region, profile_name=account)

                        waf = session.client('waf-regional')

                        sets = waf.list_ip_sets()

                        set_id = None

                        for s in sets['IPSets']:
                            if s['Name'] == 'DoS Originators':
                                set_id = s['IPSetId']
                                break
                        else:
                            self.post_message(channel, text='@{} IP Set "DoS Originators" não encontrado'.format(handle))
                            return


                        s = waf.get_ip_set(IPSetId=set_id)

                        ips = [x['Value'] for x in s['IPSet']['IPSetDescriptors']]

                        to_insert = [x for x in kwargs['addresses'].split() if x not in ips]

                        updates = [{'Action': 'INSERT', 'IPSetDescriptor': {'Type': 'IPV4', 'Value': x}} for x in to_insert]

                        token = waf.get_change_token()['ChangeToken']

                        try:
                            u = waf.update_ip_set(IPSetId=set_id, ChangeToken=token, Updates=updates)

                            self.post_message(channel, text='@{} Os seguintes IPs não estavam listados e foram bloqueados:\n{}'.format(handle, '\n'.join(to_insert)))
                        except Exception as e:
                            self.post_message(channel, text='@{} Erro: {}'.format(handle, str(e)))

                elif command == 'waf unblock':
                    if not self.authorized(handle, 'WAF'):
                        self.set_job_status('Unauthorized')
                        self.post_message(channel=channel, text='@{} Unauthorized'.format(handle))
                        return False
                    else:
                        session = boto3.Session(region_name=region, profile_name=account)

                        waf = session.client('waf-regional')

                        sets = waf.list_ip_sets()

                        set_id = None

                        for s in sets['IPSets']:
                            if s['Name'] == 'DoS Originators':
                                set_id = s['IPSetId']
                                break
                        else:
                            self.post_message(channel, text='@{} IP Set "DoS Originators" não encontrado'.format(handle))
                            return


                        s = waf.get_ip_set(IPSetId=set_id)

                        ips = [x['Value'] for x in s['IPSet']['IPSetDescriptors']]

                        to_remove = [x for x in kwargs['addresses'].split() if x in ips]

                        updates = [{'Action': 'DELETE', 'IPSetDescriptor': {'Type': 'IPV4', 'Value': x}} for x in to_remove]

                        token = waf.get_change_token()['ChangeToken']


                        try:
                            u = waf.update_ip_set(IPSetId=set_id, ChangeToken=token, Updates=updates)
                            self.post_message(channel, text='@{} Os seguintes IPs estavam listados e foram desbloqueados:\n{}'.format(handle, '\n'.join(to_remove)))
                        except Exception as e:
                            self.post_message(channel, text='@{} Erro: {}'.format(handle, str(e)))

                elif command == 'waf list':
                    session = boto3.Session(region_name=region, profile_name=account)

                    waf = session.client('waf-regional')

                    sets = waf.list_ip_sets()

                    set_id = None

                    for s in sets['IPSets']:
                        if s['Name'] == 'DoS Originators':
                            set_id = s['IPSetId']
                            break
                    else:
                        self.post_message(channel, text='@{} IP Set "DoS Originators" não encontrado'.format(handle))
                        return


                    s = waf.get_ip_set(IPSetId=set_id)

                    ips = [x['Value'] for x in s['IPSet']['IPSetDescriptors']]

                    self.post_message(channel, text='@{} Os seguintes IPs estão bloqueados:\n{}'.format(handle, '\n'.join(ips)))


                elif command == 'whoisip':
                    instances, instances_reverse = self.list_instances(session)
                    if 'address' in kwargs:
                        for addr in kwargs['address'].split():
                            if addr in instances:
                                self.post_message(channel, text='@{} A máquina `{}` possui a role `{}`'.format(handle, addr, instances[addr]))
                            else:
                                self.post_message(channel, text='@{} Máquina desconhecida: `{}`'.format(handle, addr))

                elif command == 'whois':
                    instances, instances_reverse = self.list_instances(session)
                    if 'name' in kwargs:
                        found = False
                        for name in kwargs['name'].split():
                            for key in instances_reverse.keys():
                                if name in key.lower():
                                    self.post_message(channel, text='@{} A role `{}` possui os IPs `{}`'.format(handle, key, instances_reverse[key]))
                                    found = True
                            if not found:
                                self.post_message(channel, text='@{} Role desconhecida: `{}`'.format(handle, name))
