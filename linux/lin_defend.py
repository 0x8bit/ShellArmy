# /usr/bin/python3

print('\n\t\t\t+++++++++++++++++++++++++')
print('\t\t          Linux defend     ')
print('\t\t\t+++++++++++++++++++++++++\n')
import os, sys
import subprocess

def commands():
    print("""
    [01] List services
    [02] Show processes
    [03] Start, stop or restart services
    [04] List upstart service
    [05] Export existinng iptables firewall rules
    [06] Import iptables firewall rules
    [07] iptables INPUT, OUTPUT, FORWARD connection config
    [08] iptables ip and port config
    [09] iptables DROP or ACCEPT all INPUT, OUTPUT, FORWARD connections
    [10] Save all iptables rule
    [11] List iptables rule
    [12] Flush iptable rule
    [13] Unrestricted firewall(ufw) rule (accept, deny or reject) port
    [14] Unrestricted firewall(ufw) rule (accept, deny or reject) IP
    [15] Change password
    [16] Flush DNS cache
    [17] Flush nscd DNS cache
    [18] Flush dnsmasq DNS cache
    [19] Quit

""")


def show_service():
    prompt = input('Show service (y/n) > ').lower()
    if prompt == 'y':
        try:
            shell = subprocess.Popen('service --status-all', shell=True)
            shell.communicate()
        except:
            print('Error!')
    else:
        print('Skipped')


def show_process():
    prompt = input('Show process (y/n) > ').lower()
    if prompt == 'y':
        try:
            shell = subprocess.Popen('ps -aux', shell=True)
            shell.communicate()
        except:
            print('Error!')
    else:
        print('Skipped')


def start_stop_restart_service():
    name = input('Service name > ')
    action = input('Start, stop or restart > ').lower()
    if not name:
        print('\nError!\nService is invalid')
    elif action not in ['start', 'stop', 'restart']:
        print('\nError!\nAction is invalid!')
    else:
        try:
            shell = subprocess.Popen('/etc/init.d/%s %s' % (name, action), shell=True)
            shell.communicate()
            if shell.wait() > 0:
                print('\nTrying another command...')
                shell = subprocess.Popen('service %s %s' % (name, action), shell=True)
                shell.communicate()
        except:
            print('Error!')


def list_upstart_services():
    prompt = input('List all upstart services (y/n) > ').lower()
    if prompt == 'y':
        try:
            shell = subprocess.Popen('ls /etc/init/*.conf', shell=True)
            shell.communicate()
        except:
            print('Error!')
    else:
        print('Skipped')


def export_existing_ip_tables_rules():
    print('Export ip tables firewall rules')
    filename = input('Filename > ')
    location = input(os.path.normpath('Location to save > '))
    fullpath = os.path.join(location, filename)
    if not filename:
        print('Invalid filename\n')
    if not os.path.exists:
        os.mkdir(location)
    try:
        shell = subprocess.Popen('iptables-save > %s' % fullpath, shell=True)
        shell.communicate()
    except:
        print('Error!')


def import_iptables_firewall():
    directory = os.path.normpath(input('Directory containing iptables firewall rules > '))
    if not os.path.exists(directory):
        print('Directory is invalid')
    else:
        try:
            shell = subprocess.Popen('iptables-restore < %s' % directory, shell=True)
            shell.communicate()
        except:
            print('Error!')


def iptables_input_or_output_connection_config():
    direction = input('Direction (INPUT, OUTPUT or FORWARD) > ').upper()
    ip = input('%s IP, IP range or port to block > ' % direction)
    action = input('ACCEPT OR DROP > ').upper()
    if direction not in ['INPUT', 'OUTPUT', 'FORWARD']:
        print('Direction is invalid')
    elif not ip:
        print('IP is invalid')
    elif action not in ['ACCEPT', 'DROP']:
        print('Action is invalid')
    elif not ip.isnumeric():
        try:
            shell = subprocess.Popen('iptables -A %s -s %s -j %s' % (direction, ip, action), shell=True)
            shell.communicate()
        except:
            print('Error!')
    else:
        try:
            protocol = input('TCP or UDP > ').lower()
            if not protocol: print('Protocol is invalid')
            shell = subprocess.Popen('iptables -A %s -p %s --dport %s -j %s' % (direction, protocol, ip, action),
                                     shell=True)
            shell.communicate()
        except:
            print('Error!')


def iptables_ip_and_port_config():
    direction = input('Direction (INPUT, OUTPUT or FORWARD) > ').upper()
    ip = input('%s IP > ' % direction)
    port = input('PORT > ')
    protocol = input('TCP or UDP > ').lower()
    action = input('ACCEPT OR DROP > ').upper()
    if not protocol:
        print('Protocol is invalid')
    if direction not in ['INPUT', 'OUTPUT', 'FORWARD']:
        print('Direction is invalid')
    elif not ip:
        print('IP is invalid')
    elif not port:
        print('Port is invalid')
    elif action not in ['ACCEPT', 'DROP']:
        print('Action is invalid')
    else:
        try:
            shell = subprocess.Popen('iptables -A %s -p %s --dport %s -s %s -j %s' %
                                     (direction, protocol, port, ip, action), shell=True)
            shell.communicate()
        except:
            print('Error!')


def iptables_block_or_accept_all_connections():
    direction = input('INPUT, OUTPUT, FORWARD > ').upper()
    action = input('DROP  or ACCEPT all %s connections > ' % direction).upper()
    if direction not in ['INPUT', 'OUTPUT', 'FORWARD']:
        print('Direction is invalid')
    elif action not in ['ACCEPT', 'DROP']:
        print('Action is invalid')
    else:
        try:
            shell = subprocess.Popen('iptables -P %s %s' % (direction, action), shell=True)
            shell.communicate()
        except:
            print('Error!')

def save_all_iptables_rules():
    action = input("Save all current iptables rules (y/n) > ").lower()
    if action == 'y':
        commands = ['/etc/init.d/iptables save', '/sbin/service iptables save', '/sbin/iptables-save']
        com = 0
        while com < 3:
            shell = subprocess.Popen(commands[com], shell=True)
            shell.communicate()
            if shell.wait() > 0:
                print('\nTrying another command..')
                com += 1
                continue
            else:
                print('Error!')
                break
    else:
        print('Skipped')

def list_iptables_rule():
    action = input('List iptables rule (y/n) > ').lower()
    if action == 'y':
        try:
            shell = subprocess.Popen('iptables -L', shell=True)
            shell.communicate()
        except:
            print('Error!')
    else:
        print('Skipped')

def flush_iptables_rule():
    action = input('Flush all iptables rule (y/n) > ').lower()
    if action == 'y':
        try:
            shell = subprocess.Popen('iptables -L', shell=True)
            shell.communicate()
        except:
            print('Error!')
    else:
        print('Skipped')

def ufw_rule_allow_deny_reject_port():
    port = input('Port > ')
    protocol = input('Protocol (tcp or udp) skip if none > ').lower()
    action = input('allow, reject, limit or deny port %s > ' % port).lower()
    join_port_protocol = port+'/'+protocol if protocol in ['tcp', 'udp'] or len(protocol) > 1 else port

    if not port:
        print(' Port is invalid')
    elif action not in ['allow', 'reject', 'deny', 'limit']:
        print('Action is invalid')
    else:
        try:
            shell = subprocess.Popen('ufw %s %s' % (action, join_port_protocol),
                                     shell=True)
            shell.communicate()
        except:
            print('Error!')

def ufw_rule_allow_deny_reject_port_ip():
    ip = input('IP > ')
    port = input('Port (skip if none > ')
    action = input('allow, reject, limit or deny > ').lower()
    if not ip:
        print('IP is invalid')
    elif port and ip:
        protocol = input('tcp or udp > ').lower()
        if protocol not in ['tcp', 'udp']:
            print('Protocol is invalid')
        try:
            shell = subprocess.Popen('ufw %s from %s proto %s to any port %s' % (action, ip, protocol, port),
                                     shell=True)
            shell.communicate()
        except:
            print('Error!')
    elif ip:
        try:
            shell = subprocess.Popen('ufw %s %s' % (action, ip), shell=True)
            shell.communicate()
        except:
            print('Error!')

def change_password():
    user = input('Enter user name (skip if current) > ')
    try:
        shell = subprocess.Popen('passwd ' + user if len(user) > 1 else 'passwd', shell=True)
        shell.communicate()
    except:
        print('Error!')

def dns_cache_flush():
    prompt = input('Flush DNS cache (y/n) > ').lower()
    if prompt == 'y':
        try:
            shell = subprocess.Popen('/etc/init.d/dns-clean flush', shell=True)
            shell.communicate()
        except:
            print('Error!')
    else:
        print('Skipped')

def flush_nscd_dns_cache():
    prompt = input('Flush nscd DNS cache (y/n) > ').lower()
    if prompt == 'y':
        commands = ['/etc/init.d/nscd restart', 'service nscd restart',
                    'service nscd reload', 'nscd -i hosts']
        com = 0
        while com < len(commands):
            shell = subprocess.Popen(commands[com], shell=True)
            shell.communicate()
            if shell.wait() > 0:
                print('Trying another command...')
                com += 1
                continue
            else:
                print('Error!')
                break
    else:
        print('Skipped')

def flush_dnsmasq_dns_cache():
    prompt = input('Flush dnsmasq DNS cache (y/n) > ').lower()
    if prompt == 'y':
        try:
            shell = subprocess.Popen('/etc/init.d/dnsmasq restart', shell=True)
            shell.communicate()
        except:
            print('Error!')
    else:
        print('Skipped')


print('commands - to list available commands')
while True:
    user_input = input('\n__Select >__ ')
    if user_input == '1':
        show_service()
    elif user_input == '2':
        show_process()
    elif user_input == '3':
        start_stop_restart_service()
    elif user_input == '4':
        list_upstart_services()
    elif user_input == '5':
        export_existing_ip_tables_rules()
    elif user_input == '6':
        import_iptables_firewall()
    elif user_input == '7':
        iptables_input_or_output_connection_config()
    elif user_input == '8':
        iptables_ip_and_port_config()
    elif user_input == '9':
        iptables_block_or_accept_all_connections()
    elif user_input == '10':
        save_all_iptables_rules()
    elif user_input == '11':
        list_iptables_rule()
    elif user_input == '12':
        flush_iptables_rule()
    elif user_input == '13':
        ufw_rule_allow_deny_reject_port()
    elif user_input == '14':
        ufw_rule_allow_deny_reject_port_ip()
    elif user_input == '15':
        change_password()
    elif user_input == '16':
        dns_cache_flush()
    elif user_input == '17':
        flush_nscd_dns_cache()
    elif user_input == '18':
        flush_dnsmasq_dns_cache()
    elif user_input == 'commands':
        commands()
    elif user_input in ['19', 'back', 'Back']:
        sys.exit()
    else:
        print('You\'re drunk!')










