#! /usr/bin/python3

"""
TODO: fix input protocol to accept all protocol
TODO: make cmd.communicate() to print error only if there's any
"""
print('\n\t\t\t+++++++++++++++++++++++++')
print('\t\t         Windows defend     ')
print('\t\t\t+++++++++++++++++++++++++\n')
import os, sys
import subprocess

def commands():
    print("""
    [01] Hash file
    [02] List services
    [03] Stop services
    [04] Disable services
    [05] Show firewall rules
    [06] Switch profile firewall ON/OFF
    [07] Set profile firewall to block inbound always, allow outbound only
    [08] Set port firewall rule
    [09] Set program firewall rule
    [10] Set program remote IP firewall rule
    [11] Set group firewall rule
    [12] Set services firewall rule
    [13] Delete firewall rule
    [14] Set firewall logging location
    [15] Set firewall logging settings
    [16] Show users
    [17] Change password
    [18] Flush DNS of malicious domain/IP
    [19] Flush netbios cache of host/IP
    [20] Create or add to IPSEC filter list
    [21] Create IPSEC filter action
    [22] Create IPSEC policy
    [23] Create IPSEC rule
    [24] Show IPSEC policy, filter action, filter list or rule
    [25] Unassign IPSEC policy, filter action, filter list or rule
    [26] Delete IPSEC policy, filter action, filter list or rule
    [27] Get and force new policies
    [28] Audit success or failure for user
    [29] Disallow or allow running a .exe file
    [30] Disallow or allow running a specific .exe file
    [31] Disable remote desktop
    [32] Send NTMLv2 response only/refuse LM and NTML
    [33] Restrict anonymouse access
    [34] Do not allow anonymous enumeration of SAM accounts and shares
    [35] Disable ipv6
    [36] Disable sticky keys
    [37] Disable toggle keys
    [38] Disable filter keys
    [39] Disable on-screen keyboard
    [40] Disable administrative shares - Workstations
    [41] Disable administrative share - Servers
    [42] Remove creation of hashes 
    [43] Disable registry editor - High risk
    [44] Disable IE password caching
    [45] Disable CMD prompt
    [46] Disable Admin credentials cache on host when using RDP
    [47] Do not process run once list
    [48] Require User Access Control (UAC) Permission
    [49] Back
    """)


def hashfile():
    file2hash = input('File to hash and algorithm to use (e.g file SHA1) > ').split()
    abspath = os.path.abspath(file2hash[0])
    try:
        cmd = subprocess.Popen(('certutil -hashfile %s %s') % (abspath, file2hash[1]), shell=True)
        cmd.communicate()
    except:
        print('Error hashing %s' % abspath)

def listservices():
    list_services = input('List Running Services (y/n) > ').lower()
    if list_services == 'y':
        try:
            cmd = subprocess.Popen('sc query', shell=True)
            cmd.communicate()
        except:
            print('Error')
    else:
        print('Skipped')

def stopservices():
    service_name = input('Enter the name of service to stop > ')
    if not service_name:
        print('\nError!\nService name is invalid')
    else:
        try:
            cmd = subprocess.Popen('sc stop "%s"' % service_name, shell=True)
            cmd.communicate()
        except:
            print('Error stopping service')


def disableservice():
    service_name = input('Enter the name of service to disable > ')
    if not service_name:
        print('\nError!\nService name is invalid')
    else:
        try:
            cmd = subprocess.Popen('sc config "%s" start=disable' % service_name, shell=True)
            cmd.communicate()
        except:
            print('Error disabling service')

def showfirewallrule():
    print('Show firewall rules')
    rulename = input('Rule name to show (skip to show all) > ')
    condition = rulename if len(rulename) >= 1 else 'all'
    try:
        cmd = subprocess.Popen('netsh advfirewall firewall show rule name=%s' % condition, shell=True)
        cmd.communicate()
    except:
        print('Error')

def profile_firewall_OFF_ON():
    print('Switch profile firewall ON/OFF')
    profile = input('Profile (e.g current, public, private, domain, all) > ').lower()
    prompt = input('OFF/ON %sprofile firewall > ' % profile).lower()
    if profile not in ['current', 'public', 'private', 'domain', 'all']:
        print('\nError!\nProfile is invalid')
    elif prompt not in ['on', 'off']:
        print('\nError!\nPrompt is invalid')
    else:
        try:
            cmd = subprocess.Popen('netsh advfirewall set %sprofile state %s' % (profile, prompt), shell=True)
            cmd.communicate()
        except:
            print('Error!')


def profile_firewall_inboud_outbound():
    print('Set profile firewall to block inbound always, allow outbound only')
    profile = input('Profile (e.g current, public, private, domain, all) > ').lower()
    prompt = input('Set %sprofile firewall to block inboundalways and allow outbound only (y/n) > ' %
                   profile).lower()
    if profile not in ['current', 'public', 'private', 'domain', 'all']:
        print('\nError!\nProfile is invalid')
    if prompt == 'y':
        try:
            cmd = subprocess.Popen(
                'netsh advfirewall set %sprofile firewallpolicy blockinboundalways,allowoutbound' % profile,
                shell=True)
            cmd.communicate()
        except:
            print('Error!')
    else:
        return


def set_port_firewall_rule():
    print('Set port firewall rule')
    rulename = input('Rule name > ')
    portnumber = input('Port > ')
    direction = input('Direction (in or out) > ').lower()
    action = input('Action (allow, block, bypass) > ').lower()
    protocol = input('Protocol (TCP or UDP > ').lower()
    if not rulename:
        print('\nError!\nNo rule name given')
    elif len(portnumber) < 1 or portnumber.isnumeric() != True:
        print('\nError!\nInvalid port')
    elif direction not in ['in', 'out']:
        print('\nError!\nDirection is invalid')
    elif action not in ['allow', 'block', 'bypass']:
        print('\nError!\nAction is invalid')
    elif protocol not in ['tcp', 'udp']:
        print('\nError!\nProtocol is invalid')
    else:
        try:
            cmd = subprocess.Popen(
                'netsh advfirewall firewall add rule name="%s" dir=%s action=%s protocol=%s localport=%d' %
                (rulename, direction, action, protocol, int(portnumber)), shell=True)
            cmd.communicate()
        except:
            print('Error')

def set_program_firewall_rule():
    print('Set program firewall rule')
    rulename = input('Rule name > ')
    program = input('Program directory > ')
    direction = input('Direction (in or out) > ').lower()
    action = input('Action (allow, block, bypass) > ').lower()
    enable = input('Enable (yes or no) > ').lower()
    profile = input('Enter profile (public, private, domain, any) > ').lower()
    if not rulename:
        print('\nError!\nNo rule name given')
    elif not os.path.exists(program):
        print('\nError!\nProgram directory does not exits')
    elif direction not in ['in', 'out']:
        print('\nError!\nDirection is invalid')
    elif action not in ['allow', 'block', 'bypass']:
        print('\nError!\nAction is invalid')
    elif enable not in ['yes', 'no']:
        print('\nError!\nEnable is invalid')
    elif profile not in ['private', 'public', 'domain', 'any']:
        print('\nError!\nProfile is invalid')
    else:
        try:
            cmd = subprocess.Popen(
                'netsh advfirewal firewall add rule name="%s" dir=%s action=%s program="%s" enable=%s profile=%s' %
                (rulename, direction, action, program, enable, profile), shell=True)
            cmd.communicate()
        except:
            print('Error!')

def set_program_remoteip_firewall_rule():
    print('Set program remote IP firewall rule')
    rulename = input('Rule name > ')
    program = input('Program directory > ')
    direction = input('Direction (in or out) > ').lower()
    action = input('Action (allow, block, bypass) > ').lower()
    enable = input('Enable (yes or no) > ').lower()
    remoteip = input('Enter remote IP addreess > ')
    profile = input('Enter profile (private, public, domain or any) > ').lower()
    if not rulename:
        print('\nError!\nNo rule name given')
    elif not os.path.exists(program):
        print('\nError!\nProgram directory does not exit')
    elif direction not in ['in', 'out']:
        print('\nError!\nDirection is invalid')
    elif action not in ['allow', 'block', 'bypass']:
        print('\nError!\nAction is invalid')
    elif enable not in ['yes', 'no']:
        print('\nError!\nEnable is invalid')
    elif not remoteip:
        print('\nError!\nRemote IP is invalid')
    elif profile not in ['private', 'public', 'domain', 'any']:
        print('\nError!\nProfile is invalid')
    else:
        try:
            cmd = subprocess.Popen(
                'netsh advfirewall firewall add rule name="%s" dir=%s action=%s program="%s" enable=%s remoteip=%s profile=%s' %
                (rulename, direction, action, program, enable, remoteip, profile), shell=True)
            cmd.communicate()
        except:
            print('Error!')

def set_service_firewall_rule():
    print('Set service firewall rule')
    rulename = input('Rule name > ')
    service = input('Service name > ')
    direction = input('Direction (in or out) > ').lower()
    action = input('Action (allow, block, bypass) > ').lower()
    enable = input('Enable (yes or no) > ').lower()
    profile = input('Enter profile (private, public, domain or any) > ').lower()
    if not rulename:
        print('\nError!\nNo rule name given')
    elif not service:
        print('\nError!\nService name is invalid')
    elif direction not in ['in', 'out']:
        print('\nError!\nDirection is invalid')
    elif action not in ['allow', 'block', 'bypass']:
        print('\nError!\nAction is invalid')
    elif enable not in ['yes', 'no']:
        print('\nError!\nEnable is invalid')
    elif profile not in ['private', 'public', 'domain', 'any']:
        print('\nError!\nProfile is invalid')
    else:
        try:
            cmd = subprocess.Popen(
                'netsh advfirewall firewall add rule name="%s" dir=%s action=%s service="%s" enable=%s profile=%s' %
                (rulename, direction, action, service, enable, profile), shell=True)
            cmd.communicate()
        except:
            print('Error!')

def set_group_firewall_rule():
    print('Set group firewall rule')
    groupname = input('Group name > ')
    enable = input('Enable (yes/no) > ').lower()
    profile = input('Profile (private, public, domain or any ) > ').lower()
    if not groupname:
        print('\nError!\nGroup name invalid')
    elif enable not in ['yes', 'no']:
        print('\nError!\nEnable is invalid')
    elif profile not in ['private', 'public', 'domain', 'any']:
        print('\nError!\nProfile is invalid')
    else:
        try:
            cmd = subprocess.Popen('netsh advfirewall firewall set rule group="%s" new enable=%s profile=%s' %
                                   (groupname, enable, profile), shell=True)
            cmd.communicate()
        except:
            print('Error!')

def delete_firewall_rule():
    """
    TODO: fix to delete firewall rulename if all input parameter were given,
    TODO: or just define a delete function for each input parameter
    """
    print('Delete firewall rule')
    rulename = input('Rule name > ')
    program = input('Program (skip if none) > ')
    protocol = input('Protocol (TCP or UDP, Skip if none)').lower()
    localport = input('Local port (skip if none) > ')
    if not rulename:
        print('\nError!\nRule name is invalid')
    elif (protocol or localport):
        if protocol not in ['tcp', 'udp']:
            print('\nError\nProtocol is invalid')
        elif len(localport) < 1 or localport.isnumeric() != True:
            print('\nError\nLocal port is invalid')
        else:
            try:
                cmd = subprocess.Popen('netsh advfirewall firewall delete rule name="%s" protocol=%s localport=%d' %
                                       (rulename, protocol, int(localport)), shell=True)
                cmd.communicate()
            except:
                print('Error!')
    elif (program):
        if not os.path.exists(program):
            print('\nError!\nProgram directory does not exist')
        else:
            try:
                cmd = subprocess.Popen('netsh advfirewall firewall delete rule name="%s" program=%s' %
                                       (rulename, program), shell=True)
                cmd.communicate()
            except:
                print('Error!')
    else:
        try:
            cmd = subprocess.Popen('netsh advfirewall firewall delete rule name="%s"' % rulename, shell=True)
            cmd.communicate()
        except:
            print('Error!')

def set_firewall_logging_location():
    print('Set firewall logging location')
    location = os.path.normpath(input('Location > '))
    filename = input('Filename (e.g file.log) > ')
    profile = input('Profile (e.g private, public, domain, current, all) > ').lower()
    fullpath = os.path.join(location, filename)
    if not os.path.exists(location):
        os.mkdir(location)
    else:
        files_in_location = os.listdir(location)
        for file in files_in_location:
            if file == filename:
                same_file = os.path.join(location, file)
                os.remove(same_file)
    if not location:
        print('\nError!\nLocation is invalid')
    elif not filename:
        print('\nError!\nFilename is invalid')
    elif profile not in ['private', 'public', 'domain', 'current', 'all']:
        print('\nError!\nProfile is invalid')
    else:
        try:
            cmd = subprocess.Popen('netsh advfirewall set %sprofile logging filename "%s"' %
                                   (profile, fullpath), shell=True)
            cmd.communicate()
        except:
            print('Error!')

def set_firewall_logging_settings():
    print('Set firewall logging settings')
    profile = input('Profile (e.g private, public, domain, current, all) > ').lower()
    action = input('Dropped connection logging (enable/disable) > ').lower()
    action1 = input('Allowed connection logging (enable/disable) > ').lower()
    logsize = input('Maximum log size > ')

    commands = ['netsh advfirewall set %sprofile logging droppedconnections %s',
                    'netsh advfirewall set %sprofile logging allowedconnections %s',
                    'netsh advfirewall set %sprofile logging maxfilesize %d']
    
    if profile not in ['private', 'public', 'domain', 'current', 'all']:
        print('\nError!\nProfile is invalid')
    
    elif logsize:
        if not logsize.isnumeric():
            print('\nError!\nLogsize is invalid')
        else:
            try:
                cmd = subprocess.Popen(commands[2] % (profile, int(logsize)), shell=True)
                cmd.communicate()
            except:
                print('Error!')

    elif action and logsize:
        if action not in ['enable', 'disable']:
            print('\nError!\nDropped connection is invalid')
        else:
            try:
                cmd = subprocess.Popen(commands[0] % (profile, action), shell=True)
                cmd.communicate()
            except:
                print('Error!')
    elif action1 and logsize:
        if action1 not in ['enable', 'disable']:
            print('\nError!\nAllowed connection is invalid')
        else:
            try:
                cmd = subprocess.Popen(commands[1] % (profile, action1), shell=True)
                cmd.communicate()
            except:
                print('Error!')
   
    else:
        print('Skipped')
        

def change_password():
    print('Change password')
    username = input('Username: ')
    password = input('New password: ')
    if not username:
        print('\nError!\nInvalid username')
    else:
        try:
            cmd = subprocess.Popen('net user %s %s' % (username, password), shell=True)
            cmd.communicate()
        except:
            print('Error!')

def show_users():
    user = input('User to show (skip to show all) > ')
    show = input('Show user(s) %s (y/n) > ' % user).lower()
    if show == 'y':
        try:
           cmd = subprocess.Popen('net user ' + user if len(user) > 1 else 'net user', shell=True)
           cmd.communicate()
        except:
           print('Error!')
    else:
        print('Skipped')

def flush_dns():
    flush = input('Flush DNS of malicious domain/IP (y/n)> ').lower()
    if flush == 'y':
        try:
            cmd = subprocess.Popen('ipconfig /flushdns', shell=True)
            cmd.communicate()
        except:
            print('Error!')
    else:
       print('Skipped')

def flush_netbios():
    flush = input('Flush netbios cache of host/IP (y/n) > ').lower()
    if flush == 'y':
        try:
            cmd = subprocess.Popen('nbtstat -R', shell=True)
            cmd.communicate()
        except:
            print('Error!')
    else:
        print('Skipped')

def create_ipsec_filterlist_or_add():
    filtername = input('New filter name or already exist name > ')
    print('Note: Source ip address (ipv4 or ipv6), address range, dns name, any, or server type.')
    srcaddress = input('Source address > ')
    srcport = input('Source port (0 means any port) > ')
    print('Note: Destination ip address (ipv4 or ipv6), address range, dns name, or server type.')
    dstaddress = input('Destination address > ')
    dstport = input('Destination port (0 means any port) > ')
    print('Note: Protocol Can be ANY, ICMP, TCP, UDP, RAW')
    protocol = input('Protocol > ').lower()

    srcport = srcport if srcport.isnumeric() else '0'
    dstport = dstport if dstport.isnumeric() else '0'
    if not filtername:
        print('\nError!\nFilter list name is invalid')
    elif not srcaddress:
        print('\nError!\nSource address is invalid')
    elif not dstaddress:
        print('\nError!\nDestination address is invalid')
    elif protocol not in ['any', 'tcp', 'udp', 'raw', 'icmp']:
        print('\nError!\nProtocol is invalid')
    else:
        try:
            cmd = subprocess.Popen('netsh ipsec static add filter filterlist="%s" srcaddr=%s dstaddr=%s protocol=%s dstport=%s srcport=%s' %
                                   (filtername, srcaddress, dstaddress, protocol, dstport, srcport), shell=True)
            cmd.communicate()
        except:
            print('Error!')


def ipsec_filter_action():
    print('Create IPSEC filter action')
    name = input('Filter action name > ')
    action = input('Action (block, permit or negotiate) > ').lower()
    if not name:
        print('\nError!\nFilter action name is invalid')
    elif action not in ['block', 'negotiate', 'permit']:
        print('\nError!\nAction is invalid')
    else:
        try:
            cmd = subprocess.Popen('netsh ipsec static add filteraction name="%s" action=%s' %
                   (name, action), shell=True)
            cmd.communicate()
        except:
            print('Error!')

def ipsec_policy():
    print('Create IPSEC policy')
    name = input('Policy name > ')
    assign = input('Assign (yes/no) > ').lower()
    if not name:
        print('\nError!\nName is invalid')
    elif assign not in ['yes', 'no']:
        print('\nError!\nAssign is invalid')
    else:
        try:
            cmd = subprocess.Popen('netsh ipsec static add policy name="%s" assign=%s' %
                                   (name, assign), shell=True)
            cmd.communicate()
        except:
            print('Error!')

def ipsec_rule():
    print('Create IPSEC rule')
    name = input('Rule name > ')
    policy = input('Policy name > ')
    filterlist = input('Filter list name > ')
    filteraction = input('Filter action name > ')
    conntype = input('Connection type (lan, dialup or all) > ').lower()
    psk = input('Authentication key > ')
    if not name:
        print('\nError!\nRule name is invalid')
    elif not policy:
        print('\nError!\nPolicy name is invalid')
    elif not filterlist:
        print('\nError!\nFilter list name is invalid')
    elif not filteraction:
        print('\nError!\nFilter action  name is invalid')
    elif conntype not in ['lan', 'dialup', 'all']:
        print('\nError!\nConnection type is invalid')
    elif not psk:
        print('\nError!\nAuthentication key is invalid')
    else:
        try:
            cmd = subprocess.Popen('netsh ipsec static add rule name="%s" policy=%s filterlist=%s filteraction=%s conntype=%s psk="%s"' %
                                   (name, policy, filterlist, filteraction, conntype, psk), shell=True)
            cmd.communicate()
        except:
            print('Error!')

def show_ipsecs():
    ipsec = input('IPSEC to show (filterlist, filteraction, policy, or rule) > ').lower()
    name = input('%s name > ' % ipsec.capitalize())
    if ipsec not in ['filterlist', 'filteraction', 'policy', 'rule']:
        print('\nError!\n IPSEC name is invalid')
    else:
        try:
            cmd = subprocess.Popen('netsh ipsec static show %s name="%s"' % (ipsec, name), shell=True)
            cmd.communicate()
        except:
            print('Error!')


def unassign_ipsec():
    ipsec = input('IPSEC to unassign (filterlist, filteraction, policy, or rule) > ').lower()
    name = input('%s name > ' % ipsec.capitalize())
    if ipsec not in ['filterlist', 'filteraction', 'policy', 'rule']:
        print('\nError!\n IPSEC name is invalid')
    elif not name:
        print('\nError!\nName is invalid')
    else:
        try:
            cmd = subprocess.Popen('netsh ipsec static set %s name="%s"' % (ipsec, name), shell=True)
            cmd.communicate()
        except:
            print('Error')

def delete_ipsec():
    ipsec = input('IPSEC to delete (filterlist, filteraction, policy, rule) > ').lower()
    name = input('%s name > ' % ipsec.capitalize())
    if ipsec not in ['filterlist', 'filteraction', 'policy', 'rule']:
        print('\nError!\nIPSEC name is invalid')
    elif not name:
        print('\nError!\nName is invalid')
    elif ipsec == 'rule':
        try:
            cmd = subprocess.Popen('netsh advfirewall firewall delete rule name="%s"' % name, shell=True)
            cmd.communicate()
        except:
            print('Error!')
    else:
        try:
            cmd = subprocess.Popen('netsh ipsec static delete %s name="%s"' % (ipsec, name), shell=True)
            cmd.communicate()
        except:
            print('Error!')

def get_and_force_new_policy():
    print('Get and force new policies')
    action = input('Policies (force or sync) > ')
    if not action:
        print('\nError! Invalid')
    else:
        try:
            cmd = subprocess.Popen('gpupdate /%s' % action, shell=True)
            cmd.communicate()
        except:
            print('Error')

def audit_success_or_failure_user():
    print('Audit success or failure for user')
    user = input('User > ')
    category = input('Category > ')
    success = input('Success (enable or disable) > ').lower()
    failure = input('Failure (enable or disable) > ').lower()
    if not user:
        print('\nError!\nUser is invalid')
    elif not category:
        print('\nError!\nCategory is invalid')
    elif success not in ['enable', 'disable']:
        print('\nError!\nSuccess is invalid')
    elif failure not in ['enable', 'disable']:
        print('\nError!\nFailure is invalid')
    else:
        try:
            cmd = subprocess.Popen('auditpol /set /user:%s /category:"%s" /include /success:%s /failure:%s' %
                                   (user, category, success, failure), shell=True)
            cmd.communicate()
        except:
            print('Error!')

def disallow_or_allow_running_exe():
    print('Disallow or allow running a .exe file')
    prompt = input('Disallow or Allow > ').capitalize()
    if prompt not in ['Allow', 'Disallow']:
        print('\nError!\nInput is invalid')
    else:
        try:
            cmd = subprocess.Popen('reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer" /v %sRun /t REG_DWORD /d "00000001" /f' %
                                   prompt, shell=True)
            cmd.communicate()
        except:
            print('Error!')

def disallow_or_allow_running_specific_exe():
    print('Disallow or allow running a specific .exe file')
    file = input('Enter .exe file > ')
    prompt = input('Disallow or Allow > ').capitalize()
    if not file:
        print('\nError!\nFile is invalid')
    elif prompt not in ['Allow', 'Disallow']:
        print('\nError!\nInput is invalid')
    else:
        try:
            cmd = subprocess.Popen('reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\%sRun" /v badfile.exe /t REG_SZ /d "%s".exe /f' %
                                   (prompt, file), shell=True)
            cmd.communicate()
        except:
            print('Error!')

def disable_remote_desktop():
    prompt = input('Disable remote desktop (y/n) > ').lower()
    if prompt == 'y':
        try:
            cmd = subprocess.Popen('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\TerminalServer" /f /v fDenyTSConnections /t REG_DWORD /d 1', shell=True)
            cmd.communicate()
        except:
            print('Error!')
    else:
        print('Skipped')

def send_NTMLv2_response():
    print('Send NTMLv2 response only/refuse LM and NTML')
    prompt = input('Send NTMLv2 only (y/n) > ').lower()
    if prompt == 'y':
        try:
            cmd = subprocess.Popen('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa" /v lmcompatibilitylevel /t REG_DWORD /d 5 /f', shell=True)
            cmd.communicate()
        except:
            print('Error')
    else:
        print('Skipped')

def restrict_anonymouse_access():
    prompt = input('Restrict anonymouse access (y/n) > ').lower()
    if prompt == 'y':
        try:
            cmd = subprocess.Popen('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa" /v restrictanonymous /t REG_DWORD /d 1 /f', shell=True)
            cmd.communicate()
        except:
            print('Error!')
    else:
        print('Skipped')

def do_not_allow_anonymous_SAM():
    prompt = input('Do not allow anonymous enumeration of SAM accounts and shares (y/n) > ').lower()
    if prompt == 'y':
        try:
            cmd = subprocess.Popen('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa" /v restrictanonymoussam /t REG_DWORD /d 1 /f', shell=True)
            cmd.communicate()
        except:
            print('Error!')
    else:
        print('Skipped')

def disable_ipv6():
    prompt = input('Disable ipv6 (y/n) > ').lower()
    if prompt == 'y':
        try:
            cmd = subprocess.Popen('reg add "HKLM\\SYSTEM\\CurrentControlSet\\services\\TCPIP6\\Parameters" /v DisabledComponents /t REG_DWORD /d 255 /f', shell=True)
            cmd.communicate()
        except:
            print('Error!')
    else:
        print('Skipped')

def disable_sticky_keys():
    prompt = input('Disable sticky keys (y/n) > ').lower()
    if prompt == 'y':
        try:
            cmd = subprocess.Popen('reg add "HKCU\\ControlPanel\\Accessibility\\StickyKeys" /v Flags /t REG_SZ /d 506 /f', shell=True)
            cmd.communicate()
        except:
            print('Error!')
    else:
        print('Skipped')

def disable_toggle_keys():
    prompt = input('Disable toggle keys (y/n) > ').lower()
    if prompt == 'y':
        try:
            cmd = subprocess.Popen('reg add "HKCU\\ControlPanel\\ToggleKeys" /v Flags /t REG_SZ /d 58 /f', shell=True)
            cmd.communicate()
        except:
            print('Error!')
    else:
        print('Skipped')

def disable_filter_keys():
    prompt = input('Disable filter keys (y/n) > ').lower()
    if prompt =='y':
        try:
            cmd = subprocess.Popen('reg add "HKCU\\ControlPanel\\Accessibility\\Keyboard Response" /v Flags /t REG_SZ /d 122 /f', shell=True)
            cmd.communicate()
        except:
            print('Error!')
    else:
        print('Skipped')

def disable_onscreen_keyboard():
    prompt = input('Disable on-screen keyboard (y/n) > ').lower()
    if prompt == 'y':
        try:
            cmd = subprocess.Popen('reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\LogonUI" /f /v ShowTabletKeyboard /t REG_DWORD /d 0',
                                   shell=True)
            cmd.communicate()
        except:
            print('Error!')
    else:
        print('Skipped')


def disable_administrative_share_w():
    prompt = input('Disable administrative shares - Workstations (y/n) > ').lower()
    if prompt =='y':
        try:
            cmd = subprocess.Popen('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters" /f /v AutoShareWks /t REG_DWORD /d 0',
                                   shell=True)
            cmd.communicate()
        except:
            print('Error!')
    else:
        print('Skipped')

def disable_administrative_share_s():
    prompt = input('Disable administrative share - Servers (y/n) > ').lower()
    if prompt == 'y':
        try:
            cmd = subprocess.Popen('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters" /f /v AutoShareServer /t REG_DWORD /d 0',
                                   shell=True)
            cmd.communicate()
        except:
            print('Error!')
    else:
        print('Skipped')

def remove_creation_of_hashes():
    print('Remove creation of hashes used to pass the hash attack,')
    print('requires password reset and reboot to purge old hashes')
    prompt = input('Remove creation of hashes (y/n) > ').lower()
    if prompt == 'y':
        try:
            cmd = subprocess.Popen('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa" /f /v NoLMHash /t REG_DWORD /d 1',
                                   shell=True)
            cmd.communicate()
        except:
            print('Error!')
    else:
        print('Skipped')

def disble_registry_editor():
    print('Disable registry editor - High risk')
    prompt = input('Disable registry editor (y/n) > ').lower()
    if prompt == 'y':
        try:
            cmd = subprocess.Popen('reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v DisableRegistryTools /t REG_DWORD /d 1 /f',
                                   shell=True)
            cmd.communicate()
        except:
            print('Error!')
    else:
        print('Skipped')

def disbale_ie_password_caching():
    prompt = input('Disable IE password caching (y/n) > ').lower()
    if prompt == 'y':
        try:
            cmd = subprocess.Popen('reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" /v DisablePasswordCaching /t REG_DWORD /d 1 /f',
                                   shell=True)
            cmd.communicate()
        except:
            print('Error!')
    else:
        print('Skipped')

def disbale_cmd():
    prompt = input('Disable CMD prompt (y/n) > ').lower()
    if prompt == 'y':
        try:
            cmd = subprocess.Popen('reg "HKCU\\Software\\Policies\\Microsoft\\Windows\\System" /v DisableCMD /t REG_DWORD /d 1 /f',
                                   shell=True)
            cmd.communicate()
        except:
            print('Error!')
    else:
        print('Skipped')

def disable_admin_credentials_cache():
    print('Disable Admin credentials cache on host when using RDP')
    prompt = input('Disable admin credentials cache (y/n) > ').lower()
    if prompt == 'y':
        try:
            cmd = subprocess.Popen('reg add "HKLM\\System\\CurrentControlSet\\Control\\Lsa" /DisableRestrictedAdmin /t REG_DWORD /d 0 /f',
                                   shell=True)
            cmd.communicate()
        except:
            print('Error!')
    else:
        print('Skipped')

def do_not_process_run_once_list():
    prompt = input('Do not process run once list (y/n) > ').lower()
    if prompt == 'y':
        try:
            cmd = subprocess.Popen('reg add "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer" /v DisableLocalMachineRunOnce /t REG_DWORD /d 1 /f',
                                   shell=True)
            cmd.communicate()
            cmd1 = subprocess.Popen('reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer" /v DisableLocalMachineRunOnce /t REG_DWORD /d 1 /f',
                              shell=True)
            cmd1.communicate()
        except:
            print('Error!')
    else:
        print('Skipped')

def require_user_access_control_permission():
    prompt = input('Require User Access Control (UAC) Permission (y/n) > ').lower()
    if prompt == 'y':
        try:
            cmd = subprocess.Popen('reg add "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v EnableLUA /t REG_DWORD /d 1 /f',
                                   shell=True)
            cmd.communicate()
        except:
            print('Error!')
    else:
        print('Skipped')


print('commands - to list available commands')
while True:
    user_input = input('\n__Select:__ ')
    if user_input == '1':
        hashfile()
    elif user_input == '2':
        listservices()
    elif user_input == '3':
        stopservices()
    elif user_input == '4':
        disableservice()
    elif user_input == '5':
        showfirewallrule()
    elif user_input == '6':
        profile_firewall_OFF_ON()
    elif user_input == '7':
        profile_firewall_inboud_outbound()
    elif user_input == '8':
        set_port_firewall_rule()
    elif user_input == '9':
        set_program_firewall_rule()
    elif user_input == '10':
        set_program_remoteip_firewall_rule()
    elif user_input == '11':
        set_group_firewall_rule()
    elif user_input == '12':
        set_service_firewall_rule()
    elif user_input == '13':
        delete_firewall_rule()
    elif user_input == '14':
        set_firewall_logging_location()
    elif user_input == '15':
        set_firewall_logging_settings()
    elif user_input == '16':
        show_users()
    elif user_input == '17':
        change_password()
    elif user_input == '18':
        flush_dns()
    elif user_input == '19':
        flush_netbios()
    elif user_input == '20':
        create_ipsec_filterlist_or_add()
    elif user_input == '21':
        ipsec_filter_action()
    elif user_input == '22':
        ipsec_policy()
    elif user_input == '23':
        ipsec_rule()
    elif user_input == '24':
        show_ipsecs()
    elif user_input == '25':
        unassign_ipsec()
    elif user_input == '26':
        delete_ipsec()
    elif user_input == '27':
        get_and_force_new_policy()
    elif user_input == '28':
        audit_success_or_failure_user()
    elif user_input == '29':
        disallow_or_allow_running_exe()
    elif user_input == '30':
        disallow_or_allow_running_specific_exe()
    elif user_input == '31':
        disable_remote_desktop()
    elif user_input == '32':
        send_NTMLv2_response()
    elif user_input == '33':
        restrict_anonymouse_access()
    elif user_input == '34':
        do_not_allow_anonymous_SAM()
    elif user_input == '35':
        disable_ipv6()
    elif user_input == '36':
        disable_sticky_keys()
    elif user_input == '37':
        disable_toggle_keys()
    elif user_input == '38':
        disable_filter_keys()
    elif user_input == '39':
        disable_onscreen_keyboard()
    elif user_input == '40':
        disable_administrative_share_w()
    elif user_input == '41':
        disable_administrative_share_s()
    elif user_input == '42':
        remove_creation_of_hashes()
    elif user_input == '43':
        disble_registry_editor()
    elif user_input == '44':
        disbale_ie_password_caching()
    elif user_input == '45':
        disbale_cmd()
    elif user_input == '46':
        disable_admin_credentials_cache()
    elif user_input == '47':
        do_not_process_run_once_list()
    elif user_input == '48':
        require_user_access_control_permission()
    elif user_input == 'commands':
        commands()
    elif user_input in ['49', 'Back', 'back']:
        sys.exit(1)
    else:
        print('You\'re drunk')