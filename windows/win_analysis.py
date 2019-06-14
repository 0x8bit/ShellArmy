#! /usr/bin/python3

import os, sys
import subprocess

print('\n\t\t\t+++++++++++++++++++++++++')
print('\t\t         Windows Analysis     ')
print('\t\t\t+++++++++++++++++++++++++\n')

def execute(command):
    try:
        cmd = subprocess.Popen(command,  shell=True)
        result = cmd.communicate()
        return result
    except:
        print('Error!')

def commands():
    print("""
    [01] System Info
    [02] Product Name
    [03] Bios Serial NUmber
    [04] List brief computer info
    [05] Show user
    [06] Show net localgroup administrators
    [07] Show domain group administrators
    [08] Get full user account list info
    [09] Get full group list info
    [10] Get full user login info
    [11] Get client info
    [12] Get commands history
    [13] Back

    """)



def system_info():
    show = input('Show system info (y/n) > ').lower()
    if show == 'y':
        execute('systeminfo')
    else:
        print('Skipped')

def product_name():
    show = input('Show product name (y/n) > ').lower()
    if show == 'y':
        execute('wmic csproduct get name')
    else:
        print('Skipped')

def bios_serial_number():
    show = input('Show bios serial number (y/n) > ').lower()
    if show == 'y':
        execute('wmic bios get serialnumber')
    else:
        print('Skipped')

def list_brief_computerinfo():
    show = input('List computer system brief info (y/n) > ').lower()
    if show == 'y':
        execute('wmic computersystem list brief')
    else:
        print('Skipped')

def whoami():
    show = input('Who am i (y/n) > ').lower()
    if show == 'y':
        execute('hostname')
    else:
        print('Skipped')

def net_localgroup_administrators():
    show = input('Show net localgroup administrators (y/n) > ').lower()
    if show == 'y':
        execute('net localgroup administrators')
    else:
        print('Skipped')

def net_domaingroup_administrators():
    show = input('Show domain group administrators (y/n) > ').lower()
    if show == 'y':
        execute('net group administrators')
    else:
        print('Skipped')

def full_user_list():
    show = input('Get full user account list info (y/n) > ').lower()
    if show == 'y':
        execute('wmic useraccount list')
    else:
        print('Skipped')

def full_group_list():
    show = input('Get full group list info (y/n) > ').lower()
    if show == 'y':
        execute('wmic group list')
    else:
        print('Skipped')

def get_login_info_info():
    show = input('Get full user login info (y/n) > ').lower()

    if show == 'y':
        execute('wmic netlogin get name, lastlogon, badpasswordcount')
    else:
        print('Skipped')

def client_info():
    show = input('Get client info (y/n) > ').lower()
    if show == 'y':
        execute('wmic netclient list brief')
    else:
        print('Skipped')

def cmd_history():
    show = input('Get commands history (y/n) > ').lower()

    if show == 'y':
        saveto = os.path.normpath(input('Save output to file (e.g ./blabla/history.txt or skip if none) > '))
        fullpath = os.path.join(os.path.split(saveto)[0], os.path.split(saveto)[1])
        if not os.path.exists(os.path.split(saveto)[0]):
           print('Directory does not exist')
           os.mkdir(os.path.split(saveto)[0])
           print('Directory created')
        try:
            if execute('doskey /history' + (' > ' + fullpath)):
                print('Done!')
        except:
            print('Error!')
        
    else:
        print('Skipped')

print('commands - to list available commands')

while True:
    user_input = input('\n__Select >___ ')
    if user_input == '1':
        system_info()
    elif user_input == '2':
        product_name()
    elif user_input == '3':
       bios_serial_number()
    elif user_input == '4':
        list_brief_computerinfo()
    elif user_input == '5':
        whoami()
    elif user_input == '6':
        net_localgroup_administrators()
    elif user_input == '7':
        net_domaingroup_administrators()
    elif user_input == '8':
        full_user_list()
    elif user_input == '9':
        full_group_list()
    elif user_input == '10':
        get_login_info_info()
    elif user_input == '11':
        client_info()
    elif user_input == '12':
        cmd_history()
    elif user_input == 'commands':
        commands()
    elif user_input in ['13', 'back', 'Back']:
        sys.exit(1)
