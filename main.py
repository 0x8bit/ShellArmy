#! /usr/bin/python3

print('\n\t\t#################################################################')
print('\t\t#                                                               #')
print('\t\t#                          Shell_Army                           #')
print('\t\t#                                                               #')
print('\t\t#             Author:     0x8bit                                #')
print('\t\t#             Reference:  Red and blue team field manual        #')
print('\t\t#                                                               #')
print('\t\t#                                                               #')
print('\t\t#################################################################\n')

if __name__ == '__main__':
    while True:
        print('\n**Switch Platform**')
        print("""
        [1] Linux
        [2] Windows
        [3] Quit
        """)
        user_input = input('__Choose your weapon >__ ')
        if user_input == '1':
            while True:
                    try:
                        from ShellArmy.linux import lin_main
                    except SystemExit:
                        break
        elif user_input == '2':
            while True:
                try:
                    from ShellArmy.windows import win_main
                except SystemExit:
                    break
        elif user_input in ['quit', 'Quit', '3', 'exit', 'Exit']:
            break
        else:
            print("You're Drunk!")
