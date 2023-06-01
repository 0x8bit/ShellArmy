import sys

while True:
    print('\nSelect category')
    print("""
    [1] Linux Defend
    [2] Linux Respond
    [3] Linx Monitor
    [4] Back""")
    user_input = input('__Select:__  ')

    if user_input == '1':
        while True:
            try:
                from linux import lin_defend
            except SystemExit:
                break
    elif user_input == '2':
        while True:
            try:
                from linux import lin_respond
            except SystemExit:
                break
    elif user_input == '3':
        while True:
            try:
                from linux import lin_analysis
            except SystemExit:
                break
    elif user_input in ['4', 'back', 'Back']:
        sys.exit()
