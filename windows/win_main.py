import sys

while True:
    print('\nSelect category')
    print("""
    [1] Windows Defend
    [2] Windows Analysis
    [3] Windows Log Auditing
    [4] Back""")
    user_input = input('\n__Select:__ ')

    if user_input == '1':
        while True:
            try:
                from ShellArmy.windows import win_defend
            except SystemExit:
                break
    elif user_input == '2':
        while True:
            try:
                from ShellArmy.windows import win_analysis
            except SystemExit:
                break
    elif user_input == '3':
        while True:
            try:
                from ShellArmy.windows import win_log_auditing
            except SystemExit:
                break
    elif user_input in ['4', 'back', 'Back']:
        sys.exit()
