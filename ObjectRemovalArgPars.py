from Config import *
import argparse
import os

cwd = os.getcwd()

parser = argparse.ArgumentParser(prog='PROG', formatter_class=argparse.RawDescriptionHelpFormatter, description="""
Welcome to Object deletion script :
With this script you can remove objects from firewall

================================ Notes ================================

1-For --list option : give the exact path to your txt file
(Example : C:\Documents\yourfile.txt)
if you dont specify the path, it uses the objects.txt file in current directory

2-For --object option : enter the object name that you want to be removed from
firewalls (Example : C_1.1.1.1 or S_1.1.1.1 or 1.1.1.1)

3-This Script creates text config files for each firewall in current directory
you should copy and pate the configs to your device terminal

================================ Notes ================================
""")

parser.add_argument('-o', '--object', type=str, metavar='',help='delete single object (Ex C_1.1.1.1)')
parser.add_argument('-l', '--list', type=str, metavar='', nargs='?', const=str(cwd)+'\objects.txt', help='Path to list of objects (Ex C:\Documents\objects.txt)')
args = parser.parse_args()

if args.object:
    singleObject(args.object)

if args.list:
    listObject(args.list)
