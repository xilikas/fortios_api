"""
View and edit firewall addresses. For now will only allow for IP addresses.
"""

import requests 
# Disable InsecureRequestWarning
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import os
from dotenv import load_dotenv

load_dotenv()
key = os.getenv('API_KEY')

uri: str = f'https://firewall.xilikas:4443/api/v2/cmdb/firewall/address'

def print_attr(name: str, subnet: str, interface: str):
    print(f'Name: {name}')
    print(f'Subnet: {subnet}')
    if interface == "": 
        print("Interface: none specified")
    else:
        print(f'Interface: {interface}')

def view_address(arg_name: str):
    """
    Views the attributes of an address if it exists

    Parameters:

    arg_name: str: Address name

    Returns: 

    Subnet and interface if the address name exists
    """

    url = f'{uri}/{arg_name}?access_token={key}'
    response = requests.get(url, verify=False).json()['results'][0]
    print_attr(response['name'], response['subnet'], response['associated-interface'])

def edit_address(arg_name: str, arg_subnet: str, arg_interface: str = ""):
    """
    Adds an IP address 

    Parameters:

    arg_name: str: Address name

    arg_subnet: str: Subnet mask. Does not support CIDR notation.

    arg_interface: str = "": Associated interface for that subnet

    Returns:
    
    Address atrributes
    """

    data = {
        "name": arg_name,
        "subnet": arg_subnet,
        "associated-interface": arg_interface
    }

    # Check if the name already exists 
    url = f'{uri}/{arg_name}?access_token={key}'
    response = requests.get(url, verify=False).json()
    if response['http_status'] == 404:
        # Does not exist, so make a new address object 
        url = f'{uri}?access_token={key}'
        response = requests.post(url, json=data, verify=False).json()
    else:
        # Does exist, edit current address object
        url = f'{uri}/{arg_name}?access_token={key}'
        response = requests.put(url, json=data, verify=False).json()
    
    if response['http_status'] == 200:
        print("Success")
        print_attr(response['mkey'], arg_subnet, arg_interface)
    else:
        print("Operation failed")
        print(response['cli_error'])

# Tests
print('View address object for "Class A":')
view_address('Class A')
print('Create an address object:')
edit_address('testaddressagain', '10.0.0.0 255.0.0.0', 'Trust')
print('Edit "testaddressagain":')
edit_address('testaddressagain', '10.10.0.0 255.0.0.0', '')