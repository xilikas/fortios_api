"""
View and edit firewall policies, as well as including an interface to use firewall iprope lookup
"""

import requests 
# Disable InsecureRequestWarning
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import os
from dotenv import load_dotenv

load_dotenv()
key = os.getenv('API_KEY')

uri: str = f'https://firewall.xilikas:4443/api/v2/cmdb/firewall/policy'

def print_attr(id, name, srcintf, dstintf, srcaddr, dstaddr, service, action):
    print(f'Policy ID: {id}')
    print(f'Name: {name}')
    print(f'Interface: {srcintf} -> {dstintf}')
    print(f'Address: {srcaddr} -> {dstaddr}')
    print(f'Service: {service}')
    print(f'Action: {action}')

def view_policies(arg_id = 0):
    """
    Views all or one firewall policy

    Parameters:
    optional arg_id (int): policy id for a specific policy

    Returns: 
    prints commonly viewed attributes of a policy
    """

    if arg_id == 0:
        url = f'{uri}?access_token={key}'
        response = requests.get(url, verify=False)
        policies = response.json()['results']
        counter = 0
        for policy in policies:
            id = policies[counter]['policyid']
            name = policies[counter]['name']
            srcintf = policies[counter]['srcintf'][0]['name']
            dstintf = policies[counter]['dstintf'][0]['name']
            srcaddr = policies[counter]['srcaddr'][0]['name']
            dstaddr = policies[counter]['dstaddr'][0]['name']
            service = policies[counter]['service'][0]['name']
            action = policies[counter]['action']

            print_attr(id, name, srcintf, dstintf, srcaddr, dstaddr, service, action)

            counter += 1
    else:
        url = f'{uri}/{arg_id}?access_token={key}'
        response = requests.get(url, verify=False)
        if response.json()['http_status'] == 200:
            policy = response.json()['results']
            id = policy[0]['policyid']
            name = policy[0]['name']
            srcintf = policy[0]['srcintf'][0]['name']
            dstintf = policy[0]['dstintf'][0]['name']
            srcaddr = policy[0]['srcaddr'][0]['name']
            dstaddr = policy[0]['dstaddr'][0]['name']
            service = policy[0]['service'][0]['name']
            action = policy[0]['action']

            print_attr(id, name, srcintf, dstintf, srcaddr, dstaddr, service, action)
            
        else:
            print('Policy ID does not exist.')

def edit_policy(arg_name: str , arg_srcintf: str, arg_dstintf: str, arg_srcaddr: str, arg_dstaddr: str, arg_service: str, arg_action: str, arg_id: int = 0):
    """
    Creates or edits a firewall policy if the policy ID is provided

    Parameters:
    arg_name: str : Name of the policy
    arg_srcintf: str : Source interface
    arg_dstintf: str : Destination interface 
    arg_srcaddr: str : Source address
    arg_dstaddr: str : Destination address
    arg_service: str : Services (ports)
    arg_action: str : Accept or Deny
    arg_id: int = 0 : Policy ID, blank if creating a new policy

    Returns: 
    Policy ID and attributes
    """

    # if policy ID = 0, create a dictionary with the new information and pass it through. 
    url = f'{uri}/?access_token={key}'
    data = {
        "name": arg_name,
        "srcintf": [
            {
                "name": arg_srcintf
            }
        ], 
        "dstintf": [
            {
                "name": arg_dstintf
            }
        ], 
        "srcaddr": [
            {
                "name": arg_srcaddr
            }
        ], 
        "dstaddr": [
            {
                "name": arg_dstaddr
            }
        ], 
        "srcintf": [
            {
                "name": arg_srcintf
            }
        ], 
        "service": [
        {
            "name": "ALL"
        }
        ],
        "action": arg_action,
        "schedule": "always"
    }

    response = requests.post(url, json=data, verify=False)

    if response.json()['http_status'] == 200:
        print("Success")
        print_attr(response.json()['mkey'], arg_name, arg_srcintf, arg_dstintf, arg_srcaddr, arg_dstaddr, arg_service, arg_action)
    else:
        print("Operation failed")
        print(response.json()['cli_error'])


print ('All policies:')
view_policies()
print ('Only one policy (e.g. 3):')
view_policies(3)
print ('Error message for when policy ID does not exist:')
view_policies(5)
print ('New policy:')
edit_policy("testpolicy", "Trust", "Untrust", "all", "all", "ALL", "accept")