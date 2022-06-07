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

def view_policies(arg_id = 0):
    """
    Views all or one firewall policy

    Parameters:
    optional arg_id (int): policy id for a specific policy

    Returns: 
    prints commonly viewed attributes of a policy
    """

    if arg_id == 0:
        url = f'http://firewall.xilikas/api/v2/cmdb/firewall/policy?access_token={key}'
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

            print(f'Policy ID: {id}')
            print(f'Name: {name}')
            print(f'Interface: {srcintf} -> {dstintf}')
            print(f'Address: {srcaddr} -> {dstaddr}')
            print(f'Service: {service}')
            print(f'Action: {action}')

            counter += 1
    else:
        url = f'http://firewall.xilikas/api/v2/cmdb/firewall/policy/{arg_id}?access_token={key}'
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

            print(f'Policy ID: {id}')
            print(f'Name: {name}')
            print(f'Interface: {srcintf} -> {dstintf}')
            print(f'Address: {srcaddr} -> {dstaddr}')
            print(f'Service: {service}')
            print(f'Action: {action}')
            
        else:
            print('Policy ID does not exist.')

print ('All policies:')
view_policies()
print ('Only one policy (e.g. 3):')
view_policies(3)
print ('Error message for when policy ID does not exist:')
view_policies(5)