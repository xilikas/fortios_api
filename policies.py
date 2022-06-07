"""
View and edit firewall policies, as well as including an interface to use firewall iprope lookup
"""

import requests 
import os
from dotenv import load_dotenv

load_dotenv()

key = os.getenv('API_KEY')
url = f'http://firewall.xilikas/api/v2/cmdb/firewall/policy?access_token={key}' 

response = requests.get(url, verify=False)
policies = response.json()['results']

def view_policies(arg_id = 0):
    """
    Views all or one firewall policy

    Parameters:
    optional arg_id (int): policy id for a specific policy

    Returns: 
    prints commonly viewed attributes of a policy

    Todo: 
    Add optional parameter, iterate through all policies
    """

    counter = 0

    for policy in policies: 
        if arg_id == 0: 
            # if arg_id == 0, iterate through all policies and list them 
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
            # if arg_id != 0, iterate through all policies until policy id == arg_id, then display that policy only
            if arg_id == policies[counter]['policyid']:
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

                break
            
            counter += 1

print ('All policies:')
view_policies()
print ('Only one policy (e.g. 3):')
view_policies(3)
