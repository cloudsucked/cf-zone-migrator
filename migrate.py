import json
import os
import click
import CloudFlare
import click
import requests


def main():
    ''' 
    This program migrates settings from one zone to another.
    Follow below link to see how to configure credentials...
    https://github.com/cloudflare/python-cloudflare#providing-cloudflare-username-and-api-key
    '''
    cf = CloudFlare.CloudFlare(profile="admin")
    zone_list = cf.zones.get()

    ''' Create objects for source and destination zones '''
    src_zone_dict = select_zone("Source zone: ", zone_list)
    id = src_zone_dict['id']
    message = "Destination zone: "
    while id == src_zone_dict['id']:
        dst_zone_dict = select_zone(message, zone_list)
        id = dst_zone_dict['id']
        if id == src_zone_dict['id']: 
            message = "Source and destination can't be the same! Destination zone: "
    # print(json.dumps(src_zone_dict, indent=2))
    # print(json.dumps(dst_zone_dict, indent=2))

    clear()
    if input("Delete all DNS records from Destination zone? <y/N>: ").lower() in ['y', 'yes']:
        delete_dns_records(cf, dst_zone_dict)
    else:
        print("Not deleting DNS records...")

    if input("Copy DNS? <y/N>: ").lower() in ['y', 'yes']:
        copy_dns_records(cf, src_zone_dict, dst_zone_dict)
    else:
        print("Not copying DNS records...")

    if input("Copy Page Rules? <y/N>: ").lower() in ['y', 'yes']:
        copy_page_rules(cf, src_zone_dict, dst_zone_dict)
    else:
        print("Not copying page rules...")

    if input("Copy Firewall Rules? <y/N>: ").lower() in ['y', 'yes']:
        delete_filters(cf, dst_zone_dict)
        copy_firewall_rules(cf, src_zone_dict, dst_zone_dict)
    else:
        print("Not copying firewall rules...")

    return


def delete_dns_records(cf, dst_zone_dict):
    ''' Delete all DNS records from Destination Zone '''
    dns_record_list = cf.zones.dns_records.get(dst_zone_dict['id'])
    clear()
    for dns_record in dns_record_list:
        delete_result = cf.zones.dns_records.delete(dst_zone_dict['id'], dns_record['id'])
        print("Deleted: {}".format(delete_result))
    return 


def delete_filters(cf, dst_zone_dict):
    ''' Delete filters from Destination Zone '''
    filter_list = cf.zones.filters.get(dst_zone_dict['id'])
    clear()
    for filter in filter_list:
        delete_result = cf.zones.filters.delete(dst_zone_dict['id'], filter['id'])
        print("Deleted: {}".format(delete_result))
    return 


def copy_firewall_rules(cf, src_zone_dict, dst_zone_dict):
    ''' Copy firewall rules from Source Zone to Destination Zone '''
    firewall_rules_list = cf.zones.firewall.rules.get(src_zone_dict['id'])
    clear()
    target_filter_list = []
    for firewall_rule in firewall_rules_list:
        if src_zone_dict['name'] in firewall_rule['filter']['expression']:
            firewall_rule['filter']['expression'] = firewall_rule['filter']['expression'].replace(src_zone_dict['name'], dst_zone_dict['name'])
        target_filter_list.append(firewall_rule['filter'])
    filter_result = cf.zones.filters.post(dst_zone_dict['id'], data=target_filter_list)
    # print(json.dumps(filter_result, indent=2))
        
    target_firewall_rule_list = []
    for firewall_rule in firewall_rules_list:
        for filter in filter_result:
            if firewall_rule['filter']['expression'] == filter['expression']:
                new_rule = firewall_rule
                new_rule['filter']['id'] = filter['id']
                target_firewall_rule_list.append(new_rule)
    # print(target_firewall_rule_list)

    firewall_result = cf.zones.firewall.rules.post(dst_zone_dict['id'], data=target_firewall_rule_list)
    for rule in firewall_result:
        print("Created Rule - Id: {}  Description: {}".format(rule['id'], rule['description']))

    return


def copy_page_rules(cf, src_zone_dict, dst_zone_dict):
    ''' Copy page rules from Source Zone to Destination Zone '''
    page_rules_list = cf.zones.pagerules.get(src_zone_dict['id'])
    clear()
    for pagerule in page_rules_list:
        print("SRC: " + pagerule['targets'][0]['constraint']['value'])
        if src_zone_dict['name'] in pagerule['targets'][0]['constraint']['value']:
            pagerule['targets'][0]['constraint']['value'] = pagerule['targets'][0]['constraint']['value'].replace(src_zone_dict['name'], dst_zone_dict['name'])
        newrule = {"targets":pagerule['targets'],"actions":pagerule['actions'],"priority":pagerule['priority'],"status":pagerule['status']}
        result = cf.zones.pagerules.post(dst_zone_dict['id'], data=newrule)
        print("DST: " + pagerule['targets'][0]['constraint']['value'] + "\n")
    # print(json.dumps(page_rules_list, indent=2))
    return 


def copy_dns_records(cf, src_zone_dict, dst_zone_dict):
    ''' Copy DNS records from Source Zone to Destination Zone '''
    dns_record_list = cf.zones.dns_records.get(src_zone_dict['id'])
    clear()
    for dns_record in dns_record_list:
        print("SRC: " + dns_record['type'] + (8 - len(dns_record['type'])) * " " + dns_record['name'] + "    " + dns_record['content'])
        if src_zone_dict['name'] in dns_record['name']:
            dns_record['name'] = dns_record['name'].replace(src_zone_dict['name'], dst_zone_dict['name'])
        if src_zone_dict['name'] in dns_record['content']:
            dns_record['content'] = dns_record['content'].replace(src_zone_dict['name'], dst_zone_dict['name'])
        result = cf.zones.dns_records.post(dst_zone_dict['id'], data=dns_record)
        print("DST: " + dns_record['type'] + (8 - len(dns_record['type'])) * " " + dns_record['name'] + "    " + dns_record['content'] + "\n")
    # print(json.dumps(dns_record_list, indent=2))
    return 


def select_zone(message, zone_list):
    '''
    Interactive function that lists all zones and returns the selected zone object.
    '''
    zone_selection = 0
    while not ((zone_selection <= len(zone_list)) and (zone_selection > 0)):
        print_zones(zone_list)
        i = input(message)
        try:
            zone_selection = int(i)
        except ValueError:
            message = "Try a number between 1 and " + str(len(zone_list)) + ": "
    return (zone_list[zone_selection - 1])
   

def print_zones(zone_list):
    clear()
    print("Zones:")
    for zone in zone_list:
        print(str(zone_list.index(zone) + 1) + ". " + zone['name'])
    return
   

def clear(): 
    if os.name == 'nt': 
        _ = os.system('cls') 
    else: 
        _ = os.system('clear') 


def sanity(x):
    return x + 1


def test_sanity():
    assert sanity(3) == 4


if __name__ == "__main__":
    main()
