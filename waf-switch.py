import argparse
import json
import os
import requests
import time


def main():
    headers = set_auth_headers()

    zone = select_from_list("Please select Zone: ", get_zone_list(headers), "Zones", "name")
    fw_package = select_from_list("Please select Firewall Rules Package: ", get_fw_package_list(headers, zone['id']), "Firewall Rules Packages", "name")
    clear()
    if input("Do you want to select all Firewall Groups for this Package? (y/N): ").lower() == "y":
        fw_group = {"name": "ALL"}
    else:
        fw_group = select_from_list("Please select Firewall Group: ", get_fw_group_list(headers, zone['id'], fw_package['id']), "Firewall Groups", "name")

    user_choice = ""
    while user_choice.lower() != "x":
        clear()
        print_selection(zone, fw_package, fw_group)
        user_choice = input("\n\nMain Menu:\n[L]ist Rules, Set Rules to [S]imulate, Set Rules to [D]efault | WAF [O]verride Menu | E[x]it: ")
        if user_choice.lower() == "l":
            clear()
            fw_rules = get_fw_rules_list(headers, zone, fw_package, fw_group)
            for fw_rule in fw_rules:
                print("ID:{}  MODE: {}  DESC: {}".format(fw_rule['id'],fw_rule['mode'],fw_rule['description']))
            print("{} rules listed".format(len(fw_rules)))
            input("Press any key to continue...")
        elif user_choice.lower() == "s":
            set_fw_rules_mode(headers, zone, fw_package, fw_group, "simulate")
        elif user_choice.lower() == "d":
            set_fw_rules_mode(headers, zone, fw_package, fw_group, "default")
        elif user_choice.lower() == "o":
            waf_override_menu(headers, zone, fw_group, fw_package)
    return


def set_fw_rules_mode(headers, zone, fw_package, fw_group, mode):
    clear()
    for fw_rule in get_fw_rules_list(headers, zone, fw_package, fw_group):
        url = "https://api.cloudflare.com/client/v4/zones/" + zone['id'] + "/firewall/waf/packages/" + fw_package['id'] + "/rules/" + fw_rule['id']
        body = {
            "mode":mode
        }
        result = requests.patch(url=url, headers=headers, data=json.dumps(body))
        time.sleep(.02)
        if json.loads(result.text)['success']:
            message = "success"
        else:
            message = json.loads(result.text)['errors'][0]['message']
        print("{} --> simulate mode... {}".format(fw_rule['id'], message))
    input("Press any key to continue...")
    return 


def get_fw_rules_list(headers, zone, fw_package, fw_group):
    firewall_rules = []
    url = "https://api.cloudflare.com/client/v4/zones/" + zone['id'] + "/firewall/waf/packages/" + fw_package['id'] + "/rules/?per_page=100"
    if fw_group['name'] != "ALL":
        url = url + "&group_id=" + fw_group['id']
    result = requests.get(url=url, headers=headers)
    result_info = json.loads(result.text)['result_info']
    firewall_rules = json.loads(result.text)['result']
    for i in range(1,result_info['total_pages']+1):
        page_url = url + "&page=" + str(i + 1)
        result = requests.get(url=page_url, headers=headers)
        firewall_rules += json.loads(result.text)['result']
    return firewall_rules


def waf_override_menu(headers, zone, fw_group, fw_package):
    user_choice = "l"
    waf_override = ""

    while user_choice.lower() != "x":
        waf_overrides_list = get_waf_overrides_list(headers, zone['id'])
        if user_choice.lower() == "l":
            clear()
            print("WAF Overrides for {} Firewall Group".format(fw_group['name']))
            for w in waf_overrides_list:
                if (fw_group['name'] == "ALL") or (fw_group['id'] in w['groups'].keys()):
                    print("  - " + str(w))
                else:
                    waf_overrides_list.remove(w)
            input("Press any key to continue: ")
        elif user_choice.lower() == "s":
            if len(waf_overrides_list) > 0:
                waf_override = select_from_list("Please select Firewall WAF Override: ", waf_overrides_list, "Firewall WAF Overrides", "description")
            else:
                input("There are no WAF Overrides...")
        elif user_choice.lower() == "c":
            clear()
            waf_override_description = input("WAF Override description: ")
            waf_override_url_input = input("URLs, separated by comma (,): ")
            waf_override_url_list = waf_override_url_input.split(",")
            create_waf_override(headers, zone, fw_group, fw_package, waf_override_description, waf_override_url_list)
        elif user_choice.lower() == "d":
            if waf_override != "":
                result = delete_waf_override(headers, zone['id'], fw_package['id'], waf_override)
                waf_override = ""
                input(result)
            else:
                print("Select a WAF Override first...")
        
        print_selection(zone, fw_package, fw_group, waf_override)
        user_choice = input("\n\nWAF Override:\n[L]ist, [S]elect, [C]reate, [D]elete | or E[x]it: ")
        # end of while loop

    return


def delete_waf_override(headers, zone_id, fw_package_id, waf_override):
    url = "https://api.cloudflare.com/client/v4/zones/" + zone_id + "/firewall/waf/overrides/" + waf_override['id']
    result = requests.delete(url=url, headers=headers)
    return json.loads(result.text)


def create_waf_override(headers, zone, fw_group, fw_package, waf_override_description, waf_override_url_list):
    url = "https://api.cloudflare.com/client/v4/zones/" + zone['id'] + "/firewall/waf/overrides"
    if (fw_group['name'] == "ALL"):
        groups = {}
        for group in get_fw_group_list(headers, zone['id'], fw_package['id']):
            groups[group['id']] = "disable"
    else:
        groups = { fw_group['id']: "disable" }
    body = {
        "description": waf_override_description,
        "urls": waf_override_url_list,
        "priority": 1,
        "groups": groups
    }
    result = requests.post(url=url, headers=headers, data=json.dumps(body))
    return json.loads(result.text)['result']


def get_waf_overrides_list(headers, zone_id):
    url = "https://api.cloudflare.com/client/v4/zones/" + zone_id + "/firewall/waf/overrides"
    result = requests.get(url=url, headers=headers)
    return json.loads(result.text)['result']


def get_fw_group_list(headers, zone_id, fw_package_id):
    url = "https://api.cloudflare.com/client/v4/zones/" + zone_id + "/firewall/waf/packages/" + fw_package_id + "/groups"
    result = requests.get(url=url, headers=headers)
    return json.loads(result.text)['result']


def get_fw_package_list(headers, zone_id):
    url = "https://api.cloudflare.com/client/v4/zones/" + zone_id + "/firewall/waf/packages"
    result = requests.get(url=url, headers=headers)
    return json.loads(result.text)['result']


def get_zone_list(headers):
    url = "https://api.cloudflare.com/client/v4/zones/"
    result = requests.get(url=url, headers=headers)
    return json.loads(result.text)['result']


def select_from_list(message, selection_list, item_desc, display_field):
    '''
    Interactive function that lists all _ and returns the selected _ object.
    '''
    selection_item = 0
    clear()
    while not ((selection_item <= len(selection_list)) and (selection_item > 0)):
        print_items(selection_list, item_desc, display_field)
        i = input(message)
        try:
            selection_item = int(i)
        except ValueError:
            message = "Try a number between 1 and " + \
                str(len(selection_list)) + ": "
    return (selection_list[selection_item - 1])


def print_items(item_list, item_desc, display_field):
    clear()
    print(item_desc)
    for item in item_list:
        print(str(item_list.index(item) + 1) + ". " + item[display_field])
    return


def print_selection(zone, fw_package, fw_group, waf_override=""):
    clear()
    print("Selected Zone: {} - {}".format(zone['name'], zone['id']))
    print("Selected FW Rules Package: {} - {}".format(fw_package['name'], fw_package['id']))
    try:
        test = fw_group['id']
        print("Selected FW Group: {} - {}".format(fw_group['name'], fw_group['id']))
    except:
        print("Selected FW Group: {}".format(fw_group['name']))
    if waf_override:
        print("Selected WAF Override: {} - {}".format(waf_override['description'], waf_override['id']))
    return


def clear():
    if os.name == 'nt':
        _ = os.system('cls')
    else:
        _ = os.system('clear')
    return


def set_auth_headers():
    try:
        headers = {
            "X-Auth-Email": os.environ['CF_API_EMAIL'],
            "X-Auth-Key": os.environ['CF_API_KEY'],
            "Content-Type": "application/json"
            }
    except KeyError:
        print('You need to set your API key and email address as environment variables')
        exit(1)
    return headers


if __name__ == "__main__":
    main()
