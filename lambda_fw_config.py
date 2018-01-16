from pandevice import firewall
from pandevice import policies
from pandevice import objects

import json
import logging

logging.basicConfig(level=8)

def handle_gd_threat_intel(event, context):

    l_event = None
    print("Received event: " + json.dumps(event, indent=2))
    print("Event type: {}".format(type(event)))
    if isinstance(event, (list, tuple)):
        l_event = event[0]
        print("Extracted time from list: {}".format(l_event))
    else:
        l_event = event
        print("Dict: Event details: {}".format(event))

    print("GuardDuty value = ")
    print(l_event['detail'])
    data = l_event['detail']
    print("Event details extracted: {}".format(data))
    service = data.get('service')
    print("Service details: {}".format(service))
    action = service.get('action')
    print("Action: {}".format(action))
    apiCallAction = action.get("awsApiCallAction")
    print("apiCallAction: {}".format(apiCallAction))
    remoteIpDetails = apiCallAction.get("remoteIpDetails")
    print("remoteIpDetails: {}".format(remoteIpDetails))
    ipAddressV4 = remoteIpDetails.get('ipAddressV4')
    print("Guard Duty Flagged IP: {}".format(ipAddressV4))
    return ipAddressV4

def register_ip_to_tag_map(device, ip_addresses, tag):
    """

    :param device:
    :param ip_addresses:
    :param tag:
    :return:
    """

    exc = None
    try:
        device.userid.register(ip_addresses, tag)
    except Exception, e:
            exc = get_exception()

    if exc:
        return (False, exc)
    else:
        return (True, exc)

def configure_fw_dag(ipAddressV4):

    print("Setting up a DAG to block IP: {}".format(ipAddressV4))


def create_address_group_object(**kwargs):
    """
    Create an Address object

    @return False or ```objects.AddressObject```
    """
    ad_object = objects.AddressGroup(
        name=kwargs['address_gp_name'],
        dynamic_value=kwargs['dynamic_value'],
        description=kwargs['description'],
        tag=kwargs['tag_name']
    )
    if ad_object.static_value or ad_object.dynamic_value:
        return ad_object
    else:
        return None

def get_all_address_group(device):
    """
    Retrieve all the tag to IP address mappings
    :param device:
    :return:
    """
    exc = None
    try:
        ret = objects.AddressGroup.refreshall(device)
    except Exception, e:
        exc = get_exception()

    if exc:
        return (False, exc)
    else:
        l = []
        for item in ret:
            l.append(item.name)
        s = ",".join(l)
        return (s, exc)

def add_address_group(device, ag_object):
    """
    Create a new dynamic address group object on the
    PAN FW.
    """

    device.add(ag_object)

    ag_object.create()
    return True

def handle_dags(device, group_name, dag_match_filter):
    commit = True
    ag_object = create_address_group_object(address_gp_name=group_name,
                                            dynamic_value=dag_match_filter,
                                            description='DAG for GD IP Mappings',
                                            tag_name=None
                                            )
    result = add_address_group(device, ag_object)
    commit_exc = None
    if result and commit:
        print("Attempt to commit Dynamic Address Groups.")
        try:
            device.commit(sync=True)
        except Exception, e:
            print("Exception occurred: {}".format(e))
            commit_exc = False


def register_ip_to_tag_map(device, ip_addresses, tag):
    """

    :param device:
    :param ip_addresses:
    :param tag:
    :return:
    """

    exc = None
    try:
        device.userid.register(ip_addresses, tag)
    except Exception, e:
            exc = get_exception()

    if exc:
        return (False, exc)
    else:
        return (True, exc)

def handle_dag_tags(device, ipAddressV4, tag):

    result, exc = register_ip_to_tag_map(device,
                                         ip_addresses=ipAddressV4,
                                         tag=tag
                                         )

    try:
        device.commit(sync=True)
    except Exception, e:
        print("exception occurred.. {}".format(e))
    return result, exc


def check_security_rules(device):
    output = device.op("show system info")

    print("System info: {}".format(output))

    rulebase = policies.Rulebase()
    device.add(rulebase)
    current_security_rules = policies.SecurityRule.refreshall(rulebase)

    print('Current security rules: {}'.format(len(current_security_rules)))
    for rule in current_security_rules:
        print('- {}'.format(rule.name))

def get_rulebase(device):
    # Build the rulebase

    rulebase = policies.Rulebase()
    device.add(rulebase)

    policies.SecurityRule.refreshall(rulebase)
    return rulebase

def create_security_rule(**kwargs):
    security_rule = policies.SecurityRule(
        name=kwargs['rule_name'],
        description=kwargs['description'],
        fromzone=kwargs['source_zone'],
        source=kwargs['source_ip'],
        source_user=kwargs['source_user'],
        hip_profiles=kwargs['hip_profiles'],
        tozone=kwargs['destination_zone'],
        destination=kwargs['destination_ip'],
        application=kwargs['application'],
        service=kwargs['service'],
        category=kwargs['category'],
        log_start=kwargs['log_start'],
        log_end=kwargs['log_end'],
        action=kwargs['action'],
        type=kwargs['rule_type']
    )

    if 'tag_name' in kwargs:
        security_rule.tag = kwargs['tag_name']

    # profile settings
    if 'group_profile' in kwargs:
        security_rule.group = kwargs['group_profile']
    else:
        if 'antivirus' in kwargs:
            security_rule.virus = kwargs['antivirus']
        if 'vulnerability' in kwargs:
            security_rule.vulnerability = kwargs['vulnerability']
        if 'spyware' in kwargs:
            security_rule.spyware = kwargs['spyware']
        if 'url_filtering' in kwargs:
            security_rule.url_filtering = kwargs['url_filtering']
        if 'file_blocking' in kwargs:
            security_rule.file_blocking = kwargs['file_blocking']
        if 'data_filtering' in kwargs:
            security_rule.data_filtering = kwargs['data_filtering']
        if 'wildfire_analysis' in kwargs:
            security_rule.wildfire_analysis = kwargs['wildfire_analysis']
    return security_rule


def insert_rule(rulebase, sec_rule):

    print("Inserting Rule into the top spot.")
    if rulebase:
        rulebase.insert(0, sec_rule)
        sec_rule.apply_similar()
        #rulebase.apply()

def add_rule(rulebase, sec_rule):
    if rulebase:
        rulebase.add(sec_rule)
        sec_rule.create()
        return True
    else:
        return False


def update_rule(rulebase, nat_rule, commit):
    if rulebase:
        rulebase.add(nat_rule)
        nat_rule.apply()
        return True
    else:
        return False

def find_rule(rulebase, rule_name):
    # Search for the rule name
    rule = rulebase.find(rule_name)
    if rule:
        return rule
    else:
        return False

def handle_security_rule(device, rule_name, description, source_zone,
                         destination_zone, source_ip, action):

    rule_name=rule_name
    description=description
    source_zone=source_zone
    destination_zone=destination_zone
    source_ip=source_ip
    action=action

    # Get the rulebase
    print('Retrieve rulebase')
    rulebase = get_rulebase(device)
    print('Rulebase retrieved: {}'.format(rulebase))
    match = find_rule(rulebase, rule_name)
    if match:
        print('Rule \'%s\' already exists. Use operation: \'update\' to change it.' % rule_name)
    else:
        print("Create the rule..")
        try:
            print("Creating rule with name: {}".format(rule_name))
            new_rule = create_security_rule(
                rule_name=rule_name,
                description=description,
                tag_name=[],
                source_zone=source_zone,
                destination_zone=destination_zone,
                source_ip=source_ip,
                source_user=['any'],
                destination_ip=['any'],
                category=['any'],
                application=['any'],
                service=['application-default'],
                hip_profiles=['any'],
                group_profile={},
                antivirus={},
                vulnerability={},
                spyware={},
                url_filtering={},
                file_blocking={},
                data_filtering={},
                wildfire_analysis={},
                log_start=False,
                log_end=True,
                rule_type='universal',
                action=action
            )
            print("Add the rule to the FW...")
            #changed = add_rule(rulebase, new_rule)
            changed = insert_rule(rulebase, new_rule)
        except Exception, e:
            print(e)


def lambda_handler(event, context):

    print("[Lambda handler]Received event: " + json.dumps(event, indent=2))
    fw_ip = os.environ['FWIP']
    username = os.environ['USERNAME']
    password = os.environ['PASSWORD']
    print("Establish a connection with the firewall")
    fw = firewall.Firewall(fw_ip, username, password)

    group_name='pan_gd_dag'
    print("Process threat intelligence.")
    ipAddressV4 = handle_gd_threat_intel(event, context)
    print("Process / handle the creation of DAGs")
    handle_dags(fw, group_name, 'Recon:IAMUser')
    print("Process / handle the creation of ip to tag registrations")
    handle_dag_tags(fw, ipAddressV4, 'Recon:IAMUser')
    print("Process / handle the creation of security rules.")
    handle_security_rule(fw, 'aws_gd_source_rules',
                         'Rules based on Guard Duty',
                         'external', 'web',
                         [group_name], 'deny')
    fw.commit(sync=True)
    print("All operations done...")

if __name__ == "__main__":
    lambda_handler(None, None)
