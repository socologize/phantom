"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta

##############################
# Start - Global Code Block

import requests
import os
import collections
import ordereddict

# End - Global Code block
##############################

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'Get_Failed_Results' block
    Get_Failed_Results(container=container)

    # call 'filter_1' block
    filter_1(container=container)

    return

"""
Format the data for the SOC Email, contains less data than the Error Handling Email
"""
def SOC_Email_Format(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('SOC_Email_Format() called')
    #Redoes a lot of information gathering since palybook may fail before objects are created.
    
    #Gather Correlated Event Data
    correlated_arcsight_data = phantom.collect2(container=container, datapath=['filtered-data:filter_1:condition_1:artifact:*.cef.eventId', 
                                                                   'filtered-data:filter_1:condition_1:artifact:*.cef.name',
                                                                   'filtered-data:filter_1:condition_1:artifact:*.cef.message'                                                     
                                                                   ])
    #Gather Hostname data from event
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.destinationHostName', 'artifact:*.cef.deviceCustomString4'])    
    hostname = None 
    try:
        for hostname_data in container_data:
            if hostname_data[0]:
                hostname = hostname_data[0]
            elif hostname_data[1]:
                hostname = hostname_data[1]
        correlated_arcsight_data[0].append(hostname)
    except Exception as e:
        phantom.debug('DEBUG: HostNotInFlexnet - Hostname data is not available. {}'.format(e))

    #Gather base event data
    base_arcsight_data = phantom.collect2(container=container, datapath=['filtered-data:filter_1:condition_2:artifact:*.cef.destinationAddress',  
                                                                   'filtered-data:filter_1:condition_2:artifact:*.cef.destinationUserName',
                                                                   'filtered-data:filter_1:condition_2:artifact:*.cef.managerReceiptTime',
                                                                   'filtered-data:filter_1:condition_2:artifact:*.cef.startTime',
                                                                   'filtered-data:filter_1:condition_2:artifact:*.cef.endTime',
                                                                   'filtered-data:filter_1:condition_2:artifact:*.cef.deviceCustomString1',
                                                                   'filtered-data:filter_1:condition_2:artifact:*.cef.fileName',
                                                                   'filtered-data:filter_1:condition_2:artifact:*.cef.filePath'
                                                                  ])
    
    #Create final arcsight data list
    arcsight_data = None
    try:
        arcsight_data = correlated_arcsight_data[0] + base_arcsight_data[0]
    except Exception as e:
        phantom.debug("Arcsight Data not populated: {}".format(e))
    
    incident_content_id = ''
    archer_data = phantom.collect2(container=container, datapath=['artifact:*.cef.incidentContentId'])
    for data in archer_data:
        if data[0]:
            incident_content_id = data[0]
            
    base_content_id = ''
    base_alert_data = phantom.collect2(container=container, datapath=['artifact:*.cef.baseContentId'])
    for data in base_alert_data:
        if data[0]:
            base_content_id = data[0]
    
    correlated_content_id = ''
    correlated_alert_data = phantom.collect2(container=container, datapath=['artifact:*.cef.correlatedContentId'])
    for data in correlated_alert_data:
        if data[0]:
            correlated_content_id = data[0]
    #Create lists that correspond with collected data. Must match 1 to 1. These values will be the names in the table - Name | Value 
    arcsight_data_list = ['Event Id',
                          'Name',
                          'Message',
                          'Hostname',
                          'IP Address',
                          'Username',
                          'Manager Receipt Time',
                          'Start Time',
                          'End Time',
                          'Virus Name',
                          'File Name',
                          'File Path'
                         ]  
    archer_data_list = ['Created Security Incident']
    base_alert_data_list = ['Created Base Alert']
    correlated_alert_data_list = ['Created Correlated Alert']
    
    #Instantiate dictionaries using the above lists. Default value is ''
    arcsight_data_dict = ordereddict.OrderedDict([(i,'') for i in arcsight_data_list])
    archer_data_dict = {'Security Incident': str(incident_content_id)}
    base_alert_data_dict = {'Created Base Alert': str(base_content_id)}
    correlated_alert_data_dict = {'Created Correlated Alert': str(correlated_content_id)}
    
    #Populate Arcsight Dictionary
    try:
        if arcsight_data:
            for k,v in zip(arcsight_data_list,arcsight_data):
                if v:
                    if 'Time' in k:
                        v = datetime.strptime(v,"%Y-%m-%dT%H:%M:%S.%fZ").strftime('%d %b %Y %H:%M:%S GMT')
                    arcsight_data_dict[k] = v
    except Exception as e:
        phantom.debug("Arcsight Data dict not populated: {}".format(e))
    
    #Define Email Header and Email Banner
    body="<html><head>"
    body+="<style>"
    body+="body {font-family: Calibri, Verdana, Ariel, sans-serif}"
    body+="table {border-collapse: collapse;} th, td {text-align: left; padding: 5px; border: 1px solid black}"
    body+="th {background-color: #808080; color: white;}"
    body+="th, h3 {text-align: center;}"
    body+="</style></head>"

    body+="<body>"
    #body+="<img src='https://circles.accenture.com/Resources/34fd89eb-3bed-4029-be72-685ab83846e1/banner.jpg?v=09:06:40'>"

    #Define Text to display before tables
    body+="<h3><strong>Attention: SOC Team</strong></h3>"
    body+="<p><strong style='color: red;'>Action required - An error was encountered while executing the playbook.Please take the following actions:</strong></p>"
    body+="<ol>"
    body+="<li>Notify the ActiveDefense.admin@accenture.com distribution list and attach this General Error email</li>"
    body+="<li>Delete any created Archer Incidents or Alerts manually. Any created Incidents or Alerts will be listed below.</li>"
    body+="<li>Navigate to the Phantom Malware Active Channel in Arcsight</li>"
    body+="<li>Identify the correlated alert via the Event Id provided below</li>"
    body+="<li>Triage, remediate, and close the alert manually via the standard SOC process</li>"
    body+="</ol>"
    body+="<div align='center'>"
    
    #Display Arcsight data in Table
    body+="<table>"
    body+="<tr><th colspan='2'>Event Details</th></tr>"
    if arcsight_data_dict['Event Id'] != '':
        for k,v in arcsight_data_dict.items():
            body += '<tr><td>' + k + '</td>'
            body += '<td>' + str(v) + '</td></tr>'
    else:
        body += "<tr><td align='center'>Arcsight Details are not available</td></tr>"
    body += '</table><br>'

    #Display Archer data in Table
    body+="<table>"
    body+="<tr><th colspan='2'>Archer Details</th></tr>"
    if archer_data_dict['Security Incident'] != '':
        for k,v in archer_data_dict.items():
            body += '<tr><td>' + k + '</td>'        
            body += '<td>' "<a href='https://egrc.accenture.com/apps/ArcherApp/Home.aspx#record/459/264/" + str(v)+"'>" + str(v) + '</a>' '</td></tr>'
    else:
        body += "<tr><td align='center'>Security Incident was not created</td></tr>"
    #Populate Base Alert data in Table
    if base_alert_data_dict['Created Base Alert'] != '':
        for k,v in base_alert_data_dict.items():
            body += '<tr><td>' + k + '</td>'
            body += '<td>' "<a href='https://egrc.accenture.com/apps/ArcherApp/Home.aspx#record/459/265/" + str(v)+"'>" + str(v) + '</a>' '</td></tr>'
    else:
        body += "<tr><td align='center'>Base Alert was not created</td></tr>"
    #Populate Correlated Alert data in Table
    if correlated_alert_data_dict['Created Correlated Alert'] != '':
        for k,v in correlated_alert_data_dict.items():
            body += '<tr><td>' + k + '</td>'
            body += '<td>' "<a href='https://egrc.accenture.com/apps/ArcherApp/Home.aspx#record/459/264/" + str(v)+"'>" + str(v) + '</a>''</td></tr>'
    else:
        body += "<tr><td align='center'>Correlated Alert was not created</td></tr>"
    body += '</table><br>'
    body+="</div>"
    
    #Define Email Footer and Container ID
    body+="<p>Container ID: {} </p>".format(str(container['id']))
    body+="<p><strong style='color: black;'>Sent from Phantom Tool</strong></p>"
    body+="</body></html>"

    # parameter list for template variable replacement
    parameters = []

    phantom.format(container=container, template=body.encode("utf-8"), parameters=parameters, name="SOC_Email_Format")

    SOC_Email(container=container)

    return

"""
Email for SOC
"""
def SOC_Email(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('SOC_Email() called')

    # collect data for 'SOC_Email' call
    formatted_data_1 = phantom.get_format_data(name='SOC_Email_Format')

    parameters = []
    
    # build parameters list for 'SOC_Email' call
    parameters.append({
        'from': "phantom@mycompany.com",
        'to': "you@mycompany.com",
        'subject': "Phantom Dev - General Error",
        'body': formatted_data_1,
        'attachments': "",
    })

    phantom.act("send email", parameters=parameters, assets=['smtp'], name="SOC_Email")    
    
    return

"""
Get names and messages of failed results from parent playbook execution
"""
def Get_Failed_Results(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Get_Failed_Results() called')

    # collect data for 'Get_Failed_Results' call
    parent_playbook_id = phantom.get_playbook_info()[0]['parent_playbook_run_id']
    
    parameters = []
    
    # build parameters list for 'Get_Failed_Results' call
    parameters.append({
        'location': "/action_run/?_filter_playbook_run='{}'".format(parent_playbook_id),
        'verify_certificate': False,
        'headers': json.dumps({'Content-type': 'application/json'}),
    })

    phantom.act("get data", parameters=parameters, assets=['phantom rest api'], callback=Parse_Failed_Results, name="Get_Failed_Results")    
    
    return

def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('filter_1() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.type", "==", "CORRELATION"],
        ],
        name="filter_1:condition_1")

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.type", "==", "BASE"],
        ],
        name="filter_1:condition_2")

    SOC_Email_Format(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return

"""
Send Errors to Active Defense team for further investigation
"""
def Error_Handling_Email(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Error_Handling_Email() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Error_Handling_Email' call
    formatted_data_1 = phantom.get_format_data(name='Error_Email_Format')

    parameters = []
    
    # build parameters list for 'Error_Handling_Email' call
    parameters.append({
        'from': "phantom@mycompany.com",
        'to': "you@mycompany.com",
        'subject': "Dev Playbook Error",
        'body': formatted_data_1,
        'attachments': "",
    })

    phantom.act("send email", parameters=parameters, assets=['smtp'], name="Error_Handling_Email")    
    
    return

"""
Parses Failed results and adds context
"""
def Parse_Failed_Results(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Parse_Failed_Results() called')
    
    response = phantom.collect2(container=container, datapath=['Get_Failed_Results:action_result.data.*.response_body'])[0][0]
    phantom.debug(response)

    action_results = []
    #for action_result in response['data']:
    #    result_id = action_result['id']
    #    phantom.debug(result_id)
    failed_results = []

    for action_result in response['data']:
        action_results.insert(0, action_result)
        if action_result['status'] != 'success':
            failed_results.insert(0, action_result)

    phantom.save_object(key='results_object', container_id=container['id'], value={'data': {'action_results': action_results, 'failed_results': failed_results}})
    Get_Parent_Playbook_Name(container=container)

    return

"""
Formats the data for the Error Handling Email
"""
def Error_Email_Format(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Error_Email_Format() called')
    
    # collect Action Results
    results_object = phantom.get_object(key='results_object', container_id=container['id'])[0]['value']['data']
    action_results = results_object['action_results']
    failed_results = results_object['failed_results']
    result_template = "{0} [{1}]: ({2})"
        
    #Remove unnecessary Objects from container
    phantom.clear_object(key='results_object', container_id=container['id'])
    
    #Get Artifact Info
    artifact_names = phantom.collect2(container, datapath=['artifact:*.name'])    
    artifact_count = container['artifact_count']

    #Get Parent Playbook Data
    parent_playbook_name = phantom.collect2(container=container, datapath=['Get_Parent_Playbook_Name:action_result.data.*.response_body'])[0][0]['name']
    phantom.debug('Parent Playbook Name: {}'.format(parent_playbook_name))

    body="<html><head>"
    body+="<style>"
    body+="body {font-family: Calibri, Verdana, Ariel, sans-serif}"
    body+="table {border-collapse: collapse; width: 60%;} th, td {text-align: left; padding: 5px; border: 1px solid black}"
    body+="th {background-color: #808080; color: white;}"
    body+="th, h3 {text-align: center;}"
    body+="</style></head>"
    
    body+="<body>"  
    body+="<h3>Playbook Error - " + parent_playbook_name + "</h3>"
    body+="<p>Container ID: {}<br>".format(str(container['id']))
    body+="Failed Playbook: {}<br>".format(str(parent_playbook_name))
    body+="Number of Artifacts in Container: {}</p>".format(str(container['artifact_count']))
    if artifact_names:
        body+="<b>Artifact Names</b>"
        body+="<ul>"
        for artifact in artifact_names:
            body+="<li>" + artifact[0] + "</li>"
        body+="</ul>"
    
    if failed_results:
        body+="<p><b>Failed Actions</b></p>"
        body+="<ol>"
        for failed_result in failed_results:
            body+="<li>"+ result_template.format(failed_result['name'], failed_result['action'], failed_result['status']) +"</li>"
            body+="<ul><li>Message: {}</li></ul>".format(failed_result['message']) 
        body+="</ol>"
        
    if action_results:
        body+="<p><b>Action Summary</b></p>"
        body+="<ol>"
        for action_result in action_results:
            if action_result['status'] == 'failed':
                body+="<li style='color:red;'>"+ result_template.format(action_result['name'], action_result['action'], action_result['status']) +"</li>"
                body+="<ul><li>Message: {}</li></ul>".format(action_result['message']) 
            else:
                body+="<li>"+ result_template.format(action_result['name'], action_result['action'], action_result['status']) +"</li>"
                body+="<ul><li>Message: {}</li></ul>".format(action_result['message']) 
        body+="</ol>"
    
    #Collect all objects saved throughout playbook executions
    saved_objects = phantom.get_object(key='%', container_id=container['id'])
    if len(saved_objects) > 0:
        saved_objects_body = "<div align='center'>"
        for saved_object in saved_objects:
            object_name = saved_object['composite_key']['key']
            object_data = saved_object['value']['data']

            saved_objects_body+="<table>"
            saved_objects_body+="<tr><th colspan='2'>" + str(object_name) + "</th></tr>"
            for k,v in object_data.items():
                saved_objects_body += '<tr><td>' + str(k) + '</td>'
                if isinstance(v,dict):
                    saved_objects_body += '<td><ul>'
                    for i,j in v.items():
                        if isinstance(j, basestring):
                            j = j.encode('utf-8') 
                        saved_objects_body += '<li>' + str(i) + ': ' + str(j) + '</li>'
                        
                    saved_objects_body += '</ul></td></tr>'
                else:
                    if isinstance(v, basestring):
                        v = v.encode('utf-8')
                    saved_objects_body += '<td>' + str(v) + '</td></tr>'
            saved_objects_body += '</table><br>'
        saved_objects_body += '</div>'
        body+="<p><b>Saved Objects</b></p>"
        body+=saved_objects_body

    body+="<p><strong style='color: black;'>Sent from Phantom Tool</strong></p>"
    body+="</body></html>"
    
    parameters = []

    phantom.format(container=container, template=body, parameters=parameters, name="Error_Email_Format")

    Error_Handling_Email(container=container)

    return

"""
Get name of Parent Playbook
"""
def Get_Parent_Playbook_Name(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Get_Parent_Playbook_Name() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Get_Parent_Playbook_Name' call
    results_data_1 = phantom.collect2(container=container, datapath=['Get_Failed_Results:action_result.data.*.response_body'])
    parent_playbook_id = None
    try:
        parent_playbook_id = results_data_1[0][0]['data'][0]['playbook']
    except (TypeError, IndexError, KeyError):
        pass
    
    phantom.debug('Parent Playbook Id: {}'.format(parent_playbook_id))

    parameters = []
    
    # build parameters list for 'Get_Parent_Playbook_Name' call
    if parent_playbook_id:
        parameters.append({
            #"/action_run/?_filter_playbook_run='{}'".format(parent_playbook_id),
            'location': "/playbook/{}".format(parent_playbook_id),
            'verify_certificate': False,
            'headers': json.dumps({'Content-type': 'application/json'}),
        })

        phantom.act("get data", parameters=parameters, callback=Error_Email_Format, assets=['phantom rest api'], name="Get_Parent_Playbook_Name")
        return
        
    Error_Email_Format(container=container)
    
    return

def on_finish(container, summary):
    phantom.debug('on_finish() called')
    # This function is called after all actions are completed.
    # summary of all the action and/or all detals of actions 
    # can be collected here.

    # summary_json = phantom.get_summary()
    # if 'result' in summary_json:
        # for action_result in summary_json['result']:
            # if 'action_run_id' in action_result:
                # action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                # phantom.debug(action_results)

    return