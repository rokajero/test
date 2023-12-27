import re
from datetime import datetime
import configparser

file_paths = []
log_entries = []

CEF_output = []

unique_ID = "0"

vendor = 'Unknown'
version = 'Unknown'

pattern = re.compile(r'\[.*?\]')

severity = {
    "INFO": "0",
    "ERROR": "10"
}


def get_settings(file_path='config.ini'):
    global vendor, version, file_paths
    config = configparser.ConfigParser()
    config.read(file_path)
    vendor = config.get('Settings', 'vendor')
    version = config.get('Settings', 'version')
    file_paths = config.get('Paths', 'file_paths').split(', ')


def process_lines(lines, current_result=None):
    if current_result is None:
        current_result = []

    if not lines:
        return current_result

    current_line = lines[0]

    if not current_line.startswith("20"):
        if current_result:
            current_result[-1] += ' ' + current_line.strip()
        else:
            current_result.append(current_line.strip())
    else:
        current_result.append(current_line.strip())
    return process_lines(lines[1:], current_result)


def open_files(filename, selected_list):
    with open(filename, 'r') as log_file:
        selected_list.clear()
        for line in log_file:
            selected_list.append(line)
        selected_list = process_lines(selected_list)


def remaking2(filename, list_with_lines):
    global unique_ID
    pattern = re.compile(r'\[(.*?)\]\[(.*?)\]')

    for line in list_with_lines:
        match = pattern.search(line)
        if match:
            if '/user-actions.log' in filename or '/events.log' in filename:
                timestamp, level, user_info, action_info = (
                    line.split()[:2],
                    line.split()[2],
                    match.group(1),
                    match.group(2)
                )
                data = {
                    "timestamp": " ".join(timestamp),
                    "level": level,
                    "user_info": dict(re.findall(r'(\w+): "(.*?)"', user_info)),
                    "action_info": dict(re.findall(r'(\w+): "(.*?)"', action_info))
                }
            else:
                print('Unknown name, aborted')
                #return -1
        '''else:'''

        if data['user_info']['host_ip'] == '':
            data['user_info']['host_ip'] = 'null'

        if data['user_info']['user_ip'] == '':
            data['user_info']['user_ip'] = 'null'

        cef_header = 'CEF:0|Unknown|Unknown|Unknown|'

        if "eltex-portal-constructor" in filename:
            cef_header = 'CEF:0|'+vendor+'|eltex-portal-constructor|'+version+'|'
            if 'portal-constructor.log' not in filename:
                event_name = data['action_info']['msg']
        elif "eltex-ems" in filename:
            cef_header = 'CEF:0|'+vendor+'|eltex-ems|'+version+'|'
            event_name = data['action_info']['function']

        timestamp = datetime.strptime(data['timestamp'], "%Y-%m-%d %H:%M:%S,%f").strftime("%b %d %H:%M:%S")
        log_level = data['level']

        source = 'src='+data['user_info']['host_ip']
        destination = 'dest='+data['user_info']['user_ip']

        unique_ID = str(int(unique_ID) + 1)

        cef_message = timestamp + ' host ' + cef_header + unique_ID + '|' \
            + event_name + '|' + severity.get(log_level) + '|' + source + ' ' \
            + destination

        CEF_output.append(cef_message)


def write_out_cef(cef_list):
    with open('log/cef_updated.log', 'w') as logfile:
        for line in cef_list:
            logfile.write(line+'\n')


'''----------------------------------------------------------------------------'''
get_settings()

for file in file_paths:
    open_files(file, log_entries)
    remaking2(file, log_entries)

# write_out_cef(CEF_output)

for cef in CEF_output:
    print(cef)


# open_files(log_filename3, log_entries3)
# resulting = process_lines(log_entries3)
# remaking(log_filename3, resulting)

'''open_files(log_filename, log_entries) #opening file
remaking2(log_filename, log_entries) #process of remaking log

open_files(log_filename2, log_entries2)
remaking2(log_filename2, log_entries2)'''