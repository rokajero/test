import re
from datetime import datetime
import configparser

log_filename = 'log/eltex-portal-constructor/user-actions.log'
log_filename2 = 'log/eltex-ems/events.log'
log_filename3 = 'log/eltex-portal-constructor/portal-constructor.log'

log_entries = []
log_entries2 = []
log_entries3 = []

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
    global vendor, version
    config = configparser.ConfigParser()
    config.read(file_path)
    vendor = config.get('Settings', 'vendor')
    version = config.get('Settings', 'version')


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
        for line in log_file:
            selected_list.append(line)


def remaking(filename, list_with_lines):
    global unique_ID
    for line in list_with_lines:
        event_name = ''
        source = ''
        destination = ''

        parts = line.split()

        if '/portal-constructor.log' in filename:
            timestamp = line[line.find('20'):line.find(',')]
            milliseconds = line[line.find(',') + 1:line.find(' ')]
            log_level = parts[2]
            timestamp = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S").strftime("%b %d %H:%M:%S")
        else:
            timestamp = line[line.find('20'):line.find(',')]
            milliseconds = parts[1].split(',')[1]
            log_level = parts[2]
            user_info, action_info = re.findall(pattern, line)
            timestamp = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S").strftime("%b %d %H:%M:%S")

        if "eltex-portal-constructor" in filename:
            cef_header = 'CEF:0|'+vendor+'|eltex-portal-constructor|'+version+'|'
            if 'portal-constructor.log' not in filename:
                event_name = re.search(r'msg: "(.*?)"', action_info).group(1)
        elif "eltex-ems" in filename:
            cef_header = 'CEF:0|'+vendor+'|eltex-ems|'+version+'|'
            event_name = re.search(r'function: "(.*?)"', action_info).group(1)
        else:
            break

        if 'portal-constructor.log' in filename:
            event_name = parts[3]

        if 'portal-constructor.log' not in filename:
            source = "src="+re.search(r'host_ip: "(.*?)"', user_info).group(1)
            destination = "dest="+re.search(r'user_ip: "(.*?)"', user_info).group(1)

        if 'portal-constructor.log' not in filename:
            if re.search(r'user_ip: "(.*?)"', user_info).group(1) == '':
                destination = "dest=null"

        unique_ID = str(int(unique_ID)+1)

        if 'portal-constructor.log' not in filename:
            cef_message = timestamp + ' host ' + cef_header + unique_ID + '|' \
                + event_name + '|' + severity.get(log_level) + '|' + source + ' ' \
                + destination
        else:
            cef_message = timestamp + ' host ' + cef_header + unique_ID + '|' \
                + event_name + '|' + severity.get(log_level) + '|' \
                + line[line.find(parts[4]):]

        CEF_output.append(cef_message)


def write_out_cef(cef_list):
    with open('log/cef_updated.log', 'w') as logfile:
        for line in cef_list:
            logfile.write(line+'\n')


'''----------------------------------------------------------------------------'''
get_settings()

open_files(log_filename, log_entries)
remaking(log_filename, log_entries)

open_files(log_filename2, log_entries2)
remaking(log_filename2, log_entries2)

open_files(log_filename3, log_entries3)
resulting = process_lines(log_entries3)
remaking(log_filename3, resulting)

write_out_cef(CEF_output)

for cef in CEF_output:
    print(cef)
