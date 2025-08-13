#!/usr/bin/env python3
# Copyright 2022 F5 Networks, Inc.
# Modified work Copyright 2024 [fung04]
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Modifications:
# - Converted from JavaScript to Python
# - Converted parser.js to Python class BigIPConfigParser()
# - Restructured logic to accommodate Python's language constraints
# - Adjusted function implementation to achieve same functionality

import tarfile
import os
import re
import json
import csv
import traceback
from typing import List, Dict, Any
from collections import defaultdict

# Script will sort by first column, thus the first column should not be a list
VS_LB_CONFIG = {
    "vs_name": 'N/A',
    'vs_type': 'N/A',
    "vs_description": 'N/A',
    'vs_ip_src': 'N/A', 
    'vs_ip_src_cidr': 'N/A',
    "vs_ip_dest": 'N/A',
    "vs_ip_dest_port": 'N/A',
    "vs_ip_dest_mask": 'N/A',
    "vs_ip_protocol": 'N/A',
    "vs_vlans": ['N/A'],
    "vs_vlans_status": ['N/A'],
    "vs_pool_name": 'N/A',
    'vs_pool_members': ['N/A'],
    'vs_pool_port': ['N/A'],
    'vs_pool_lb_mode': 'N/A',
    'vs_pool_monitor_members': ['N/A'],
    'vs_presist': ['N/A'],
    'vs_profiles': ['N/A'],
    'vs_policies':['N/A'],
    'vs_asm_policies': ['N/A'],
    'vs_security_log_profiles': ['N/A'],
    'vs_ssl_offload': ['N/A'],
    'vs_irules': ['N/A'],
    'vs_snat': 'N/A',
    'vs_snat_translation': 'N/A',
}

F5_IP_CONFIG = {
    "self_ip": "N/A",
    "self_ip_cidr": "N/A",
    "traffic-group": "N/A",
    "vlan": "N/A",
    "vlan_id": "N/A",
    "interface_tag":['N/A'],
    "interface_untag":['N/A'],
    "trunk":"N/A"
}

F5_SNAT_CONFIG = {
    "snat_name": "N/A",
    "snat_pool_name": "N/A",
    "translation_ip": ['N/A'],
    "origins_ip": ['N/A'],
    "vlan": ["N/A"],
    "vlan_status": ["N/A"]
}

F5_DEVICE_CONFIG = {
    "hostname": "N/A",
    "management_ip": "N/A",
    "serial_number": "N/A",
    "device_model": "N/A",
    "device_type": "N/A",
    "version": "N/A",
    "config_sync_ip": "N/A",
    "snmp": ['N/A'],
    "sys_log": ['N/A'],
    "ntp": ['N/A'],
    "dns": ['N/A'],
    "tacacs": ['N/A'],
}

F5_ROUTE_CONFIG = {
    "network": "N/A",
    "gateway": ['N/A'],
    "description": "N/A",

}

FILE_EXTENSION = [".ucs", ".qkview"]
CONFIG_OUTPUT_FOLDER = "config"
JSON_OUTPUT_FOLDER = "output"
UNSET = "unset"
# CONFIG_TYPE = ['.bigip_emergency.conf', '.cluster.conf', 'bigip_base.conf', 'bigip_script.conf', 'bigip_user.conf', 'bigip.conf', 'cipher.conf', 'user_alert.conf','bigip_gtm.conf', 'ntp.conf']


class BigIPConfigParser():
    def __init__(self):
        self.topology_arr = []
        self.topology_count = 0
        self.longest_match_enabled = False

    @staticmethod
    def arr_to_multiline_str(arr: List[str]) -> Dict[str, str]:
        key, *rest = arr[0].strip().split()
        arr[0] = ' '.join(rest)
        return {key: '\n'.join(arr)}

    @staticmethod
    def count_indent(string: str) -> int:
        return len(string) - len(string.lstrip())

    @staticmethod
    def get_title(string: str) -> str:
        return re.sub(r'\s?\{\s?}?$', '', string).strip()

    @staticmethod
    def obj_to_arr(line: str) -> List[str]:
        return line.split('{')[1].split('}')[0].strip().split()

    @staticmethod
    def remove_indent(arr: List[str]) -> List[str]:
        return [line[4:] if BigIPConfigParser.count_indent(line) > 1 else line for line in arr]

    @staticmethod
    def str_to_obj(line: str) -> Dict[str, str]:
        key, *rest = line.strip().split()
        return {key: ' '.join(rest)}

    # Return true if the string contains the header of ltm/gtm/pem rule
    @staticmethod
    def is_rule(string: str) -> bool:
        return any(rule in string for rule in ('ltm rule', 'gtm rule', 'pem irule'))

    # Pass arr of individual bigip-obj
    # Recognize && handle edge cases
    def orchestrate(self, arr: List[str]) -> Dict[str, Any]:
        key = self.get_title(arr[0])
        
        # Below fix is likely related with Issues and PR discuss in f5devcentral/f5-automation-config-converter
        # Issues: Error "Missing or mis-indented '}'" #99
        # PR: Update parser.js #102 
        if len(arr) <= 1:
            return {key: {}}
        
        # Remove opening and closing brackets
        arr = arr[1:-1]  
        
        # Edge case: iRules (multiline string)
        if self.is_rule(key):
            return {key: '\n'.join(arr)}
        
        # Edge case: monitor min X of {...}
        if 'monitor min' in key:
            return {key: ' '.join(s.strip() for s in arr).split()}
        
        # Edge case: skip cli script
        # Also skip 'sys crypto cert-order-manager', it has quotation marks around curly brackets of 'order-info'
        if 'cli script' in key or 'sys crypto cert-order-manager' in key:
            return {key: {}}
        
        obj = {}
        i = 0
        while i < len(arr):
            line = arr[i]
            
            # Edge case: nested object
            # RECURSIVE FUNCTION
            # Quoted bracket "{" won't trigger recursion
            if line.endswith('{') and len(arr) != 1:
                c = next((j for j, l in enumerate(arr[i:], start=i) if l == '    }'), None)
                if c is None:
                    raise ValueError(f"Missing or mis-indented '}}' for line: '{line}'")
                sub_obj_arr = self.remove_indent(arr[i:c+1])
                
                # Coerce unnamed objects into array
                coerce_arr = [f"{j} {l}" if l == '    {' else l for j, l in enumerate(sub_obj_arr)]
                # Recursion for subObjects
                obj.update(self.orchestrate(coerce_arr))
                # Skip over nested block
                i = c
            
            # Edge case: empty object
            elif line.strip().endswith('{ }'):
                obj[line.split('{')[0].strip()] = {}
            
            # Edge case: pseudo-array pattern (coerce to array)
            elif '{' in line and '}' in line and '"' not in line:
                obj[line.split('{')[0].strip()] = self.obj_to_arr(line)
            
            # Edge case: single-string property
            elif (not line.strip().count(' ') or re.match(r'^"[\s\S]*"$', line.strip())) and '}' not in line:
                obj[line.strip()] = ''
            
            # Regular string property
            # Ensure string props on same indentation level
            elif self.count_indent(line) == 4:
                # Check if the line contains an odd number of double quotes, indicating an unclosed string
                if line.count('"') % 2 == 1:
                    # Find the next line that also contains an odd number of double quotes, which would close the string
                    for j, l in enumerate(arr[i:]):
                        if l.count('"') % 2 == 1:
                            c = j + i
                    # If no such line is found, raise an error indicating an unclosed quote
                    if c is None:
                        raise ValueError(f"Unclosed quote in multiline string starting at: '{line}'")
                    # Extract the chunk of lines between the current line and the closing line
                    chunk = arr[i:c+1]
                    # Convert the chunk of lines into a multiline string and update the object
                    obj.update(self.arr_to_multiline_str(chunk))
                    # Move the index to the closing line to continue processing
                    i = c
                
                # Treat as typical string
                else:
                    tmp = self.str_to_obj(line.strip())
                    if key.startswith('gtm monitor external') and 'user-defined' in tmp:
                        obj.setdefault('user-defined', {}).update(self.str_to_obj(tmp['user-defined']))
                    else:
                        obj.update(tmp)
            
            # Else report exception
            else:
                print(f"Unexpected line: {line}")
            
            i += 1
        
        return {key: obj}

    # THIS FUNCTION SHOULD ONLY GROUP ROOT-LEVEL CONFIG OBJECTS
    def group_objects(self, arr: List[str]) -> List[List[str]]:
        group = []
        i = 0
        while i < len(arr):
            current_line = arr[i]
            
            # Empty obj / pseudo-array
            # Change to use first/last char pattern (not nested empty obj)
            # Skip nested objects for now..
            if '{' in current_line and '}' in current_line and not current_line.startswith(' '):
                group.append([current_line])
            elif current_line.strip().endswith('{') and not current_line.startswith(' '):
                # Looking for non-indented '{'
                rule_flag = self.is_rule(current_line)
                # Different grouping logic for iRules
                bracket_count = 1
                c = 0
                while bracket_count != 0:
                    c += 1
                    # Count { and }. They should occur in pairs
                    line = arr[i + c]
                    if not ((line.strip().startswith('#') or line.strip().startswith('set') or 
                             line.strip().startswith('STREAM')) and rule_flag):
                        # Exclude quoted parts
                        updated_line = re.sub(r'\\"', '', line.strip())
                        updated_line = re.sub(r'"[^"]*"', '', updated_line)
                        
                        # Count brackets if functional (not stringified)
                        # Closing root-level obj
                        bracket_count += updated_line.count('{') - updated_line.count('}')
                    
                    # Abort if run into next rule
                    if self.is_rule(line):
                        c -= 1
                        break
     
                group.append(arr[i:i + c + 1])
                i += c
            i += 1
        return group

    def parse_files(self, files: Dict[str, str]) -> Dict[str, Any]:
        try:
            data = {}
            for key, value in files.items():
                # print(f"Parsing {key}")
                 # Do not parse certs, keys or license
                if any(x in key for x in ('Common_d', 'bigip_script.conf', '.license', 'profile_base.conf', 'statsd.conf', 'daemon.conf')):
                    continue
                
                file_arr = value.replace('\r\n', '\n').split('\n')
                
                # GTM topology
                new_file_arr = []
                self.topology_arr = []
                self.topology_count = 0
                self.longest_match_enabled = False
                in_topology = False
                irule = 0
                
                for line in file_arr:
                    # Process comments in iRules
                    if irule == 0:
                        if line.strip().startswith('# '):
                            # Mark comments outside of irules with specific prefix
                            line = line.strip().replace('# ', '#comment# ')
                        elif self.is_rule(line):
                            irule += 1
                    # Don't count brackets in commented or special lines
                    elif not line.strip().startswith('#'):
                        irule += line.count('{') - line.count('}')
                    
                    if 'topology-longest-match' in line and 'yes' in line:
                        self.longest_match_enabled = True
                    elif line.startswith('gtm topology ldns:'):
                        in_topology = True
                        if not self.topology_arr:
                            self.topology_arr.extend(['gtm topology /Common/Shared/topology {', '    records {'])
                        ldns_index, server_index, bracket_index = (line.index(x) for x in ('ldns:', 'server:', '{'))
                        ldns = line[ldns_index + 5:server_index].strip()
                        server = line[server_index + 7:bracket_index].strip()
                        self.topology_arr.extend([
                            f"        topology_{self.topology_count} {{",
                            f"            source {ldns}",
                            f"            destination {server}"
                        ])
                        self.topology_count += 1
                    elif in_topology:
                        if line == '}':
                            in_topology = False
                            self.topology_arr.append('        }')
                        else:
                            self.topology_arr.append(f"        {line}")
                    else:
                        new_file_arr.append(line)
                
                if self.topology_arr:
                    self.topology_arr.extend([
                        f"        longest-match-enabled {str(self.longest_match_enabled).lower()}",
                        '    }',
                        '}'
                    ])
                
                file_arr = new_file_arr + self.topology_arr
                # Filter whitespace && found comments
                file_arr = [line for line in file_arr if line and not line.strip().startswith('#comment# ')]
                
                group_arr = [self.orchestrate(obj) for obj in self.group_objects(file_arr)]
                data.update({k: v for d in group_arr for k, v in d.items()})
            
            return data
        except Exception as e:
            # error_message = f"Error parsing input file. Please open an issue at https://github.com/f5devcentral/f5-automation-config-converter/issues and include the following error:\n{str(e)}"
            error_message = f"Error parsing input file. Error as following error:\n{str(e)}"
            raise Exception(error_message)
        
class BigIPConfigExtractor():
    def __init__(self):
        files = [file for file in os.listdir() if os.path.splitext(file)[1] in FILE_EXTENSION]
        
        for file in files:
            file_name = os.path.splitext(file)[0]
            try:
                print(f"Extracting [{file}]")
                with tarfile.open(file, 'r:gz') as tar:
                    # Extract all files within the 'config' directory to the destination folder
                    for member in tar.getmembers():
                        if member.name.startswith('config/') and '/' not in member.name[len('config/'):]:
                            # Remove the 'config/' prefix from the member name
                            member.name = member.name[len('config/'):]
                            if member.name.endswith('.conf'):
                                if not member.issym() and not member.islnk():
                                    tar.extract(member, path=f"{CONFIG_OUTPUT_FOLDER}/{file_name}", set_attrs=False, filter="data")
            except Exception as e:
                print(f"Error processing {file}:\n{e}")
    
class BigIPConfigExporter:
    def __init__(self, filename):
        self.vs_config_list = []
        self.f5_self_ip_list = []
        self.f5_device_info_list = []
        self.f5_snat_info_list = []
        self.f5_route_info_list = []
        self.filename = filename

        with open(f"{JSON_OUTPUT_FOLDER}/{filename}.json", "r") as f:
            self.response = json.load(f)
        self.pre_process_config()
        self.extract_config()
        self.export_config()

    def pre_process_config(self):
        # as3_converted_config = self.response['as3Converted']
        # as3_recognized_config = self.response['as3Recognized']
        # as3_notconverted_config = self.response['as3NotConverted']
        try:
            self.as3_output_config = self.response['output']['Common']['Shared']
        except (KeyError, TypeError):
            self.as3_output_config = []

        # print(f'AS3 Converted Config    : {len(as3_converted_config)}')
        # print(f'AS3 Recognized Config   : {len(as3_recognized_config)}')
        # print(f'AS3 Not Converted Config: {len(as3_notconverted_config)}')
        
        self.virtual_servers_list = {key: value for key, value in self.response.items() if key.startswith('ltm virtual ')}
        self.ltm_pool_list = {key: value for key, value in self.response.items() if key.startswith('ltm pool')}
        self.ltm_profile_list = {key: value for key, value in self.response.items() if key.startswith('ltm profile')}

        self.self_ip_list = {key: value for key, value in self.response.items() if key.startswith('net self ')}
        self.vlan_list = {key: value for key, value in self.response.items() if key.startswith('net vlan')}
        self.trunk_list = {key: value for key, value in self.response.items() if key.startswith('net trunk')}
        self.snat_list = {key: value for key, value in self.response.items() if key.startswith('ltm snat ')}
        self.snat_pool_list = {key: value for key, value in self.response.items() if key.startswith('ltm snatpool')}
        self.vcmp_guest_list = {key: value for key, value in self.response.items() if key.startswith('vcmp guest ')}
        self.routes_list = {key: value for key, value in self.response.items() if key.startswith('net route ') or key.startswith('sys management-route')}

        self.device_list = {key: value for key, value in self.response.items() if key.startswith('cm device ')}
        self.sys_config_list = {key: value for key, value in self.response.items() if key.startswith('sys') or key.startswith('auth')}
    
    def extract_config(self):

        vs_processor = VirtualServerProcessor(self.virtual_servers_list, self.ltm_pool_list, self.as3_output_config)
        self.vs_config_list = vs_processor.process_virtual_servers()
        
        self_ip_processor = SelfIPProcessor(self.self_ip_list, self.vcmp_guest_list, self.vlan_list, self.trunk_list)
        self.f5_self_ip_list = self_ip_processor.process_self_ips()

        device_processor = DeviceInfoProcessor(self.device_list, self.sys_config_list)
        self.f5_device_info_list = device_processor.process_device_info()

        snat_processor = SNATProcessor(self.snat_list, self.snat_pool_list)
        self.f5_snat_info_list = snat_processor.process_snats()
        
        route_processor = RouteProcessor(self.routes_list, self.ltm_pool_list)
        self.f5_route_info_list = route_processor.process_routes()

        print(f"Total Virtual Servers: {len(self.vs_config_list)}")
        
    def export_config(self):
        os.makedirs('output', exist_ok=True)
        
        with open(f'output/f5_all_ip.csv', 'a', newline="") as file:
            self.f5_self_ip_list.sort(key=lambda x: x[list(x.keys())[0]])
            writer = csv.writer(file)
            writer.writerow([self.filename])
            for config in self.f5_self_ip_list:
                if isinstance(config, dict):
                    row = ["\n".join(v) if isinstance(v, list) else v for v in config.values()]
                else:
                    row = [config] 
                writer.writerow(row)

        configs_to_export = [
            (f'{self.filename}_vs.csv', self.vs_config_list, VS_LB_CONFIG.keys()),
            (f'{self.filename}_self_ip.csv', self.f5_self_ip_list, F5_IP_CONFIG.keys()),
            (f'{self.filename}_device_info.csv', self.f5_device_info_list, F5_DEVICE_CONFIG.keys()),
            (f'{self.filename}_snat.csv', self.f5_snat_info_list, F5_SNAT_CONFIG.keys()),
            (f'{self.filename}_route.csv', self.f5_route_info_list, F5_ROUTE_CONFIG.keys()),
        ]

        for filename, data_list, headers in configs_to_export:
            # sort by first column of the data_list
            data_list.sort(key=lambda x: x[list(x.keys())[0]])
            os.makedirs(f'output/{self.filename}', exist_ok=True)

            if data_list:
                with open(f'output/{self.filename}/{filename}', 'w', newline="") as file:
                    writer = csv.writer(file)
                    writer.writerow(headers)
                    for item in data_list:
                        if isinstance(item, dict):
                            row = ["\n".join(v) if isinstance(v, list) else v for v in item.values()]
                        else:
                            row = [item]
                        writer.writerow(row)
                # print(f"Data exported to output/{filename}")
            else:
                print(f"No data to export for {filename}")

class VirtualServerProcessor:   
    def __init__(self, virtual_servers_list, ltm_pool_list, as3_output_config):
        self.virtual_servers_list = virtual_servers_list
        self.ltm_pool_list = ltm_pool_list
        self.as3_output_config = as3_output_config
        self.monitor_pattern = re.compile(r'(/.+?)(?: and |$)')
        
        self.vs_config_list = []

    def process_virtual_servers(self):
        # Process each Virtual Server from list
        for key, data in self.virtual_servers_list.items():
            self.vs_config = VS_LB_CONFIG.copy()
            self.create_base_vs_config(key, data)
            self.process_vs_components(data)
            
            self.vs_config_list.append(self.vs_config)
        return self.vs_config_list

    def create_base_vs_config(self, key, data):
        # Extract basic VS configuration details
        # Similar to the current implementation in extract_config method
        self.vs_config['vs_name'] = key.split('/')[-1]
        
        source = data.get('source', 'N/A')
        if source != 'N/A':
            self.vs_config['vs_ip_src'] = source.split("/")[0]
            self.vs_config['vs_ip_src_cidr'] = source.split('/')[-1]
        
        destination = data.get('destination', 'N/A')
        if destination != 'N/A':
            self.vs_config['vs_ip_dest'] = destination.split("/")[-1].split(":")[0]
            self.vs_config['vs_ip_dest_port'] = destination.split(':')[-1]  
        
        self.vs_config['vs_ip_dest_mask']  = data.get('mask', 'N/A')
        self.vs_config['vs_ip_protocol'] = data.get('ip-protocol', 'N/A')
        
        description = data.get('description', 'N/A')
        if description != 'N/A':
            self.vs_config['vs_description'] = description.replace('"', '/')

        return self.vs_config   

    def process_vs_components(self, data):
        # Coordinate calls to specific component extraction methods
        # Get the the component from each of the Virtual Server
        
        # Mandatory
        if data.get('pool'): 
            self.extract_vs_pool(data, self.ltm_pool_list) # Passing Virtual Server and Pools list
        else:
            self.vs_config['vs_pool_name'] = [UNSET]
            self.vs_config['vs_pool_members'] = [UNSET]
            self.vs_config['vs_pool_port'] = [UNSET]
            self.vs_config['vs_pool_lb_mode'] = UNSET
            self.vs_config['vs_pool_monitor_members'] = [UNSET]
        
        if data.get('persist'):
            self.extract_vs_presist(data)
        else:
            self.vs_config['vs_presist'] = [UNSET]

        if data.get('profiles'):
            self.extract_vs_profiles(data)
        else:
            self.vs_config['vs_profiles'] = [UNSET]
            self.vs_config['vs_asm_policies'] = [UNSET]
            self.vs_config['vs_ssl_offload'] = [UNSET]
        
        if data.get('policies'):
            self.extract_vs_policies(data)
        else:
            self.vs_config['vs_policies'] = [UNSET]

        if data.get('security-log-profiles'):
            self.extract_vs_security_log_profiles(data)
        else:
            self.vs_config['vs_security_log_profiles'] = [UNSET]
        
        if data.get('source-address-translation'):
            self.extract_vs_snat(data)
        else:
            self.vs_config['vs_snat'] = UNSET
            self.vs_config['vs_snat_translation'] = UNSET

        if data.get('rules'):
            self.extract_vs_irules(data)
        else:
            self.vs_config['vs_irules'] = [UNSET]
        
        if data.get('vlans'):
            self.extract_vs_vlans(data)
        else:
            self.vs_config['vs_vlans'] = [UNSET]

        # self.identify_vs_type(data) # TODO
        # ... other component methods
    
    def extract_vs_pool(self, data, ltm_pool_list):
        # Get Pool name from Virtual Server data, then serach in Pools list
        vs_pool = f"ltm pool {data.get('pool', '')}"
        pool_data = ltm_pool_list.get(vs_pool, {})
      
        if pool_data: # Pool name is found in Pools list
            self.vs_config['vs_pool_members'] = []
            self.vs_config['vs_pool_port'] = []

            self.vs_config['vs_pool_name'] = vs_pool.split('/')[-1]
            members = pool_data.get('members', {})
            load_balancing_mode = pool_data.get('load-balancing-mode', 'round-robin')
            monitor = pool_data.get('monitor', None)
            monitor_min = pool_data.get('monitor min 1 of', None)

            for member_key, member_info in members.items():
                address_port = re.search(r'(\:\S+)', member_key).group(0)
                address = member_info.get('address')
                session = member_info.get('session')
                state = member_info.get('state')

                if session and state:
                    full_address = f"{address}{address_port}:{session}:{state}"
                else:
                    full_address = f"{address}{address_port}"

                self.vs_config['vs_pool_members'].append(full_address)
                self.vs_config['vs_pool_port'].append(address_port)
            
            if monitor:
                monitor_members = self.monitor_pattern.findall(monitor)
                self.vs_config['vs_pool_monitor_members'] = monitor_members
            elif monitor_min:
                self.vs_config['vs_pool_monitor_members'] = monitor_min
            
            if load_balancing_mode:
                self.vs_config['vs_pool_lb_mode'] = load_balancing_mode
        else:
            print(f"NOT FOUND: Pool For VS {self.vs_config['vs_name']}")
            print(data.get('pool', ''))

    def extract_vs_presist(self, data):
        vs_presist = data.get('persist', {})

        if vs_presist:
            self.vs_config['vs_presist'] = []
            for presist_key, presist_info in vs_presist.items():
                if presist_info.get('default') == 'yes':
                    self.vs_config['vs_presist'].append(presist_key)
  
    def extract_vs_profiles(self, data):
        vs_profiles = data.get('profiles', {})
        # if ASM_ in profile_key: put in asm_polcies

        if vs_profiles:
            self.vs_config['vs_profiles'] = []
            self.vs_config['vs_ssl_offload'] = []
            self.vs_config['vs_asm_policies'] = []
            
            for profile_key, profile_info in vs_profiles.items():
                profile_name = profile_key.split('/')[-1]
                profile_context = profile_info.get('context', '')

                if 'ASM_' in profile_name:
                    self.vs_config['vs_asm_policies'].append(profile_name.replace('ASM_', ''))

                if profile_context == 'clientside':
                    self.vs_config['vs_ssl_offload'].append(f"{profile_name} (clientside)")
                elif profile_context == 'serverside':
                    self.vs_config['vs_ssl_offload'].append(f"{profile_name} (serverside)")
                else:
                    self.vs_config['vs_profiles'].append(profile_name)

            # Ensure that vs_ssl_offload and vs_asm_policies are always lists after loop
            if not self.vs_config['vs_ssl_offload']:
                self.vs_config['vs_ssl_offload'] = [UNSET]
            if not self.vs_config['vs_asm_policies']:
                self.vs_config['vs_asm_policies'] = [UNSET]

    def extract_vs_policies(self, data):
        vs_policies = data.get('policies', {})
        if vs_policies:
            self.vs_config['vs_policies'] = list(vs_policies.keys())
    
    def extract_vs_security_log_profiles(self, data):
        vs_security_log_profiles = data.get('security-log-profiles', {})
        if vs_security_log_profiles:
            self.vs_config['vs_security_log_profiles'] = list(vs_security_log_profiles.keys())
    
    def extract_vs_vlans(self, data):
        vs_vlans = data.get('vlans', {})

        if vs_vlans:
            self.vs_config['vs_vlans'] = []
            self.vs_config['vs_vlans_status'] = []
            for vlan_key, vlan_value in vs_vlans.items():
                vlan = vlan_key.split('/')[-1]

                vlan_status = "enable" if "vlans-enabled" in data.keys() else "disable"
                self.vs_config['vs_vlans'].append(vlan)
                self.vs_config['vs_vlans_status'].append(vlan_status)
 
    def extract_vs_snat(self, data):
        vs_snat = data.get('source-address-translation', {})
        vs_snat_port = data.get('translate-port', '')
        vs_snat_address = data.get('translate-address', '')

        if vs_snat:
            self.vs_config['vs_snat'] = vs_snat.get('type', '')
            self.vs_config['vs_snat_translation'] = (
                "port, address" if vs_snat_port and vs_snat_address else
                "port" if vs_snat_port else
                "address" if vs_snat_address else
                None
            )
    
    def extract_vs_irules(self, data):
        vs_rules = data.get('rules', {})
        if vs_rules:
            self.vs_config['vs_irules'] = list(vs_rules.keys())
    
    def identify_vs_type(self, data):
        vs_name = self.vs_config['vs_name']
        vs_service = self.as3_output_config.get(vs_name, None)
        self.vs_config['vs_type'] = vs_service.get('class', "N/A") if vs_service else "N/A"

class SelfIPProcessor:
    def __init__(self, self_ip_list, vcmp_guest_list, vlan_list, trunk_list):
        self.self_ip_list = self_ip_list
        self.vcmp_guest_list = vcmp_guest_list
        self.vlan_list = vlan_list
        self.trunk_list = trunk_list
        self.f5_self_ip_list = []
        self.vlan_interface_pattern = re.compile(r'(\d?/?\d+.\d+|mgmt|\d?/?mgmt)')


    def process_self_ips(self):
        if self.self_ip_list:
            self.process_standard_self_ips()
        elif self.vcmp_guest_list:
            self.process_vcmp_guest_self_ips()
        
        return self.f5_self_ip_list

    def process_standard_self_ips(self):
        # Process self IPs from standard configuration
        for key, data in self.self_ip_list.items():
            self.f5_self_ip = F5_IP_CONFIG.copy()

            self.f5_self_ip['self_ip'] = data.get('address', 'N/A').split("/")[0]
            self.f5_self_ip['self_ip_cidr'] = data.get('address', 'N/A').split('/')[-1]
            self.f5_self_ip['traffic-group'] = data.get('traffic-group', 'N/A')
            self.f5_self_ip['vlan'] = data.get('vlan', UNSET).split('/')[-1]
            
            if data.get('vlan'):
                self.extract_f5_vlan_details(data, self.vlan_list, vlan_name=None)
            else:
                self.f5_self_ip['vlan_id'] = UNSET
                self.f5_self_ip['interface_tag'] = [UNSET]
                self.f5_self_ip['interface_untag'] = [UNSET]
                self.f5_self_ip['trunk'] = UNSET

            self.f5_self_ip_list.append(self.f5_self_ip)

    def process_vcmp_guest_self_ips(self):
        # Process self IPs from VCMP guests
            for key, data in self.vcmp_guest_list.items():
                total_vlans = list(data.get('vlans', '').keys())
                if len(total_vlans) > 0:
                    for vlan in total_vlans:
                        self.f5_self_ip = F5_IP_CONFIG.copy()
                        self.f5_self_ip['self_ip'] = data.get('management-ip', 'N/A').split("/")[0]
                        self.f5_self_ip['self_ip_cidr'] = data.get('management-ip', 'N/A').split('/')[-1]
                        self.f5_self_ip['traffic-group'] = data.get('hostname', 'N/A') 
                        self.f5_self_ip['vlan'] = vlan.split('/')[-1]
                        self.extract_f5_vlan_details(data, self.vlan_list, vlan_name=f"net vlan {vlan}")

                        self.f5_self_ip_list.append(self.f5_self_ip)
    
    def extract_f5_vlan_details(self, data, vlan_list, vlan_name):
        if vlan_name is None:
            vlan_name = f"net vlan {data.get('vlan', '')}"  
        vlan_data = vlan_list.get(vlan_name, {})

        if vlan_data:
            self.f5_self_ip['vlan_id'] = vlan_data.get('tag', 'N/A')
            vlan_interface = vlan_data.get('interfaces', '')
            if vlan_interface:

                for interface, interface_data in vlan_interface.items():
                    interface_match = self.vlan_interface_pattern.match(interface)
                    if not interface_match:
                        interface_match = self.extract_f5_trunk(data, interface)
                        self.f5_self_ip['trunk'] = interface
                    else:
                        interface_match = interface_match.group(1)
                    
                    if 'tagged' in interface_data:
                        self.f5_self_ip['interface_tag'] = interface_match
                    else:
                        self.f5_self_ip['interface_untag'] = interface_match
    
    def extract_f5_trunk(self, data, trunk_name):
        trunk_name = f"net trunk {trunk_name}"
        trunk_data = self.trunk_list.get(trunk_name, {})

        if trunk_data:
            if 'interfaces' in trunk_data:
                return list(trunk_data['interfaces'].keys())

class DeviceInfoProcessor:
    def __init__(self, device_list, sys_config_list):
        self.device_list = device_list
        self.sys_config_list = sys_config_list
        self.f5_device_info_list = []
        self.device_pattern = re.compile(r'\"(.+?)(?:, \S+)?, (\S+?)\|')

    def process_device_info(self):
        for key, data in self.device_list.items():
            self.f5_device_info = F5_DEVICE_CONFIG.copy()
            self.extract_device_details(data)
            self.extract_system_configurations(data)
            self.f5_device_info_list.append(self.f5_device_info)
        
        return self.f5_device_info_list

    def extract_device_details(self, data):
        # Extract basic device information like model, serial, version
        active_modules = data.get('active-modules', '') # Example: "BIG-IP, 1SLOT, Z100|BIG-IP"

        if active_modules:
            device_pattern_match = self.device_pattern.search(active_modules)
            self.f5_device_info['device_model'] = device_pattern_match.group(2)
            self.f5_device_info['device_type'] = device_pattern_match.group(1)
        else:
            self.f5_device_info['device_model'] = "N/A"
            self.f5_device_info['device_type'] = "N/A"
        
        self.f5_device_info['serial_number'] = data.get('chassis-id', 'N/A').replace("\"","").strip()
        version = f"{data.get('product', 'N/A')} {data.get('version', 'N/A')} Build {data.get('build', 'N/A')} {data.get('edition', 'N/A')}"
        version = version.replace("\"","")
        self.f5_device_info['version'] = version
        self.f5_device_info['hostname'] = data.get('hostname', 'N/A')
        self.f5_device_info['management_ip'] = data.get('management-ip', 'N/A')
        self.f5_device_info['config_sync_ip'] = data.get('configsync-ip', 'N/A')

    def extract_system_configurations(self, data):
        # Extract SNMP, syslog, NTP, DNS, TACACS configurations
        self.extract_f5_snmp(self.sys_config_list)
        self.extract_f5_syslog(self.sys_config_list)
        self.extract_f5_ntp(self.sys_config_list)
        self.extract_f5_dns(self.sys_config_list)
        self.extract_f5_tacacs(self.sys_config_list)
    
    def extract_f5_snmp(self, sys_list):
        snmp_data = sys_list.get('sys snmp', {})

        if snmp_data:
            if snmp_data.get('allowed-addresses'):
                self.f5_device_info['snmp'] = snmp_data.get('allowed-addresses', "")
            else:
                self.f5_device_info['snmp'] = [UNSET]

    def extract_f5_syslog(self, sys_list):
        syslog_data = sys_list.get('sys syslog', {})

        if syslog_data:
            self.f5_device_info['sys_log'] = []
            remote_syslog_servers = syslog_data.get('remote-servers', [])
            if remote_syslog_servers:
                for server_key, server_info in remote_syslog_servers.items():
                    for key, value in server_info.items():
                        if key == 'host':
                            self.f5_device_info['sys_log'].append(value)
            else:
                self.f5_device_info['sys_log'] = [UNSET]

    
    def extract_f5_ntp(self, sys_list):
        ntp_data = sys_list.get('sys ntp', {})
        if ntp_data:
            if ntp_data.get('servers'):
                self.f5_device_info['ntp'] = ntp_data.get('servers', '')
            else:
                self.f5_device_info['ntp'] = [UNSET]
    
    def extract_f5_dns(self, sys_list):
        dns_data = sys_list.get('sys dns', {})
        if dns_data:
            if dns_data.get('name-servers'):
                self.f5_device_info['dns'] = dns_data.get('name-servers', '')
            else:
                self.f5_device_info['dns'] = [UNSET]
    
    def extract_f5_tacacs(self, sys_list):
        tacacs_data = sys_list.get('auth tacacs /Common/system-auth', {})
        if tacacs_data:
            if tacacs_data.get('servers'):
                self.f5_device_info['tacacs'] = tacacs_data.get('servers', '')
            else:
                self.f5_device_info['tacacs'] = [UNSET]
        
class SNATProcessor:
    def __init__(self, snat_list, snat_pool_list):
        self.snat_list = snat_list
        self.snat_pool_list = snat_pool_list
        self.f5_snat_info_list = []

    def process_snats(self):
        for key, data in self.snat_list.items():
            self.f5_snat_info = F5_SNAT_CONFIG.copy()

            self.create_base_snat_config(key, data)
            self.process_snat_details(data)

            self.f5_snat_info_list.append(self.f5_snat_info)
        return self.f5_snat_info_list

    def create_base_snat_config(self, key, data):
        # Create base SNAT configuration
        self.f5_snat_info['snat_name'] = key.split('/')[-1]
        self.f5_snat_info['snat_pool_name'] = data.get('snatpool', UNSET)

    def process_snat_details(self, data):
        # Process SNAT origins, translations, pools, VLANs
        self.extract_f5_snat_origin(data)
        self.extract_f5_snat_vlan(data)
        
        # if there is no translation ip, then it is a snat pool
        if data.get("translation"):
            self.f5_snat_info['translation_ip'] = data.get('translation', UNSET).split('/')[-1]
        elif data.get("snatpool"):
            self.extract_f5_snat_pool(data, self.snat_pool_list)

    def extract_f5_snat_origin(self, data):
        snat_origin = data.get('origins', {})

        if snat_origin:
            self.f5_snat_info['origins_ip'] = list(snat_origin.keys())
        else:
            self.f5_snat_info['origins_ip'] = UNSET
             

    def extract_f5_snat_pool(self, data, snat_pool_list):
        snat_pool_name = f"ltm snatpool {data.get("snatpool", "")}"
        pool_data = snat_pool_list.get(snat_pool_name, {})

        if pool_data:
            self.f5_snat_info['translation_ip'] = []
            members = pool_data.get('members', {})
            if members:
                for member_key, member_value in members.items():
                    address_info = member_key.split('/')[-1]
                    self.f5_snat_info['translation_ip'].append(address_info)
            else:
                self.f5_snat_info['translation_ip'] = UNSET
        else:
            print(f"NOT FOUND: SNAT Pool For VS")
            print(data.get("snatpool", ""))

            
    def extract_f5_snat_vlan(self, data):
        snat_vlan = data.get('vlans', {})

        if snat_vlan:
            self.f5_snat_info['vlan'] = []
            self.f5_snat_info['vlan_status'] = []
            for vlan_key, vlan_value in snat_vlan.items():
                vlan = vlan_key.split('/')[-1]

                vlan_status = "enable" if "vlans-enabled" in data.keys() else "disable"
                self.f5_snat_info['vlan'].append(vlan)
                self.f5_snat_info['vlan_status'].append(vlan_status)
        else:
            # Where indicate all vlan
            self.f5_snat_info['vlan'] = UNSET

class RouteProcessor:
    def __init__(self, route_list, ltm_pool_list):
        self.ltm_pool_list = ltm_pool_list
        self.route_list = route_list
        self.f5_route_info_list = []
    
    def process_routes(self):
        for key, data in self.route_list.items():
            self.f5_route_info = F5_ROUTE_CONFIG.copy()
            if key.startswith("sys management-route"):
                self.f5_route_info['gateway'] = data.get('gateway', UNSET)
                self.f5_route_info['network'] = f"management-route {data.get('network', UNSET)}"
                self.f5_route_info['description'] = data.get('description', UNSET)
            
            elif key.startswith("net route"):
                if data.get('gw'):
                    self.f5_route_info['gateway'] = data.get('gw', UNSET)
                elif data.get('pool'):
                    self.extract_vs_pool(data, self.ltm_pool_list) # Passing Virtual Server and Pools list
                    # print(f"Gateway: {self.f5_route_info['gateway']}")
                else:
                    self.f5_route_info['gateway'] = UNSET
                
                self.f5_route_info['network'] = data.get('network', UNSET)
                self.f5_route_info['description'] = data.get('description', UNSET)

            self.f5_route_info_list.append(self.f5_route_info)
        return self.f5_route_info_list
    
    def extract_vs_pool(self, data, ltm_pool_list):
        # Get Pool name from Virtual Server data, then serach in Pools list
        vs_pool = f"ltm pool {data.get('pool', '')}"
        pool_data = ltm_pool_list.get(vs_pool, {})
      
        if pool_data:
            self.f5_route_info['gateway'] = []

            members = pool_data.get('members', {})
            for member_key, member_info in members.items():
                address_port = re.search(r'(\:\S+)', member_key).group(0)
                address = member_info.get('address')
                session = member_info.get('session')
                state = member_info.get('state')

                if session and state:
                    full_address = f"{address}{address_port}:{session}:{state}"
                else:
                    full_address = f"{address}{address_port}"

                self.f5_route_info['gateway'].append(full_address)
        else:
            print(f"NOT FOUND: Pool For VS")
            print(data.get('pool', ''))


if __name__ == "__main__":    
    os.makedirs(CONFIG_OUTPUT_FOLDER, exist_ok=True)
    os.makedirs(JSON_OUTPUT_FOLDER, exist_ok=True)
    
    if not os.listdir(CONFIG_OUTPUT_FOLDER): # 
        print("No config files found in the output folder, extracting from tar files...")
        BigIPConfigExtractor()

    for item_name in os.listdir(CONFIG_OUTPUT_FOLDER):
        # Construct the full path to the item
        item_path = os.path.join(CONFIG_OUTPUT_FOLDER, item_name)

        # Check if the item is actually a directory
        if os.path.isdir(item_path):
            print(f"\nProcessing directory: [{item_name}]")
            config_files = {}
            # Iterate through files inside this directory
            for config_filename in os.listdir(item_path):
                config_file_path = os.path.join(item_path, config_filename)

                # Optional but recommended: Ensure it's a file, not a nested directory
                if os.path.isfile(config_file_path):
                    try:
                        with open(config_file_path, "r", encoding='utf-8') as f: # Added encoding
                            config_files[config_filename] = f.read()
                    except Exception as e:
                        print(f"Error reading file {config_file_path}: {e}")
                else:
                    print(f"Skipping non-file item in directory {item_name}: {config_filename}")


            # Only parse and write if we actually found config files
            if config_files:
                try:
                    # Parse the collected config files for this directory
                    parser = BigIPConfigParser() # Instantiate parser here if it holds no state across dirs
                    json_dump = parser.parse_files(config_files)
                    print(f"Parsed [{item_name}] successfully")

                    # Write the JSON output for this directory
                    output_json_path = os.path.join(JSON_OUTPUT_FOLDER, f"{item_name}.json")
                    with open(output_json_path, "w", encoding='utf-8') as f: # Added encoding
                        json.dump(json_dump, f, indent=4)
                    print(f"Written JSON for [{item_name}] to {output_json_path}")

                    # Perform export for this directory
                    BigIPConfigExporter(item_name)

                except Exception as e:
                     print(f"Error processing directory {item_name}: {traceback.format_exc()}")

            else:
                print(f"No valid config files found in directory: [{item_name}]")

        else:
            # This item is not a directory (e.g., .DS_Store), skip it
            print(f"Skipping non-directory item: [{item_name}]")
    
    input("Press Enter to exit...")
