#!/usr/bin/env python3
from cortexutils.responder import Responder
import requests
import ipaddress, json
import sys,logging

class FortiGate(Responder):
    def __init__(self):
    
        Responder.__init__(self)
        self.fortigate_ip = self.get_param('config.fortigate_ip', None, 'https://localhost')
        self.fortigate_port = self.get_param('config.fortigate_port', None, 'Port missing!')
        self.fortigate_api = self.get_param('config.fortigate_api', None, 'API missing!')
        self.fortigate_addgrp = self.get_param('config.fortigate_addrgrp', None, "Address group is required !")
        self.observable = self.get_param('data.data', None, "Data is empty")
        self.observable_type = self.get_param('data.dataType', None, "Data type is empty")
        self.ca_path = self.get_param('config.fortigate_cert', None, 'Path to cert')
        logging.basicConfig(filename='/tmp/app.log', level=logging.DEBUG)
    
    
    def run(self):
    
        try:
            logging.info('-- responder is starting --')
            Responder.run(self)
            headers = {'Content-Type': 'application/json'}
            
            # Check observable to ensure valid IP address
            if self.observable_type == "ip":
                try:
                    ipaddress.ip_address(self.observable)
                except ValueError:
                    self.error({'message': "Not a valid IPv4/IPv6 address!"})
            else:
                self.error({'message': "Not a valid IPv4/IPv6 address!"})

            payload = "/api/v2/cmdb/firewall/address/"
            payload2 = "/api/v2/cmdb/firewall/addrgrp/"
            self.adr_name = "HIVE" + self.observable
            
            try:
                #check if address exist in fortigate
                r = requests.get(("https://" + self.fortigate_ip + ":" + self.fortigate_port + payload + self.adr_name +"?access_token=" + self.fortigate_api),verify=self.ca_path)
                if r.status_code == 200:
                
                    logging.info("address found, reading blocking group.")
                    
                    
                    try:
                        #read adresses in address group
                        r2 = requests.get(("https://" + self.fortigate_ip + ":" + self.fortigate_port + payload2 + self.fortigate_addgrp + "?access_token=" + self.fortigate_api), verify=self.ca_path)

                        addres_group = r2.json()['results'][0]['member']
                        
                        #remove IP from group
                        for address in addres_group:
                            if address['name'] == self.adr_name:
                                addres_group.remove(address)
                                
                        updated_group = {"name": self.fortigate_addgrp, 'member': addres_group }
                    
                    except:
                        self.error("Pukao R2")
                    
                    try:
                        #update group on FortiGate
                        r3 = requests.put(("https://" + self.fortigate_ip + ":" + self.fortigate_port + payload2 + self.fortigate_addgrp + "?access_token=" + self.fortigate_api), verify=self.ca_path, data=json.dumps(updated_group))

                        if r3.status_code == 200:
                            self.report({'message': "IP is no longer blocked on FortiGate"  })
                            
                        else:
                            logging.error("Doslo je do greske!")
                    except:
                        self.error("Pukao R3")
                        

                       #remove IP form FortiGate
                    try:
                        r4 = r = requests.delete(("https://" + self.fortigate_ip + ":" + self.fortigate_port + payload + self.adr_name +"?access_token=" + self.fortigate_api),verify=self.ca_path)
                    
                    except:
                        self.error("Pukao R4")
                else:
                    self.error({'message': "IP Address not blocked on FortiGate!"})
                    
            except requests.exceptions.RequestException as e:
                logging.error("r: " + e)
            
        except OSError as err:
            self.error("OS error:" + self.fortigate_ip + " {0}".format(err))
        except:
            self.error("Program pukao", sys.exc_info()[0])


    def operations(self, raw):
        return [self.build_operation('AddTagToCase', tag='Fortigate: Blocked IP')]


if __name__ == '__main__':
    FortiGate().run()
