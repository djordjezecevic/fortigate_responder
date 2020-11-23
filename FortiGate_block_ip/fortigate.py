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
            body = { 'name':self.adr_name ,'subnet':self.observable + " 255.255.255.255" }
            
            try:
                #check if address exist in fortigate
                r = requests.get(("https://" + self.fortigate_ip + ":" + self.fortigate_port + payload + self.adr_name +"?access_token=" + self.fortigate_api),verify=self.ca_path)
                if r.status_code == 200:
                    logging.info("address already exists, skip adding")
            except requests.exceptions.RequestException as e:
                logging.error("r: " + e)
            if r.status_code != 200:
                #add adress to fortigate
                try:
                    r1 = requests.post(("https://" + self.fortigate_ip + ":" + self.fortigate_port + payload + "?access_token=" + self.fortigate_api), data=json.dumps(body),verify=self.ca_path)
                    if r1.status_code == 200:
                        logging.info("Address "  + self.adr_name + " added to fortigate ")
                except requests.exceptions.RequestException as e:
                    logging.error("r1 " + e)
            
            #read adresses in address group
            logging.info("Reading addreses from adressgroup")
            try:
                r2 = requests.get(("https://" + self.fortigate_ip + ":" + self.fortigate_port + payload2 + self.fortigate_addgrp + "?access_token=" + self.fortigate_api), verify=self.ca_path)
            except requests.exceptions.RequestException as e:
                    logging.error("r2 " + e)
            #logging.debug(r2.json())
            body3 = r2.json()['results'][0]['member']
            logging.debug(body3)
            logging.info("Appending new member")
            body3.append({"name":  self.adr_name, "q_origin_key":  self.adr_name })
            #logging.info("Removing potential duplicates")
            logging.debug(json.dumps(body3))
            body_update_group = {"name": self.fortigate_addgrp, 'member': body3 }
            logging.debug(json.dumps(body_update_group))
            #Modify group to add old + new addresses
            logging.info("Adding addresses in addres group")
            try:
                r3 = requests.put(("https://" + self.fortigate_ip + ":" + self.fortigate_port + payload2 + self.fortigate_addgrp + "?access_token=" + self.fortigate_api), verify=self.ca_path, data=json.dumps(body_update_group))
                if r3.status_code == 200:
                    logging.info("Address added to a group " + self.fortigate_addgrp)
                else:
                    logging.error("Address not added. Status code " + str(r3.status_code))
            except requests.exceptions.RequestException as e:
                    logging.error("r3 " + e)
            #if r.status_code == 200 and r2.status_code == 200 and r3.status_code == 200:
            if r.status_code == 200:
                self.report({'message': "Added DROP rule for " + self.observable  })
            else:
                self.error("Doslo je do greske r1" + str(r.status_code))
        except OSError as err:
            self.error("OS error:" + self.fortigate_ip + " {0}".format(err))
        except:
            self.error("Program pukao", sys.exc_info()[0])

    def operations(self, raw):
        return [self.build_operation('AddTagToCase', tag='Fortigate: Blocked IP')]

if __name__ == '__main__':
    FortiGate().run()
