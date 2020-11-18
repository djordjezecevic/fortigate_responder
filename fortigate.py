#!/usr/bin/env python3
from cortexutils.responder import Responder
import requests
import ipaddress, json

class FortiGate(Responder):
    def __init__(self):
        Responder.__init__(self)
        self.fortigate_ip = self.get_param('config.fortigate_ip', None, 'https://localhost')
        self.fortigate_port = self.get_param('config.fortigate_port', None, 'Port missing!')
        self.fortigate_api = self.get_param('config.fortigate_api', None, 'API missing!')
        self.fortigate_addgrp = self.get_param('config.fortigate_addrgrp', None, "Address group is required !")
        self.observable = self.get_param('data.data', None, "Data is empty")
        self.observable_type = self.get_param('data.dataType', None, "Data type is empty")

    def run(self):
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

        body = { 'name':"HIVE" + self.observable ,'subnet':self.observable + " 255.255.255.255" }


        #add adress to fortigate
        r = requests.put(("https://" + self.fortigate_ip + ":" + self.fortigate_port + payload + "?access_token=" + self.fortigate_api), verify="fortigate_responder/certca.pem", data=json.dumps(body))

        #read adresses in address group
        #r2 = requests.get(("https://" + self.fortigate_ip + ":" + self.fortigate_port + payload2 + self.fortigate_addgrp + "?access_token=" + self.fortigate_api), verify=False)

        #body3 = r2['results'][0]['member']
        #body3.append({"name":  "HIVE" + self.observable, "q_origin_key":  "HIVE" + self.observable })
        #Modify group to add old + new addresses
        #r3 = requests.put(("https://" + self.fortigate_ip + ":" + self.fortigate_port + payload2 + self.fortigate_addgrp + "?access_token=" + self.fortigate_api), verify=False, data=body3)

        #if r.status_code == 200 and r2.status_code == 200 and r3.status_code == 200:
        if r.status_code == 200:
            self.report({'message': "Added DROP rule for " + self.observable  })
        else:
            self.error({'success': "false", 'errorMessage' :"Doslo je do greske r1" + str(r.status_code) })

    def operations(self, raw):
        return [self.build_operation('AddTagToCase', tag='Fortigate: Blocked IP')]

if __name__ == '__main__':
    FortiGate().run()
