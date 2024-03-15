import socket
from threading import Thread
import sys
import queue
import time
import pickle
from scapy.all import *
import psycopg2
import random
import os

if len(sys.argv)!=7:
    print('python3 proxy.py <local_ip> <loop_probe_table_name> <sampled_payloads_file> <cycle_result_output> <start_port> <target_port>')
    exit(0)

local_ip = sys.argv[1]
scan_2nd_table_name = sys.argv[2]
scan_payload_file = sys.argv[3]
cycle_ip_dict_file = sys.argv[4]
start_port = int(sys.argv[5])
proto_port = int(sys.argv[6])




TRUE_POSITIVE_CAP = 25
RATE_LIMIT = 3
SAMPLED_PAIRS_PER_CYCLE = 100
OVER_ALL_TIMEOUT = 300


class Host():
    def __init__(self,host_ip,host_port,ratelimit=3):
        self.host_ip = host_ip
        self.host_port = host_port
        self.ratelimit = ratelimit
        self.last_sent_time = int(time.time()*10)
        self.interval = int((1.0/(ratelimit * 1.0))*10)
    def get_addr(self):
        return (self.host_ip,self.host_port)

    def get_and_update_next_pac_time(self):
        curr_time = int(time.time()*10)
        self.last_sent_time = max(curr_time,self.last_sent_time+self.interval)
        return self.last_sent_time
        

class Loop_pair():
    def __init__(self, local_ip, local_port, host_A, host_B):
        self.host_A = host_A
        self.host_B = host_B
        
        self.host_A_ip,self.host_A_port = host_A.get_addr()
        self.host_B_ip,self.host_B_port = host_B.get_addr()

        self.local_ip = local_ip
        self.local_port = local_port

        self.prepared_to_A_pac = IP(src=local_ip,dst=self.host_A_ip)/UDP(sport=local_port,dport=self.host_A_port)
        self.prepared_to_B_pac = IP(src=local_ip,dst=self.host_B_ip)/UDP(sport=local_port,dport=self.host_B_port)

        self.total_rcv_counter = 0

    def get_peer_pac(self,ip_addr):
        if self.host_A_ip==ip_addr:
            return (self.prepared_to_B_pac,self.host_B)
        elif self.host_B_ip==ip_addr:
            return (self.prepared_to_A_pac,self.host_A)
        else:
            raise Exception()

    def get_host_A_addr(self):
        return (self.host_A_ip, self.host_A_port)
    
    def get_host_B_addr(self):
        return (self.host_B_ip, self.host_B_port)



class Proxy_core():
    def __init__(self,local_ip,cycle_ip_dict_file,scan_payload_file,scan_2nd_table_name,timeout,protocol_port,start_port_number):
        self.timeout = timeout  
        self.protocol_port = protocol_port
        self.raw_sock = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_UDP)
        self.raw_sock.setsockopt(0,socket.IP_HDRINCL,1)
        self.raw_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 52428800) 
        self.local_ip = local_ip
        self.raw_sock.bind((local_ip,0)) 
        self.port_pair_mapping = {}
        self.cycle_pair_mapping = {}
        self.ip_hostobj_mapping = {}
        self.send_queue = queue.PriorityQueue()
        self.input_queue = queue.Queue()

        self.work_scheduler(cycle_ip_dict_file,scan_payload_file,scan_2nd_table_name,start_port_number)

        # ----- threading init -----
        thread1 = Thread(target=self.worker_recv)
        thread2 = Thread(target=self.worker_send)
        thread4 = Thread(target=self.worker_pac_build)

        thread1.start()
        thread2.start()
        thread4.start()
        # listening started
        # next step is to send initial probes so we can cause a loop
        for cycle in self.cycle_pair_mapping.keys():
            pair_list,init_payload = self.cycle_pair_mapping[cycle]
            for loop_pair in pair_list:
                packet = IP(raw(loop_pair.prepared_to_A_pac/init_payload))
                self.raw_sock.sendto(bytes(packet),loop_pair.get_host_A_addr())
                time.sleep(0.05)


        thread3 = Thread(target=self.progress_check)
        thread3.start()

    def work_scheduler(self,cycle_ip_dict_file,scan_payload_file,scan_2nd_table_name,start_port_number):
        f = open(scan_payload_file,'rb')
        payload_dict = pickle.load(f)
        f.close()
        
        self.most_replied_probe_each_cluster = {}
        db_name = "loop_scan"
        db_conn = psycopg2.connect(database=db_name, user="scan")
        db_conn.autocommit = True
        cursor = db_conn.cursor()
        # select_command = "SELECT ARRAY_LENGTH(ARRAY_agg(DISTINCT rsp_src_ip),1) as c,attack_name,index FROM %s GROUP BY index,attack_name ORDER BY c DESC;" % scan_2nd_table_name
        select_command = "SELECT ARRAY_LENGTH(ARRAY_agg(DISTINCT rsp_src_ip),1),attack_name,index FROM %s GROUP BY index,attack_name ORDER BY attack_name,index DESC;" % scan_2nd_table_name
        cursor.execute(select_command)
        all_data = cursor.fetchall()
        for entry in all_data:
            if not entry[1] in self.most_replied_probe_each_cluster:
                self.most_replied_probe_each_cluster[entry[1]] = int(entry[2])

        f = open(cycle_ip_dict_file,'rb')
        cycle_ip_dict = pickle.load(f)
        f.close()

        # per_cycle_init = {}
        # cluster_table = '' 
        # for cycle in cycle_ip_dict.keys():
            # init_payload_type = cycle[1:-1].split(', ')[0] 
            # second_payload_type = cycle[1:-1].split(', ')[1]
            # select_command = "select ARRAY_LENGTH(ARRAY_agg(DISTINCT rsp_src_ip),1) as c, attack_name, index FROM (select * from %s JOIN %s on rsp_payload=payload WHERE attack_name='%s' and type_id=%s) as t GROUP BY index,attack_name ORDER BY c DESC;" % (scan_2nd_table_name,cluster_table,init_payload_type,second_payload_type)
            # cursor.execute(select_command)
            # all_data = cursor.fetchall()
            # for entry in all_data:
            #     if not cycle in per_cycle_init:
            #             per_cycle_init[cycle] = entry[2]



        for cycle in cycle_ip_dict.keys():
            self.cycle_pair_mapping[cycle] = [[],'']
            host_A_ips = (random.sample(cycle_ip_dict[cycle][0],SAMPLED_PAIRS_PER_CYCLE))
            host_B_ips = (random.sample(cycle_ip_dict[cycle][1],SAMPLED_PAIRS_PER_CYCLE))
            if len(host_A_ips)<100 or len(host_B_ips)<100:
                print('cycle ', cycle ,'does not have enough ips for sampling')

            initiate_probe_type = cycle[1:-1].split(',')[0]
            payload_to_initiate = payload_dict[initiate_probe_type][self.most_replied_probe_each_cluster[initiate_probe_type]]
            # payload_to_initiate = payload_dict[initiate_probe_type][int(per_cycle_init[cycle])]
            
            self.cycle_pair_mapping[cycle][1] = bytes.fromhex(payload_to_initiate)
    
            for i in range(0,SAMPLED_PAIRS_PER_CYCLE):
                if not host_A_ips[i] in self.ip_hostobj_mapping:
                    self.ip_hostobj_mapping[host_A_ips[i]] = Host(host_A_ips[i],self.protocol_port,ratelimit=RATE_LIMIT)
                if not host_B_ips[i] in self.ip_hostobj_mapping:
                    self.ip_hostobj_mapping[host_B_ips[i]] = Host(host_B_ips[i],self.protocol_port,ratelimit=RATE_LIMIT)
                loop_pair_object = Loop_pair(self.local_ip,start_port_number,self.ip_hostobj_mapping[host_A_ips[i]],self.ip_hostobj_mapping[host_B_ips[i]])

                self.port_pair_mapping[start_port_number] = loop_pair_object
                self.cycle_pair_mapping[cycle][0].append(loop_pair_object)
                start_port_number = start_port_number + 1
                if start_port_number > 65535:
                    raise Exception('out of ports')
            

    def worker_pac_build(self):
        while(True):
            try:
                self.build_queued_pac(self.input_queue.get())
            except:
                pass
    
    def build_queued_pac(self,packet):
        try:
            proto = int.from_bytes(packet[9:10])
            if proto!=17:
                return
            src_port = int.from_bytes(packet[20:22])
            dst_port = int.from_bytes(packet[22:24])
            
            if src_port!=self.protocol_port: 
                return
            loop_pair = self.port_pair_mapping[dst_port]
        except:
            return
        
        
        try:
            packet_to_sent,target_host = loop_pair.get_peer_pac(socket.inet_ntoa(packet[12:16]))
        except:
            return

        if loop_pair.total_rcv_counter >= TRUE_POSITIVE_CAP:
            return
        loop_pair.total_rcv_counter = loop_pair.total_rcv_counter + 1


        addr_tuple = target_host.get_addr()
        pac = IP(raw(packet_to_sent/packet[28:]))
        send_time = target_host.get_and_update_next_pac_time()
        self.send_queue.put((send_time,(pac,addr_tuple)))

    def worker_recv(self):
        while(True):            
            packet = self.raw_sock.recv(8096)
            self.input_queue.put(packet)

    def worker_send(self):
        while(True):
            try:
                send_time = self.send_queue.queue[0][0]
            except:
                pass
            else:
                curr_time = int(time.time()*10)
                if send_time<=curr_time:
                    pac,addr_tuple = self.send_queue.get()[1]
                    try:
                        self.raw_sock.sendto(bytes(pac),addr_tuple)
                    except Exception as e:
                        print(str(e), ' : ', bytes(pac), ' : ', addr_tuple)

    def progress_check(self):
        start_time = time.time()
        while(True):
            time.sleep(30)
            curr_time = time.time()
            if curr_time-start_time > self.timeout:
                f = open('udp_proxy_result.log','w')
                for key in self.cycle_pair_mapping.keys():
                    f.write(str(key).strip() + '\n')
                    for pair in self.cycle_pair_mapping[key][0]:
                        line = str(pair.get_host_A_addr()) + ' : ' + str(pair.get_host_B_addr()) + ':' + str(pair.total_rcv_counter) + '\n'
                        f.write(line)
                    pair.total_rcv_counter = TRUE_POSITIVE_CAP + 1
                f.close()
                print('-----End-----')
                os._exit(0)
            else:
                lines = []
                for key in self.cycle_pair_mapping.keys():
                    temp_counter = 0
                    for pair in self.cycle_pair_mapping[key][0]:
                        if pair.total_rcv_counter >= TRUE_POSITIVE_CAP:
                            temp_counter = temp_counter + 1
                    line = str(key).strip() + ' : ' + str(temp_counter) + '/' + str(len(self.cycle_pair_mapping[key][0])) + '\n'
                    lines.append(line)


                f = open('progress.log','w')
                for line in lines:
                    f.write(line)
                f.write(str(time.time()))
                f.close()



proxy = Proxy_core(local_ip,cycle_ip_dict_file,scan_payload_file,scan_2nd_table_name,OVER_ALL_TIMEOUT,proto_port,start_port) 
