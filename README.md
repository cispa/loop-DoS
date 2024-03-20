#### Setup:

Postgresql:

    db_name: loop_scan
    user_name: scan

Zmap
Scapy 2.5.0

#### STEP 1: Discovery Probe
1. prepare the scan allowlist (a list of all server IPs running certain protocol).

    The file shall be named as:
        
        allowlist_<proto>.txt 
        e.g., allowlist_dns.txt
        
    Example content of the file:

        X.X.X.X/32
        X.X.X.X/32
        ...

    In case you want to scan a subnet e.g., X.X.X.X/16 or 0.0.0.0/0, remove the following from discovery_probe.py and loop_probe.py

        --max-targets=" + str(num_probes) + " \\\n\
    


2. prepare the blacklist (a list of all server IPs that are not scanned).

    The file shall be named as:
        
        blacklist.txt
    
    Example content of the file:

        X.X.X.X/32
        192.168.0.0/16
        ...

3. prepare the config file for zmap:

    The file is named as:

        box.config
    
    Example content of the file:

        interface <your interface>
        source-ip <your scanner ip>
        gateway-mac <your gateway mac>
    

4. run ```python3 discovery_probe.py <protocol> <num_ips_to_probe>``` (num_ips_to_probe=-1 means all)

        e.g., python3 discovery_probe.py ntp -1

5. Upon finishing, a table with all responses collected from server will be created:

        named as : <protocol>_rsps_<num_probes>_probed_<timestamp>
    
        e.g., ntp_rsps_10000_probed_1609562355

--------------

The ```discovery_probe.py``` script will use probes prepared in ```proto_attack_profiles.py```. If you want to add more discovery probes, see the comment in ```proto_attack_profiles.py```.


#### STEP 2: Response Clustering
1. run ```python3 dns/ntp/tftp_clustering.py <scan_table> <cluster_table> <type_summary_id_mapping_dict>```

        <scan_table>: the table containing responses collected from servers during discovery probe (Step 1).
        e.g., ntp_rsps_10000_probed_1609562355

        <cluster_table>: table used to save the clustering result, i.e., the cluster id of each payload
        e.g., ntp_cluster_discovery

        <type_summary_id_mapping_dict>: file used to save the summary of each cluster id.
        e.g., ntp_mapping_dict.pkl



#### STEP 3: Loop Probe
1. run ```python3 sample_loop_probe_payloads.py <proto> <discovery_table> <cluster_table> <responder_amount>``` to sample payloads.

        <proto>: target protocol
        e.g., DNS

        <discovery_table>: the table containing responses collected from servers during discovery probe.
        e.g., ntp_rsps_10000_probed_1609562355

        <cluster_table>: clustering result table in STEP 2
        e.g., ntp_cluster_discovery

        <responder_amount>: ignore clusters with under <responder_amount> distinct responders.
        e.g. 10000

    Upon finishing, a file ```<proto>_payload.pkl``` containing saved payloads will be created.
    The file contains a dict:

        {
            'cluster_type':[payloads1, payloads2],
            'cluster_type2':[payloads1, payloads2],
            ...
        }
    
    To see the detail of sampled payloads, you can use:

        import pickle
        import pprint
        f = open('<proto>_payload.pkl','rb')
        d = pickle.load(f)
        pprint.pprint(d)


2. run ```python3 loop_probe.py <proto1> <proto2> <num_ips_to_probe>``` to perform the loop probe.

        e.g., python3 loop_probe.py ntp ntp -1

    The loop probe script use the same configuration files as STEP 1. 

    Upon finishing a table containig scanning result as follow would be created:

        <proto1>_target_<proto2>_pkts_rsps_<num_probes>_probed_<timestamp>
        e.g., ntp_target_ntp_pkts_rsps_10000_probed_1609562355


    The loop_probe.py script is also capable to explore cross-protocol. For example, once you have the ```tftp_payload.pkl``` prepared, you can explore TFTP+DNS loop using:

        python3 loop_probe.py dns tftp -1
        This will use sampled tftp payloads to scan DNS resolvers.

3. run ```python3 dns/ntp/tftp_clustering.py <scan_table> <cluster_table> <type_summary_id_mapping_dict>```

        <scan_table> : the table generated in loop probe (Step 3.2).

        <cluster_table> : the table to save clustering result.

        <type_summary_id_mapping_dict> : please use the same <type_summary_id_mapping_dict> as the one used in STEP 2, so for known cluster types, you won't get a new cluster id.

4. run ```python3 cluster_verify.py <loop_probe_scan_result_table> <sampled_payloads_file>``` to check the clustering effectiveness. 

        <loop_probe_scan_result_table> : the table from Step 3.2
        e.g., ntp_target_ntp_pkts_rsps_10000_probed_1609562355

        <sampled_payloads_file> : the file containing sampled payloads, from Step 3.1


#### STEP 4: Loop Graph
1. run ```python3 draw_directed_graph.py <loop_probe_result_table> <loop_probe_cluster_result> <cycle_result_output>``` to get the loop graph.

        <loop_probe_result_table>: the table from Step 3.2 
        
        <loop_probe_cluster_result>: the cluster table from Step 3.3

        <cycle_result_output> : the file containing identified cycles and vulnerable hosts.
        The file contains a dict, where the key is the identified cycle:

        {
            '[cluster1, cluster2, cluster1]':[[IP_list_1],[IP_list_2]],
            '[cluster1, cluster1]':[[IP_list_1],[IP_list_2]],
            ...
        }


The script will also show a table which summarizes identified cycles and number of affected IPs using stdout.

#### STEP 5: Loop Verify:
1. run ```python3 proxy.py <local_ip> <loop_probe_table_name> <sampled_payloads_file> <cycle_result_output> <start_port> <target_port>``` to verify identified loops.

        <local_ip> : the IP used by the proxy verifier
        <loop_probe_table_name> : the table from Step 3.2
        <sampled_payloads_file> : the file containing sampled payload from Step 3.1
        <cycle_result_output> : the file containing identified cycles from Step 4
        <start_port> : the proxy server use one port per sampled loop pair, this value definies the first port to be used.
        e.g., 10000
        <target_port> : use 53, 123, 69 for DNS, NTP, and TFTP respectively.


Upon finishing, the script will creat two files:

        progress.log : summarizies the success rate for each cycle
        udp_proxy_result.log : provides more detail regarding how much packets are sent among each sampled pair.

    
