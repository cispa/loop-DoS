import logging
import pandas as pd
import proto_attack_profiles
import psycopg2
import random
import string
from subprocess import call
import time
import os
import sys

DEBUG = True
logging.basicConfig(level=logging.DEBUG, format="[%(asctime)s]    %(message)s")


db_name = "loop_scan"
db_conn = psycopg2.connect(database=db_name, user="scan")
db_conn.autocommit = True
db_cursor = db_conn.cursor()

proto = sys.argv[1].lower()


proto_profile = proto_attack_profiles.proto_to_profile[proto]

trunc_timestamp = str(time.time()).rpartition(".")[0]
num_probes = int(sys.argv[2])
if DEBUG: logging.debug("START: counting lines in allowlist.")
with open(r"allowlist_" + proto + ".txt", 'r') as fp:
    num_allowed_ips = len(fp.readlines())
if (num_probes < 0) or (num_probes > num_allowed_ips):
    num_probes = num_allowed_ips
if DEBUG: logging.debug("FINISHED: counting lines in allowlist.\n")

responses_storage_name = proto + "_rsps_" + str(num_probes) + "_probed_" + trunc_timestamp

create_new_table_sql = "CREATE TABLE IF NOT EXISTS " + responses_storage_name + "(saddr inet NOT NULL,\
data text NOT NULL, attack_name text NOT NULL);"
if DEBUG: logging.debug("START: creating sql responses table.")
db_cursor.execute(create_new_table_sql)
if DEBUG: logging.debug("FINISHED: creating sql responses table.\n")


num_allowlists = 1

for i in range(num_allowlists):

    allowlist_path = "allowlist_" + proto + ".txt"
    attacks = proto_profile.attack_name_to_pkt
    sending_port = 50000  
    
    # the server might deploy source port filtering -> to filter out well-known port number 
    # if you want to get rid of these cases, use the following code
    # proto_to_port = { "dns" : 53, "ntp" : 123, "tftp" : 69 } 
    # target_port = proto_to_port[proto]
    # sending_port = proto_to_port[proto]
    
    
    # one could use the following output filter:
    # --output-fields=\"saddr,sport,dport,data\" \\\n\
    # --output-filter=\"sport=" + str(proto_to_port[proto]) + " && dport=" + str(sending_port) + " && success=1 && repeat=0\" \\\n\
    # In case some UDP server (e.g., TFTP server) will use random port to send response.
    

    for attack_name in attacks:
        if DEBUG: logging.debug("---------- PROBE: " + attack_name + " ----------\n")
        sending_port += 1
        scan_script_str = "#!/usr/bin/env bash\n\
WHITELIST=" + allowlist_path + "\n\
BLACKLIST=blacklist.txt\n\
box_config=box.config\n\
responses_dir_path=rsps/" + responses_storage_name + "\n\
mkdir -p $responses_dir_path\n\
set -o pipefail &&\n\
/usr/local/sbin/zmap \\\n\
--config=$box_config \\\n\
--target-port=" + str(proto_profile.port) + " \\\n\
--source-port=" + str(sending_port) + " \\\n\
--allowlist-file=${WHITELIST} \\\n\
--blocklist-file=${BLACKLIST} \\\n\
--rate=100000 \\\n\
--sender-threads=1 \\\n\
--max-targets=" + str(num_probes) + " \\\n\
--cooldown-time=10 \\\n\
--seed=85 \\\n\
--probes=1 \\\n\
--probe-module=udp \\\n\
--probe-args=" + proto_profile.attack_name_to_format[attack_name] + ":" + proto_profile.attack_name_to_pkt[attack_name] + " \\\n\
--output-module=csv \\\n\
--output-fields=\"saddr,data\" \\\n\
--output-filter=\"\" \\\n\
--verbosity=0 \\\n\
--quiet \\\n\
--disable-syslog \\\n\
--ignore-blocklist-errors \\\n\
> ${responses_dir_path}/" + attack_name + "_responses.csv"
        
        if DEBUG: logging.debug("START: write zmap script to .sh file.")
        scan_script_f = open("zmap_scan.sh", "w")
        scan_script_f.write(scan_script_str)
        scan_script_f.close()
        if DEBUG: logging.debug("FINISHED: write zmap script to .sh file.\n")


        if DEBUG: logging.debug("START: call zmap on a single attack packet.")
        call(['/bin/bash', 'zmap_scan.sh'])
        if DEBUG: logging.debug("FINISHED: call zmap on a single attack packet.\n")

        time.sleep(5)  

    # ---------------------------- SAVE RESPONSES ----------------------------------

        # Label: each row/response labeled with attack name.
        if DEBUG: logging.debug("START: read csv into pandas dataframe.")
        csv_path = os.getcwd() + "/rsps/" + responses_storage_name + "/" + attack_name + "_responses.csv"
        zmap_df = pd.read_csv(csv_path)
        if DEBUG: logging.debug("FINISHED: read csv into pandas dataframe.")
        zmap_df['attack_name'] = attack_name
        # zmap_df = zmap_df.drop(['sport','dport'],axis=1)
        if DEBUG: logging.debug("FINISHED: add attack column to csv.")
        zmap_df.to_csv(csv_path, index=False)
        if DEBUG: logging.debug("FINISHED: convert dataframe back to csv.\n")

        # Transfer: ZMap csv output file -> postgresql table
        transfer_sql = "COPY " + responses_storage_name + "(saddr, data, attack_name) FROM '" + csv_path + "' DELIMITER ',' CSV HEADER WHERE data IS NOT NULL;"
        if DEBUG: logging.debug("START: copy csv to database.")
        db_cursor.execute(transfer_sql)
        if DEBUG: logging.debug("FINISHED: copy csv to database.\n")

        

# All ZMap responses were transferred into the postgresql table, so it is now 
# safe to rename the columns to more descriptive names.
if DEBUG: logging.debug("START: rename two columns in database.")
rename_col1_sql = "ALTER TABLE " + responses_storage_name + " RENAME saddr TO rsp_src_ip;"
db_cursor.execute(rename_col1_sql)

rename_col2_sql = "ALTER TABLE " + responses_storage_name + " RENAME data TO rsp_payload;"
db_cursor.execute(rename_col2_sql)
if DEBUG: logging.debug("FINISHED: rename two columns in database.\n")



if DEBUG: logging.debug("START: close database cursor and connection.")
db_cursor.close()
db_conn.close()
if DEBUG: logging.debug("FINISHED: close database cursor and connection.\n")

print("Probe responses were stored using Postgresql.")
print("\tdatabase name: " + db_name) 
print("\ttable name: " + responses_storage_name)