import psycopg2
import pickle
import random
import sys

db_name = "loop_scan"
db_conn = psycopg2.connect(database=db_name, user="scan")
db_conn.autocommit = True
cursor = db_conn.cursor()

if len(sys.argv)!=5:
    print('python3 sample_loop_probe_payloads.py <proto> <discovery_table> <cluster_table> <responder_amount>')
    exit(-1)

proto = sys.argv[1].lower()
discovery_table = sys.argv[2]
cluster_table = sys.argv[3]
responder_amount = int(sys.argv[4])



select_command = "SELECT type_id,IPs FROM (SELECT type_id, (ARRAY_AGG(DISTINCT rsp_payload)) AS IPs, COUNT(DISTINCT rs\
p_src_ip) AS IP_count FROM (SELECT * FROM %s JOIN %s on rsp\
_payload=payload) AS temp GROUP BY type_id ORDER BY IP_count DESC) AS temp2 WHERE IP_count>%d;" % (discovery_table, cluster_table,responder_amount)

cursor.execute(select_command)
all_data = cursor.fetchall()


output_dict = {}


f_name = '%s_payload.pkl' % proto
f=open(f_name,'wb')
for item in all_data:
    all_payload_in_cluster = list(item[1])
    if len(all_payload_in_cluster)<=5:
        output_dict[str(item[0])] = list(item[1])
    else:
        output_dict[str(item[0])] = random.sample(all_payload_in_cluster,5)


pickle.dump(output_dict,f)
f.close()




