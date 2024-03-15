import psycopg2
import tabulate
import pickle
import sys

db_name = "loop_scan"
db_conn = psycopg2.connect(database=db_name, user="scan")
db_conn.autocommit = True
cursor = db_conn.cursor()

if len(sys.argv)!=3:
    print('python3 cluster_verify.py <loop_probe_scan_result_table> <sampled_payloads_file>')
    exit(-1)



scan_2nd_table_name = sys.argv[1]
select_command = "SELECT ARRAY_LENGTH(ARRAY_AGG(rsp_src_ip),1) AS IP_count, count AS num_of_probes, \
attack_name  FROM (SELECT ARRAY_LENGTH(ARRAY_AGG(DISTINCT index),1) AS count, attack_name, rsp_src_ip FROM %s \
GROUP BY attack_name,rsp_src_ip) AS temp GROUP BY count,attack_name ORDER BY attack_name,count ASC;" % (scan_2nd_table_name)

cursor.execute(select_command)
data = cursor.fetchall()


id_probe_amount_map = {}
f = open(sys.argv[2],'rb')
payload_dict = pickle.load(f)
f.close()

for key in payload_dict.keys():
    id_probe_amount_map[key] = len(payload_dict[key])



table_headers = ['attack_name','reply to 0 probe','1 probe','2 probe','3 probe','4 probe','5 probe','reply all fraction','num of probes']
readable_table = []


amount_dict ={}
for data_item in data:
    attack_name = str(data_item[2]).strip()
    if attack_name in amount_dict:
        amount_dict[attack_name][str(data_item[1]).strip()] = int(data_item[0])
    else:
        amount_dict[attack_name]={}
        amount_dict[attack_name][str(data_item[1]).strip()] = int(data_item[0])

for attack_name in amount_dict.keys():
    temp_list = [attack_name,'?']
    try:
        amount_1 = amount_dict[attack_name][str(1)]
        temp_list.append(amount_1)
    except:
        if id_probe_amount_map[attack_name]>=1:
            amount_1 = '0'
        else:
            amount_1 = '-'
        temp_list.append(amount_1)
    try:
        amount_2 = amount_dict[attack_name][str(2)]
        temp_list.append(amount_2)
    except:
        if id_probe_amount_map[attack_name]>=2:
            amount_2 = '0'
        else:
            amount_2 = '-'
        temp_list.append(amount_2)
    try:
        amount_3 = amount_dict[attack_name][str(3)]
        temp_list.append(amount_3)
    except:
        if id_probe_amount_map[attack_name]>=3:
            amount_3 = '0'
        else:
            amount_3 = '-'
        temp_list.append(amount_3)
    try:
        amount_4 = amount_dict[attack_name][str(4)]
        temp_list.append(amount_4)
    except:
        if id_probe_amount_map[attack_name]>=4:
            amount_4 = '0'
        else:
            amount_4 = '-'
        temp_list.append(amount_4)
    try:
        amount_5 = amount_dict[attack_name][str(5)]
        temp_list.append(amount_5)
    except:
        if id_probe_amount_map[attack_name]>=5:
            amount_5 = '0'
        else:
            amount_5 = '-'
        temp_list.append(amount_5)
    try:
        s = 0
        s = s + amount_dict[attack_name][str(1)]
        s = s + amount_dict[attack_name][str(2)]
        s = s + amount_dict[attack_name][str(3)]
        s = s + amount_dict[attack_name][str(4)]
        s = s + amount_dict[attack_name][str(5)]
    except:
        pass

    try:
        s = round(amount_dict[attack_name][str(id_probe_amount_map[attack_name])]/s*1.0,1)
        temp_list.append(s)    
    except:
        temp_list.append('?')
        pass


    temp_list.append(id_probe_amount_map[attack_name])
    readable_table.append(temp_list)


print(tabulate.tabulate(readable_table,headers = table_headers))
