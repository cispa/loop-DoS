from scapy.all import *
import psycopg2
import pickle
import psycopg2.extras


def NTP_classifier(payload):
    try:
        status_bit = ''
        status_code = ''
        packet = NTPHeader(bytes.fromhex(payload))
        
        mode = str(packet.mode)
        status_bit = status_bit + mode
        status_code = status_code + status_bit

        if status_bit=='6':
            try:
                packet = NTPControl(bytes.fromhex(payload))
                try:
                    status_bit = str(packet.zeros).zfill(2)
                except:
                    status_bit = '--'
                status_code = status_code + status_bit
                
                try:
                    status_bit = str(packet.version).zfill(2)
                except:
                    status_bit = '--'
                status_code = status_code + status_bit

                try:
                    status_bit = str(packet.response).zfill(2)
                except:
                    status_bit = '--'
                status_code = status_code + status_bit

                try:
                    status_bit = str(packet.err).zfill(2)
                except:
                    status_bit = '--'
                status_code = status_code + status_bit

                try:
                    status_bit = str(packet.more).zfill(2)
                except:
                    status_bit = '--'
                status_code = status_code + status_bit

                try:
                    status_bit = str(packet.opcode).zfill(2)
                except:
                    status_bit = '--'
                status_code = status_code + status_bit

                try:
                    status_bit = str(packet.status_word)
                except:
                    status_bit = 'cn'
                status_code = status_code + status_bit


                try:
                    status_bit = str(packet.status).zfill(4)
                except:
                    status_bit = '----'
                status_code = status_code + status_bit


                try:
                    if packet.authenticator != '':
                        status_bit = 'yy'
                    else:
                        status_bit = 'nn'
                
                except:
                    status_bit = 'cn'
                status_code = status_code + status_bit
            except Exception as e:
                status_code =  status_code + str(e)

        # elif status_bit=='7':
            # try:
            #     packet = NTPPrivate(bytes.fromhex(payload))
            #     try:
            #         status_bit = str(packet.response).zfill(2)
            #     except:
            #         status_bit = '--'
            #     status_code = status_code + status_bit

                
            #     try:
            #         status_bit = str(packet.version).zfill(2)
            #     except:
            #         status_bit = '--'
            #     status_code = status_code + status_bit

            #     try:
            #         status_bit = str(packet.implementation).zfill(4)
            #     except:
            #         status_bit = '----'
            #     status_code = status_code + status_bit

            #     try:
            #         status_bit = str(packet.err).zfill(4)
            #     except:
            #         status_bit = '----'
            #     status_code = status_code + status_bit

            #     try: 
            #         status_bit = str(packet.request_code).zfill(4)
            #     except:
            #         status_bit = '----'
            #     status_code = status_code + status_bit

            # except Exception as e:
            #     status_code =  status_code + str(e)            
        else:
            try:
                status_bit =  str(packet.leap).zfill(2)
            except:
                status_bit = '--'
            status_code = status_code + status_bit

            try:
                status_bit  = str(packet.version).zfill(2)
            except:
                status_bit = '--'
            status_code = status_code + status_bit

            try:
                status_bit = str(packet.stratum).zfill(4)
            except:
                status_bit = '----'
            status_code = status_code + status_bit

            try:
                status_bit = str(packet.poll).zfill(4)
            except:
                status_bit = '----'
            status_code = status_code + status_bit
                    

            # try:
            #     status_bit = str(packet.ref_id)
            # except:
            #     status_bit = '----'
            # status_code = status_code + status_bit


        return status_code

    except Exception as e:
        status_code = str(e)
        return status_code 


def do_cluster(raw_data_table_name,output_mapping_table_name,cluster_payload_pattern_mapping):
    db_name = "loop_scan"
    db_conn = psycopg2.connect(database=db_name, user="scan")
    db_conn.autocommit = True
    cursor = db_conn.cursor()

    sql_get_length = "SELECT COUNT(*) FROM %s;" % (raw_data_table_name)
    cursor.execute(sql_get_length)
    max_item_count = cursor.fetchall()[0][0]


    status_dict = {}
    total_cluster = 0
    try:
        dict_file = open(cluster_payload_pattern_mapping,'rb')
        status_dict = pickle.load(dict_file)
        total_clusters = len(status_dict)
        dict_file.close()
    except:
        pass
    

    offset = 0
    step_size = 10000
    progress_count = 0


    try:
        drop_table = "DROP TABLE %s;" % (output_mapping_table_name)
        cursor.execute(drop_table)
    except:
        pass

    create_table = "CREATE TABLE %s (type_id INT,\
                    payload TEXT PRIMARY KEY);" % (output_mapping_table_name)
    cursor.execute(create_table)


    insert_command = "INSERT INTO " + output_mapping_table_name + " VALUES %s;"
    payload_list = set()
    while(True):
        if offset > max_item_count:
            break

        select_command = "select DISTINCT rsp_payload from %s;" % (raw_data_table_name)
        cursor.execute(select_command)
        all_data = cursor.fetchall()

        update_list = []
        for data in all_data:
            progress_count = progress_count + 1
            payload_data = data[0].strip()
            total_clusters = len(status_dict.keys()) + 1
            status_code = NTP_classifier(payload_data)
            if len(payload_data) > 2500:
                continue
            if not status_code in status_dict:
                status_dict[status_code] = total_clusters 

            update_list.append((status_dict[status_code],payload_data,))

        temp = psycopg2.extras.execute_values(cursor,insert_command,update_list)

        offset = offset + step_size
        break


    with open(cluster_payload_pattern_mapping,'wb') as f:
        pickle.dump(status_dict,f)
        f.close()


import sys

if len(sys.argv)!=4:
    print('python3 ntp_clustering.py <scan_table_name> <cluster_table_name> <type_summary_id_mapping_dict>')
    exit(-1)

scan_table_name = sys.argv[1]
cluster_table_name = sys.argv[2]
type_summary_id_mapping_dict = sys.argv[3]
do_cluster(scan_table_name,cluster_table_name,type_summary_id_mapping_dict)
