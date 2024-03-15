from scapy.all import *
import psycopg2
import pickle
import psycopg2.extras
import pathvalidate


def TFTP_classifier(payload):
    status_code = ''
    status_bit = ''

    payload_hex_len = len(payload)

    if payload_hex_len<4:
        status_code = 'os'
        return status_code

    if payload_hex_len%2 !=0:
        status_code = 'hf'
    
    opcode = payload[0:4]
    payload = payload[4:]

    if opcode == '0001' or opcode=='0002':
        if opcode =='0001':
            status_bit = 'rr'
        else:
            status_bit = 'wr'

        first_null_byte = payload.index('00')
        if first_null_byte == -1:
            status_bit = status_bit + 'nf' +'nm' + 'nn'
            status_code = status_code + status_bit
            return status_code
        
        filename = payload[4:first_null_byte]
        try:
            filename = bytes.fromhex(filename).decode()
            filename_len = len(filename)
            if len(filename)<32:
                status_bit = status_bit + '32'
            elif len(filename)<256:
                status_bit = status_bit + '256'
            else:
                status_bit = status_bit + 'ffff'
            
            if pathvalidate.is_valid_filename(filename,platform='Linux'):
                status_bit = status_bit + 'vflin'
            else:
                status_bit = status_bit + 'iflin'

            if pathvalidate.is_valid_filename(filename,platform='Windows'):
                status_bit = status_bit + 'vfwin'
            else:
                status_bit = status_bit + 'ifwin'

            if pathvalidate.is_valid_filename(filename,platform='macOS'):
                status_bit = status_bit + 'vfmac'
            else:
                status_bit = status_bit + 'ifmac'

            if pathvalidate.is_valid_filename(filename,platform='POSIX'):
                status_bit = status_bit + 'vfpos' 
            else:
                status_bit = status_bit + 'ifpos'
        except:
            status_bit = status_bit + 'bf'

        # ----- mode --------

        payload = payload[first_null_byte+2:]
        second_null_byte = payload.index('00')
        if second_null_byte == -1:
            status_bit = status_bit +'nm'+'n2n'
            status_code = status_code + status_bit
            return status_code

        mode = payload[0:second_null_byte]
        mode = bytes.fromhex(mode).decode()
        status_bit = status_bit + mode
        
        # ----- rest --------

        payload = payload[second_null_byte+2:]
        if len(payload)>0:
            status_bit = status_bit + 'extra' 
        

        status_code = status_code + status_bit
        return status_code

    elif opcode == '0003':
        status_bit ='dr'  
        if len(payload)<4:
            status_bit = status_bit + 'os' 
            status_code = status_code + status_bit
            return status_code

        block_id = int(payload[0:4],16)
        if block_id ==0:
            status_bit = status_bit + '0b' 
        
        payload = payload[4:]
        if len(payload)<1024:
            status_bit = status_bit+'eb' 
        elif len(payload)==1024:
            status_bit = status_bit + 'fb' 
        elif len(payload)>1024:
            status_bit = status_bit + 'ob'

        status_code = status_code + status_bit
        return status_code

    elif opcode == '0004':
        status_bit = 'ar' 
        if len(payload)<4:
            status_bit = status_bit + 'os'
        if len(payload)>4:
            status_bit = status_bit + 'extra'
        status_code = status_code + status_bit
        return status_code
        
    elif opcode == '0005':
        status_bit = 'er'
        if len(payload)<4:
            status_bit = status_bit + 'os' 
            status_code = status_code + status_bit 
            return status_code
        
        error_code = payload[0:4]
        status_bit = status_bit + error_code
        payload = payload[4:]

        num_of_null_byte = payload.count('00')
        status_bit = status_bit + str(num_of_null_byte)
        status_code = status_code + status_bit
        return status_code

    else:
        status_bit = opcode
        if len(payload)<64:
            status_bit =status_bit + '64'
        elif len(payload) < 256:
            status_bit = status_bit + '256'
        elif len(payload) <1024:
            status_bit = status_bit + '1024'
        else:
            status_bit = status_bit + 'ffff'
        status_code = status_code + status_bit
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
            status_code = TFTP_classifier(payload_data)
            if len(payload_data) > 2500:
                continue
            if not status_code in status_dict:
                status_dict[status_code] = total_clusters 
            
            if not payload_data in payload_list:
                update_list.append((status_dict[status_code],payload_data,))
                payload_list.add(payload_data)

        temp = psycopg2.extras.execute_values(cursor,insert_command,update_list)


        offset = offset + step_size
        break


    with open(cluster_payload_pattern_mapping,'wb') as f:
        pickle.dump(status_dict,f)
        f.close()


import sys

if len(sys.argv)!=4:
    print('python3 tftp_clustering.py <scan_table_name> <cluster_table_name> <type_summary_id_mapping_dict>')
    exit(-1)

scan_table_name = sys.argv[1]
cluster_table_name = sys.argv[2]
type_summary_id_mapping_dict = sys.argv[3]
do_cluster(scan_table_name,cluster_table_name,type_summary_id_mapping_dict)

