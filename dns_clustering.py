from scapy.all import *
import psycopg2
import pickle
import psycopg2.extras

# Remind to replace the domain name in line #175

def DNS_classifier(payload):
    try:
        dns_pac = DNS(bytes.fromhex(payload))
        status_code = ''
        #  -------------    QR  -----------------
        status_bit = ''
        try:
            qr = dns_pac.qr
            status_bit = hex(qr)[2]
        except:
            status_bit = '-'

        status_code = status_code + status_bit

        #   ------------    OPCODE  ------------
        status_bit = ''
        try:
            opcode = dns_pac.opcode
            status_bit = hex(opcode)[2]
        except:
            status_bit = '-'
        status_code = status_code + status_bit

        #   -----------     AA   ------------
        status_bit = ''
        try:
            aa = dns_pac.aa
            status_bit = hex(aa)[2]
        except:
            status_bit = '-'
        status_code = status_code + status_bit
        
        #   -----------     TC   ------------
        status_bit = ''
        try:
            tc = dns_pac.tc
            status_bit = hex(tc)[2]
        except:
            status_bit = '-'
        status_code = status_code + status_bit


        #   -----------     RD   ------------
        status_bit = ''
        try:
            rd = dns_pac.rd
            status_bit = hex(rd)[2]
        except:
            status_bit = '-'
        status_code = status_code + status_bit

        #   -----------     RA   ------------
        status_bit = ''
        try:
            ra = dns_pac.ra
            status_bit = hex(ra)[2]
        except:
            status_bit = '-'
        status_code = status_code + status_bit


        #   -----------     z   ------------
        status_bit = ''
        try:
            z = dns_pac.z
            status_bit = hex(z)[2]
        except:
            status_bit = '-'
        status_code = status_code + status_bit

        #   -----------     ad   ------------
        status_bit = ''
        try:
            ad = dns_pac.ad
            status_bit = hex(ad)[2]
        except:
            status_bit = '-'
        status_code = status_code + status_bit

        #   -----------     cd   ------------
        status_bit = ''
        try:
            cd = dns_pac.cd
            status_bit = hex(cd)[2]
        except:
            status_bit = '-'
        status_code = status_code + status_bit

        #   -----------     rcode   ------------
        status_bit = ''
        try:
            rcode = dns_pac.rcode
            status_bit = hex(rcode)[2]
        except:
            status_bit = '-'
        status_code = status_code + status_bit

        #   -----------     qdcount     ---------
        status_bit = ''
        try:
            qdcount = dns_pac.qdcount
            if qdcount <=1:
                status_bit = '000'+hex(qdcount)[2]
            elif qdcount<=256:
                status_bit = '0100'
            elif qdcount<=8192:
                status_bit = '2000'
            elif qdcount<=65536:
                status_bit = 'ffff'
        except:
            status_bit = '----'
        status_code = status_code + status_bit

        #   -----------     ancount     ---------
        status_bit = ''
        try:
            ancount = dns_pac.ancount
            if ancount <=1:
                status_bit = '000'+hex(ancount)[2]
            elif ancount<=256:
                status_bit = '0100'
            elif ancount<=8192:
                status_bit = '2000'
            elif ancount<=65536:
                status_bit = 'ffff'
        except:
            status_bit = '----'
        status_code = status_code + status_bit

        #   -----------     nscount     ---------
        status_bit = ''
        try:
            nscount = dns_pac.nscount
            if nscount <=1:
                status_bit = '000'+hex(nscount)[2]
            elif nscount<=256:
                status_bit = '0100'
            elif nscount<=8192:
                status_bit = '2000'
            elif nscount<=65536:
                status_bit = 'ffff'
        except:
            status_bit = '----'
        status_code = status_code + status_bit

        #   -----------     arcount     ---------
        status_bit = ''
        try:
            arcount = dns_pac.arcount
            if arcount <=1:
                status_bit = '000'+hex(arcount)[2]
            elif arcount<=256:
                status_bit = '0100'
            elif arcount<=8192:
                status_bit = '2000'
            elif arcount<=65536:
                status_bit = 'ffff'
        except:
            status_bit = '----'
        status_code = status_code + status_bit

        # ------------ qname------------------
        status_bit=''
        try:
            qname = dns_pac.qd.qname
            if qname==b'.':
                status_bit = 'isdot'
            elif b'our domain' in qname:
                status_bit = 'okdom'
            else:
                status_bit = 'nodom'
        except:
            status_bit = '-----'
        status_code = status_code + status_bit

        #   ----------  QTYPE       --------------
        status_bit = ''
        try:
            qtype = dns_pac.qd.qtype
            hex_str = hex(qtype)
            hex_str = hex_str[2:len(hex_str)]
            for i in range(0,4-len(hex_str)):
                hex_str = '0'+hex_str
            status_bit = hex_str
        except:
            status_bit = '----'
        status_code = status_code+status_bit

        #   ----------  QCLASS       --------------
        status_bit = ''
        try:
            qclass = dns_pac.qd.qclass
            hex_str = hex(qclass)
            hex_str = hex_str[2:len(hex_str)]
            for i in range(0,4-len(hex_str)):
                hex_str = '0'+hex_str
            status_bit = hex_str
        except:
            status_bit = '----'
        status_code = status_code+status_bit


        #   ----------  atype       --------------
        status_bit = ''
        try:
            atype = dns_pac.an.type
            hex_str = hex(atype)
            hex_str = hex_str[2:len(hex_str)]
            for i in range(0,4-len(hex_str)):
                hex_str = '0'+hex_str
            status_bit = hex_str
        except:
            status_bit = '----'
        status_code = status_code+status_bit

        #   ----------  aclass       --------------
        status_bit = ''
        try:
            aclass = dns_pac.an.rclass
            hex_str = hex(aclass)
            hex_str = hex_str[2:len(hex_str)]
            for i in range(0,4-len(hex_str)):
                hex_str = '0'+hex_str
            status_bit = hex_str
        except:
            status_bit = '----'
        status_code = status_code+status_bit


        # #   ---------   rdlen   -------------------
        # status_bit = ''
        # try:
        #     rdlen = dns_pac.an.rdlen
        #     if rdlen <=32:
        #         status_bit = '0020'
        #     # elif arcount<=256:
        #         # status_bit = '0100'
        #     # elif arcount<=8192:
        #         # status_bit = '2000'
        #     # elif arcount<=65536:
        #         # status_bit = 'ffff'
        # except:
        #     status_bit = '----'
        # status_code = status_code + status_bit

        return status_code
    except Exception as e:
        status_code = str(e) + '|'
        status_bit = ''

        if len(payload)<=2:
            status_bit = 'os'
            status_code = status_code + status_bit
            return status_code

        payload_bits_str = ''
        for hex_str in payload:
            payload_bits_str = payload_bits_str + bin(int(hex_str,16))[2:].zfill(4)
        
        payload_bits_str_len = len(payload_bits_str)

        # QR
        status_bit = ''
        if payload_bits_str_len>=17:
            qr = payload_bits_str[16]
            status_bit = qr
        else:
            status_bit = '-'
            status_code = status_code + status_bit
            return status_code
        
        status_code = status_code + status_bit
        
        # OPCODE
        status_bit = ''
        if payload_bits_str_len>=21:
            opcode = payload_bits_str[17:21]
            status_bit = hex(int(opcode,2))[2:]
        else:
            status_bit = '-'
            status_code = status_code + status_bit
            return status_code
        
        status_code = status_code + status_bit


        # AA
        status_bit = ''
        if payload_bits_str_len>=22:
            aa = payload_bits_str[21]
            status_bit = aa
        else:
            status_bit = '-'
            status_code = status_code + status_bit
            return status_code

        status_code = status_code + status_bit

        # TC        
        status_bit = ''
        if payload_bits_str_len>=23:
            tc = payload_bits_str[22]
            status_bit = tc
        else:
            status_bit = '-'
            status_code = status_code + status_bit
            return status_code
        
        status_code = status_code + status_bit

        # RD
        status_bit = ''
        if payload_bits_str_len>=24:
            rd = payload_bits_str[23]
            status_bit = rd
        else:
            status_bit = '-'
            status_code = status_code + status_bit
            return status_code

        status_code = status_code + status_bit

        # RA        
        status_bit = ''
        if payload_bits_str_len>=25:
            ra = payload_bits_str[24]
            status_bit = ra
        else:
            status_bit = '-'
            status_code = status_code + status_bit
            return status_code

        status_code = status_code + status_bit


        # z
        status_bit = ''
        if payload_bits_str_len>=26:
            z = payload_bits_str[25]
            status_bit = z
        else:
            status_bit = '-'
            status_code = status_code + status_bit
            return status_code

        status_code = status_code + status_bit


        # ad
        status_bit = ''
        if payload_bits_str_len>=27:
            ad = payload_bits_str[26]
            status_bit = ad
        else:
            status_bit = '-'
            status_code = status_code + status_bit
            return status_code
            
        status_code = status_code + status_bit


        # cd
        status_bit = ''
        if payload_bits_str_len>=28:
            cd = payload_bits_str[27]
            status_bit = cd
        else:
            status_bit = '-'
            status_code = status_code + status_bit
            return status_code
            
        status_code = status_code + status_bit


        # rcode
        status_bit = ''
        if payload_bits_str_len>=32:
            rcode = payload_bits_str[28:32]
            status_bit = hex(int(rcode,2))[2:]
        else:
            status_bit = '-'
            status_code = status_code + status_bit
            return status_code
            
        status_code = status_code + status_bit


        # qdcount
        status_bit = ''
        if payload_bits_str_len>=48:
            qdcount = payload_bits_str[32:48]
            qdcount = int(qdcount,2)
            if qdcount <=1:
                status_bit = '000'+hex(qdcount)[2]
            elif qdcount<=256:
                status_bit = '0100'
            elif qdcount<=8192:
                status_bit = '2000'
            elif qdcount<=65536:
                status_bit = 'ffff'
        else:
            status_bit = '----'
            status_code = status_code + status_bit
            return status_code
            
        status_code = status_code + status_bit

        # ancount
        status_bit = ''
        if payload_bits_str_len>=64:
            ancount = payload_bits_str[48:64]
            ancount = int(ancount,2)
            if ancount <=1:
                status_bit = '000'+hex(ancount)[2]
            elif ancount<=256:
                status_bit = '0100'
            elif ancount<=8192:
                status_bit = '2000'
            elif ancount<=65536:
                status_bit = 'ffff'
        else:
            status_bit = '----'
            status_code = status_code + status_bit
            return status_code
            
        status_code = status_code + status_bit


        # nscount
        status_bit = ''
        if payload_bits_str_len>=80:
            nscount = payload_bits_str[64:80]
            nscount = int(nscount,2)
            if nscount <=1:
                status_bit = '000'+hex(nscount)[2]
            elif nscount<=256:
                status_bit = '0100'
            elif nscount<=8192:
                status_bit = '2000'
            elif nscount<=65536:
                status_bit = 'ffff'
        else:
            status_bit = '----'
            status_code = status_code + status_bit
            return status_code
            
        status_code = status_code + status_bit


        # arcount
        status_bit = ''
        if payload_bits_str_len>=96:
            arcount = payload_bits_str[80:96]
            arcount = int(arcount,2)
            if arcount <=1:
                status_bit = '000'+hex(arcount)[2]
            elif arcount<=256:
                status_bit = '0100'
            elif arcount<=8192:
                status_bit = '2000'
            elif arcount<=65536:
                status_bit = 'ffff'
        else:
            status_bit = '----'
            status_code = status_code + status_bit
            return status_code
            
        status_code = status_code + status_bit

        status_bit = ''
        rest_payload_length = len(payload_bits_str)-96
        if rest_payload_length==0:
            status_bit = '0000'
        elif rest_payload_length<=128:
            status_bit = '0080'
        elif rest_payload_length<=1024:
            status_bit = '0400'
        else:
            status_bit = 'ffff'
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
            status_code = DNS_classifier(payload_data)
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
    print('python3 dns_clustering.py <scan_table_name> <cluster_table_name> <type_summary_id_mapping_dict>')
    exit(-1)

scan_table_name = sys.argv[1]
cluster_table_name = sys.argv[2]
type_summary_id_mapping_dict = sys.argv[3]
do_cluster(scan_table_name,cluster_table_name,type_summary_id_mapping_dict)

