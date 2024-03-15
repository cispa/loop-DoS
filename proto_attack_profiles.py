from scapy.all import *

TEXT = "text"
HEX = "hex"

def to_hex(pkt):
    pkt = linehexdump(pkt, dump=True)    
    pkt = pkt[:pkt.find("  ")]
    pkt = pkt.replace(" ", "")    
    return pkt

class Chargen_Attack_Profile:
    def __init__(self):
        self.port = 19
        self.attack_name_to_pkt = {}
        self.attack_name_to_format = {}
        self.attack_name_to_pkt["random"] = "a"
        self.attack_name_to_format["random"] = TEXT

class Qotd_Attack_Profile:
    def __init__(self):
        self.port = 17
        self.attack_name_to_pkt = {}
        self.attack_name_to_format = {}
        self.attack_name_to_pkt["random"] = "a"
        self.attack_name_to_format["random"] = TEXT

class Echo_Attack_Profile:
    def __init__(self):
        self.port = 7
        self.attack_name_to_pkt = {}
        self.attack_name_to_format = {}
        self.attack_name_to_pkt["random"] = "a"
        self.attack_name_to_format["random"] = TEXT

class Daytime_Attack_Profile:
    def __init__(self):
        self.port=13
        self.attack_name_to_pkt = {}
        self.attack_name_to_format = {}

        self.attack_name_to_pkt['noempty'] = 'a'
        self.attack_name_to_format['noempty'] = TEXT

class Time_Attack_Profile:
    def __init__(self):
        self.port=37
        self.attack_name_to_pkt = {}
        self.attack_name_to_format = {}

        self.attack_name_to_pkt['noempty'] = 'a'
        self.attack_name_to_format['noempty'] = TEXT

class Auser_Attack_Profile:
    def __init__(self):
        self.port=11
        self.attack_name_to_pkt = {}
        self.attack_name_to_format = {}

        self.attack_name_to_pkt['noempty'] = 'a'
        self.attack_name_to_format['noempty'] = TEXT

class DNS_Attack_Profile:
    def __init__(self):
        self.port = 53  # Port corresponding to the protocol.
        
        self.attack_name_to_pkt = {}     # Stores the attack packets that can be
                                         # sent to create a loop attack by 
                                         # abusing dns protocol implementations.
        self.attack_name_to_format = {}  # Maps each attack in 
                                         # 'attack_name_to_pkt' to the packet's 
                                         # format (format options in 
                                         # class Attack_Pkt_Format()).


        # ----------------------- Query Based ----------------------------------

        self.attack_name_to_pkt["test1"] = "860c010000010000000000000a6f757220646f6d61696e0000010001"
        self.attack_name_to_format["test1"] = HEX

        self.attack_name_to_pkt["test2"] = "a745008000010000000000000a6f757220646f6d61696e0000010001"
        self.attack_name_to_format["test2"] = HEX

        self.attack_name_to_pkt["bad_req_hdr1"] = "000001000001000000000000"
        self.attack_name_to_format["bad_req_hdr1"] = HEX

        self.attack_name_to_pkt["bad_req_hdr2"] = "06361706026465000001"
        self.attack_name_to_format["bad_req_hdr2"] = HEX

        self.attack_name_to_pkt["bad_req_hdr3"] = "b0b506b3b6c973701d6102c6465f00001c0001"
        self.attack_name_to_format["bad_req_hdr3"] = HEX

        self.attack_name_to_pkt["bad_req_hdr4"] = "fb6c6072b9037469612a2ddd6f73536f372264650000410001"
        self.attack_name_to_format["bad_req_hdr4"] = HEX

        self.attack_name_to_pkt["bad_req_hdr5"] = "860c610000010000000000000a6f757220646f6d61696e0000010001"
        self.attack_name_to_format["bad_req_hdr5"] = HEX


        self.attack_name_to_pkt["bad_req_qr1"] = "0000010000010000000000000a6f757220646f6d61696e0001180118"
        self.attack_name_to_format["bad_req_qr1"] = HEX

        self.attack_name_to_pkt["bad_req_qr2"] = to_hex(DNS(qd=DNSQR(qname='m', qtype=280, qclass=280)))
        self.attack_name_to_format["bad_req_qr2"] = HEX


        # ------------------------ Response Based---- ------------------------
        self.attack_name_to_pkt["good_rsp"] = "0000818000010001000000000a6f757220646f6d61696e00000100010a6f757220646f6d61696e00000100010000003c000401020304"
        self.attack_name_to_format["good_rsp"] = HEX

        self.attack_name_to_pkt["bad_rsp_hdr1"] = "7b0a818000010000000000000a6f757220646f6d61696e00000100010a6f757220646f6d61696e00000100010000003c000401020304"
        self.attack_name_to_format["bad_rsp_hdr1"] = HEX

        self.attack_name_to_pkt["bad_rsp_hdr2"] = "00b5a44818010001c030a00f23789000b1001c006f757220646f6d61696e2e00001c0001c00c00060001000000f50038036e732e0078957d1500002a3000000e1000093a8000007080"
        self.attack_name_to_format["bad_rsp_hdr2"] = HEX

        self.attack_name_to_pkt["bad_rsp_hdr3"] = "9309c18000010001000000000a6f757220646f6d61696e00000100010a6f757220646f6d61696e00000100010000003c000401020304"
        self.attack_name_to_format["bad_rsp_hdr3"] = HEX

        self.attack_name_to_pkt["bad_rsp_hdr4"] = "0000818f00010001000000000a6f757220646f6d61696e00000100010a6f757220646f6d61696e00000100010000003c000401020304"
        self.attack_name_to_format["bad_rsp_hdr4"] = HEX


        self.attack_name_to_pkt["bad_rsp_hdr5"] = "a745010000010001000000000a6f757220646f6d61696e00000100010a6f757220646f6d61696e0000010001000100b1000401020304"
        self.attack_name_to_format["bad_rsp_hdr5"] = HEX

        self.attack_name_to_pkt["bad_rsp_rr1"] = to_hex(DNS(qd=DNSRR(type=280, rclass=280)))
        self.attack_name_to_format["bad_rsp_rr1"] = HEX

        self.attack_name_to_pkt["bad_rsp_rr2"] = to_hex(DNS(qd=DNSRR(rrname='m', type=280, rclass=280)))
        self.attack_name_to_format["bad_rsp_rr2"] = HEX


        self.attack_name_to_pkt["bad_rsp_hdr_rr1"] = "a74581800001000100000000c00c00010001000100b10004d415a572"
        self.attack_name_to_format["bad_rsp_hdr_rr1"] = HEX

        self.attack_name_to_pkt["bad_rsp_hdr_rr2"] = "a74581800000000100000000046f757220646f6d61696e0000010001c00c00010001000100b10004d415a572"
        self.attack_name_to_format["bad_rsp_hdr_rr2"] = HEX

        self.attack_name_to_pkt["bad_rsp_hdr_rr3"] = "75a223cf47d3f2c40b889c" + to_hex(DNSRR(rrname='m', type=280, rclass=280))
        self.attack_name_to_format["bad_rsp_hdr_rr3"] = HEX


        # ---------------------------- ERRORS ----------------------------------
        self.attack_name_to_pkt["err1"] = "6974818100010000000000000a6f757220646f6d61696e0000010001"
        self.attack_name_to_format["err1"] = HEX

        self.attack_name_to_pkt["err2"] = "7d9a818200010000000000000a6f757220646f6d61696e0000410001"
        self.attack_name_to_format["err2"] = HEX

        self.attack_name_to_pkt["err3"] = "6974818300010000000000000a6f757220646f6d61696e0000010001"
        self.attack_name_to_format["err3"] = HEX

        self.attack_name_to_pkt["err4"] = "6974818400010000000000000a6f757220646f6d61696e0000010001"
        self.attack_name_to_format["err4"] = HEX

        self.attack_name_to_pkt["err5"] = "6974818500010000000000000a6f757220646f6d61696e0000010001"
        self.attack_name_to_format["err5"] = HEX

class NTP_Attack_Profile:
    def __init__(self):
        self.port = 123

        self.attack_name_to_pkt = {}     # Stores the attack packets that can be
                                         # sent to create a loop attack by 
                                         # abusing protocol implementations.
        self.attack_name_to_format = {}  # Maps each attack in 
                                         # 'attack_name_to_pkt' to the packet's 
                                         # format (format options are constants
                                         # at the top of this file).

        # ------------------ Server Mode -----------------------------------------
        self.attack_name_to_pkt["stratum1"] = to_hex(NTPHeader(mode=4, stratum=14))
        self.attack_name_to_format["stratum1"] = HEX
        
        self.attack_name_to_pkt["stratum2"] = to_hex(NTPHeader(mode=4, stratum=15))
        self.attack_name_to_format["stratum2"] = HEX

        self.attack_name_to_pkt["stratum3"] = to_hex(NTPHeader(mode=4, stratum=16))
        self.attack_name_to_format["stratum3"] = HEX

        self.attack_name_to_pkt["kiss_xxxx_s"] = to_hex(NTPHeader(mode=4, stratum=0, ref_id="XXXX"))
        self.attack_name_to_format["kiss_xxxx_s"] = HEX

        self.attack_name_to_pkt["kiss_abcd_s"] = to_hex(NTPHeader(mode=4, stratum=0, ref_id="ABCD"))
        self.attack_name_to_format["kiss_abcd_s"] = HEX


        # -------------------- broadcast -----------------------------------------
        self.attack_name_to_pkt["bcast"] = to_hex(NTPHeader(mode=5))
        self.attack_name_to_format["bcast"] = HEX


        # -------------------- Control message -----------------------------------

        self.attack_name_to_pkt["cntrl_zer"] = to_hex(NTPControl(zeros=1))
        self.attack_name_to_format["cntrl_zer"] = HEX

        self.attack_name_to_pkt["cntrl_err1"] = to_hex(NTPControl(err=1, response=1))
        self.attack_name_to_format["cntrl_err1"] = HEX

        self.attack_name_to_pkt["cntrl_err2"] = to_hex(NTPControl(err=1))
        self.attack_name_to_format["cntrl_err2"] = HEX

        self.attack_name_to_pkt["cntrl_opcode1"] = to_hex(NTPControl(op_code=31))
        self.attack_name_to_format["cntrl_opcode1"] = HEX

        self.attack_name_to_pkt["cntrl_opcode2"] = to_hex(NTPControl(op_code=31, data="iyQo7zCkRZOuGqu"))
        self.attack_name_to_format["cntrl_opcode2"] = HEX

        self.attack_name_to_pkt["cntrl_opcode3"] = to_hex(NTPControl(op_code=5, data="iyQo7zCkRZOuGqu"))
        self.attack_name_to_format["cntrl_opcode3"] = HEX
  
        self.attack_name_to_pkt["cntrl_opcode4"] = to_hex(NTPControl(op_code=7, data="iyQo7zCkRZOuGqu"))
        self.attack_name_to_format["cntrl_opcode4"] = HEX

        self.attack_name_to_pkt["cntrl_opcode5"] = to_hex(NTPControl(response=1, op_code=7))
        self.attack_name_to_format["cntrl_opcode5"] = HEX

        self.attack_name_to_pkt["cntrl_sys_stat"] = to_hex(NTPControl(err=1, response=1, status_word=NTPSystemStatusPacket(system_event_code=7)))
        self.attack_name_to_format["cntrl_sys_stat"] = HEX

        self.attack_name_to_pkt["cntrl_err_stat1"] = to_hex(NTPControl(err=1, response=1, status_word=NTPErrorStatusPacket(error_code=1)))
        self.attack_name_to_pkt["cntrl_err_stat2"] = to_hex(NTPControl(err=1, response=1, status_word=NTPErrorStatusPacket(error_code=2)))
        self.attack_name_to_pkt["cntrl_err_stat3"] = to_hex(NTPControl(err=1, response=1, status_word=NTPErrorStatusPacket(error_code=3)))
        self.attack_name_to_pkt["cntrl_err_stat4"] = to_hex(NTPControl(err=1, response=1, status_word=NTPErrorStatusPacket(error_code=4)))
        self.attack_name_to_pkt["cntrl_err_stat5"] = to_hex(NTPControl(err=1, response=1, status_word=NTPErrorStatusPacket(error_code=5)))
        self.attack_name_to_pkt["cntrl_err_stat6"] = to_hex(NTPControl(err=1, response=1, status_word=NTPErrorStatusPacket(error_code=6)))
        self.attack_name_to_pkt["cntrl_err_stat7"] = to_hex(NTPControl(err=1, response=1, status_word=NTPErrorStatusPacket(error_code=7)))
        self.attack_name_to_pkt["cntrl_err_stat8"] = to_hex(NTPControl(err=1, response=1, status_word=NTPErrorStatusPacket(error_code=200)))

        self.attack_name_to_format["cntrl_err_stat1"] = HEX
        self.attack_name_to_format["cntrl_err_stat2"] = HEX
        self.attack_name_to_format["cntrl_err_stat3"] = HEX
        self.attack_name_to_format["cntrl_err_stat4"] = HEX
        self.attack_name_to_format["cntrl_err_stat5"] = HEX
        self.attack_name_to_format["cntrl_err_stat6"] = HEX
        self.attack_name_to_format["cntrl_err_stat7"] = HEX
        self.attack_name_to_format["cntrl_err_stat8"] = HEX

        self.attack_name_to_pkt["cntrl_clock_stat1"] = to_hex(NTPControl(err=1, response=1, status_word=NTPClockStatusPacket(clock_status=149, code=5)))
        self.attack_name_to_format["cntrl_clock_stat1"] = HEX
    
        self.attack_name_to_pkt["cntrl_clock_stat2"] = to_hex(NTPControl(err=1, response=1, status_word=NTPClockStatusPacket(clock_status=5)))
        self.attack_name_to_format["cntrl_clock_stat2"] = HEX

        self.attack_name_to_pkt["cntrl_peer_stat1"] = to_hex(NTPControl(err=1, response=1, status_word=NTPPeerStatusPacket(peer_sel=0, peer_event_code=2)))
        self.attack_name_to_format["cntrl_peer_stat1"] = HEX

        

        # -------------------- Private reserved -----------------------------------

        self.attack_name_to_pkt["bad5_rsvd"] = "270206000000007f00000100000000e8622e8655e0000000000000000000e8622e86696000"
        self.attack_name_to_format["bad5_rsvd"] = HEX

        self.attack_name_to_pkt["bad2_rsvd"] = "27020a0000000000000000007f000001000000000000007c5f8504ad93cd4cd1aad3329ffbb2fea822a2f2fead61ea73"
        self.attack_name_to_format["bad2_rsvd"] = HEX

        self.attack_name_to_pkt["bad6_rsvd"] = "270f1a0e0310a0da40130c007f000bb10a00000000000ca0e86a2ee6bf6ce0000a300001b00c000e0e8622e86556a600b0"
        self.attack_name_to_format["bad6_rsvd"] = HEX

        self.attack_name_to_pkt["bad4_rsvd"] = "27102034a0130034000340aa0340500105065307090807f263000001b000000b0bb000b000000e8622e8b6556b7e0000b0000000b000000b00e862b2e86b55696000"
        self.attack_name_to_format["bad4_rsvd"] = HEX

class TFTP_Attack_Profile:
    def __init__(self):
        self.port = 69  # Port corresponding to the protocol.
        self.attack_name_to_pkt = {}     # Stores the attack packets that can be
                                         # sent to create a loop attack by 
                                         # abusing dns protocol implementations.
        self.attack_name_to_format = {}  # Maps each attack in
                                         # 'attack_name_to_pkt' to the packet's 
                                         # format (format options in 
                                         # class Attack_Pkt_Format()).
        
        # ------------------- Good Request --------------------------------
        tftp_payload = TFTP(op=1)/b'fJFJmcl.jieopg'/TFTP_RRQ()
        self.attack_name_to_pkt['good_read_req'] = to_hex(tftp_payload)
        self.attack_name_to_format['good_read_req'] = HEX

        # ------------------- REQEUST BAD MODE ----------------------------
        request_mode = TFTP_RRQ()
        request_mode.mode = b'ajsoei'
        tftp_payload = TFTP(op=1)/b'fJFJmcl.jieopg'/request_mode
        self.attack_name_to_pkt['bad_mode_read_req'] = to_hex(tftp_payload)
        self.attack_name_to_format['bad_mode_read_req'] = HEX

        # ------------------- REQUEST BAD NULL BYTES ----------------------

        tftp_payload = TFTP(op=1)/b'.'/TFTP_RRQ()
        self.attack_name_to_pkt['read_req_dir'] = to_hex(tftp_payload)
        self.attack_name_to_format['read_req_dir'] = HEX

        tftp_payload = TFTP(op=1)/TFTP_RRQ()
        self.attack_name_to_pkt['read_req_no_filename'] = to_hex(tftp_payload)
        self.attack_name_to_format['read_req_no_filename'] = HEX


        tftp_payload = TFTP(op=1)/b'fJFJmcl.jieopg'/b'\x00'/b'\x00'
        self.attack_name_to_pkt['read_req_no_mode'] = to_hex(tftp_payload)
        self.attack_name_to_format['read_req_no_mode'] = HEX

        tftp_payload = TFTP(op=1)/b'\x00'/b'\x00'
        self.attack_name_to_pkt['read_req_no_file_mode'] = to_hex(tftp_payload)
        self.attack_name_to_format['read_req_no_file_mode'] = HEX
        

        tftp_payload = TFTP(op=1)/b'fJFJmcl.jieopg'/b'\x00octet'
        self.attack_name_to_pkt['read_req_no_end'] = to_hex(tftp_payload)
        self.attack_name_to_format['read_req_no_end'] = HEX

        tftp_payload = TFTP(op=1)/b'fJFJm@!cl.jieopg'/b'\x00octet\x00'
        self.attack_name_to_pkt['read_req_bad_symbol_fname'] = to_hex(tftp_payload)
        self.attack_name_to_format['read_req_bad_symbol_fname'] = HEX

        tftp_payload = TFTP(op=1)
        self.attack_name_to_pkt['read_req_no_payload'] = to_hex(tftp_payload)
        self.attack_name_to_format['read_req_no_payload'] = HEX

        # ------------------- UNEXPECTED DATA -----------------------------


        tftp_payload = TFTP(op=3)/b'\x00\x17\x61\x61' 
        self.attack_name_to_pkt['data_2_bytes'] = to_hex(tftp_payload)
        self.attack_name_to_format['data_2_bytes'] = HEX

        tftp_payload = TFTP(op=3)/b'\x00\x17'/b'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
        self.attack_name_to_pkt['data_512_bytes'] = to_hex(tftp_payload)
        self.attack_name_to_format['data_512_bytes'] = HEX

        # ------------------ UNEXPECTED ACK -------------------------------
        tftp_payload = TFTP(op=4)/b'\x00\x17'
        self.attack_name_to_pkt['ack'] = to_hex(tftp_payload)
        self.attack_name_to_format['ack'] = HEX

        tftp_payload = TFTP(op=4)
        self.attack_name_to_pkt['ack_no_payload'] = to_hex(tftp_payload)
        self.attack_name_to_format['ack_no_payload'] = HEX

        # ------------------ ERROR_MESSAGE --------------------------------

        tftp_payload = TFTP(op=5)/TFTP_ERROR(errorcode=0,errormsg='Not defined')
        self.attack_name_to_pkt['err0'] = to_hex(tftp_payload)
        self.attack_name_to_format['err0'] = HEX
        tftp_payload = TFTP(op=5)/TFTP_ERROR(errorcode=1,errormsg='File not found')
        self.attack_name_to_pkt['err1'] = to_hex(tftp_payload)
        self.attack_name_to_format['err1'] = HEX
        tftp_payload = TFTP(op=5)/TFTP_ERROR(errorcode=2,errormsg='Access violation')
        self.attack_name_to_pkt['err2'] = to_hex(tftp_payload)
        self.attack_name_to_format['err2'] = HEX
        tftp_payload = TFTP(op=5)/TFTP_ERROR(errorcode=3,errormsg='Disk full or allocation exceeded')
        self.attack_name_to_pkt['err3'] = to_hex(tftp_payload)
        self.attack_name_to_format['err3'] = HEX
        tftp_payload = TFTP(op=5)/TFTP_ERROR(errorcode=4,errormsg='Illegal TFTP operation')
        self.attack_name_to_pkt['err4'] = to_hex(tftp_payload)
        self.attack_name_to_format['err4'] = HEX
        tftp_payload = TFTP(op=5)/TFTP_ERROR(errorcode=5,errormsg='Unknown transfer ID')
        self.attack_name_to_pkt['err5'] = to_hex(tftp_payload)
        self.attack_name_to_format['err5'] = HEX
        tftp_payload = TFTP(op=5)/TFTP_ERROR(errorcode=6,errormsg='File already exists')
        self.attack_name_to_pkt['err6'] = to_hex(tftp_payload)
        self.attack_name_to_format['err6'] = HEX
        tftp_payload = TFTP(op=5)/TFTP_ERROR(errorcode=7,errormsg='No such user')
        self.attack_name_to_pkt['err7'] = to_hex(tftp_payload)
        self.attack_name_to_format['err7'] = HEX
        tftp_payload = TFTP(op=5)/TFTP_ERROR(errorcode=128,errormsg='Test ERROR')
        self.attack_name_to_pkt['err8'] = to_hex(tftp_payload)
        self.attack_name_to_format['err8'] = HEX

proto_to_profile = {
    "dns" : DNS_Attack_Profile(), 
    "ntp" : NTP_Attack_Profile(), 
    "tftp" : TFTP_Attack_Profile(),
    "chargen" : Chargen_Attack_Profile(),
    "qotd" : Qotd_Attack_Profile(),
    "echo" : Echo_Attack_Profile(),
    "daytime" : Daytime_Attack_Profile(),
    'auser': Auser_Attack_Profile(),
    'time' : Time_Attack_Profile(),
}


'''
If you want to add a new discovery probe to an existing protocol, e.g., TFTP, you can add the following
lines to class *TFTP_Attack_Profile*.

    self.attack_name_to_pkt['<new_probe_name>'] = 'a hex string, e.g., 0x0005000500'
    self.attack_name_to_format['<new_probe_name>'] = HEX

or you can add:

    self.attack_name_to_pkt['<new_probe_name>'] = 'a string'
    self.attack_name_to_format['<new_probe_name>'] = TEXT
    
TEXT and HEX are two probe payload types accepted by Zmap.

----------------------------------------------------------------------------------------

If you want to probe a new protocol, you can add the following:

1. create a new class for the new protocol and add discovery probes. Example:

    class New_Protocol_Attack_Profile:
        def __init__(self):
            self.port = XX  # Port corresponding to the protocol.
            self.attack_name_to_pkt = {}
            self.attack_name_to_format = {}  

            self.attack_name_to_pkt['probe_1'] = 'example_payload_string'
            self.attack_name_to_format['probe_1'] = TEXT

2. create an instance for the new class in ```proto_to_profile```. Example:


    proto_to_profile = {
        "dns" : DNS_Attack_Profile(), 
        "ntp" : NTP_Attack_Profile(), 
        "tftp" : TFTP_Attack_Profile(),
        "chargen" : Chargen_Attack_Profile(),
        "qotd" : Qotd_Attack_Profile(),
        "echo" : Echo_Attack_Profile(),
        "daytime" : Daytime_Attack_Profile(),
        'auser': Auser_Attack_Profile(),
        'time' : Time_Attack_Profile(),
        'new_p' : New_Protocol_Attack_Profile(),
    }

'''