/* -*- P4_16 -*- */

#include <core.p4>
#include <tna.p4>

#include "./include/types.p4"
#include "./include/headers.p4"
/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/
parser TofinoIngressParser(
        packet_in pkt,
        out ingress_intrinsic_metadata_t ig_intr_md) {
    state start {
        pkt.extract(ig_intr_md);
        transition select(ig_intr_md.resubmit_flag) {
            1 : parse_resubmit;
            0 : parse_port_metadata;
        }
    }
    state parse_resubmit {
        // Parse resubmitted packet here.
        transition reject;
    }
    state parse_port_metadata {
        pkt.advance(PORT_METADATA_SIZE);
        transition accept;
    }
}

parser IngressParser(packet_in        pkt,
    /* User */
    out my_ingress_headers_t          hdr,
    out my_ingress_metadata_t         meta,
    /* Intrinsic */
    out ingress_intrinsic_metadata_t  ig_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
    TofinoIngressParser() tofino_parser;

    state start {
        tofino_parser.apply(pkt, ig_intr_md);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            TYPE_IPV4:  parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        meta.ip_ttl = hdr.ipv4.ttl;
        meta.ip_len = hdr.ipv4.total_len;
        transition select(hdr.ipv4.protocol) {
            TYPE_TCP:  parse_tcp;
            TYPE_UDP:  parse_udp;
            default: accept;
        }
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        meta.hdr_dstport = hdr.tcp.dst_port;
        meta.hdr_srcport = hdr.tcp.src_port;
        meta.tcp_window_size   = hdr.tcp.window;
        meta.tcp_hdr_len = hdr.tcp.data_offset;
        meta.flag_ack    = hdr.tcp.ack;
        meta.flag_syn   = hdr.tcp.syn;
        meta.flag_push   = hdr.tcp.psh;
        transition accept;
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        meta.hdr_dstport = hdr.udp.dst_port;
        meta.hdr_srcport = hdr.udp.src_port;
        meta.tcp_window_size   = 0;
        meta.tcp_hdr_len = 0;
        meta.flag_ack    = 0;
        meta.flag_syn   = 0;
        meta.flag_push = 0;
        transition accept;
    }
}

/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/
/***************** M A T C H - A C T I O N  *********************/
control Ingress(
    /* User */
    inout my_ingress_headers_t                       hdr,
    inout my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_t               ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md)
{
    
    action drop() {
        ig_dprsr_md.drop_ctl = 1;
    }

    /* Forward to a specific port upon classification */
    action ipv4_forward(PortId_t port) {
        ig_tm_md.ucast_egress_port = port;
    }
    /* Custom Do Nothing Action */
    action nop(){}

    /* Assign classes for model RF */
    action SetClass_t0(bit<8> classe, int<8> cert) {
        meta.class_t0 = classe;
        meta.cert_t0 = cert;
    }
    action SetClass_t1(bit<8> classe, int<8> cert) {
        meta.class_t1 = classe;
        meta.cert_t1 = cert;
    }
    action SetClass_t2(bit<8> classe, int<8> cert) {
        meta.class_t2 = classe;
        meta.cert_t2 = cert;
    }


    action set_final_class(bit<8> class_result) {
        meta.class_final = class_result;
        hdr.ipv4.ttl = meta.class_final;
        ipv4_forward(260);
    }

    /* Feature table actions for RF */
    action SetCode_f0(bit<63> code0, bit<69> code1, bit<61> code2) {
        meta.cw_t0[381:319] = code0;
        meta.cw_t1[325:257] = code1;
        meta.cw_t2[319:259] = code2;
    }
    action SetCode_f1(bit<74> code0, bit<61> code1, bit<78> code2) {
        meta.cw_t0[318:245] = code0;
        meta.cw_t1[256:196] = code1;
        meta.cw_t2[258:181] = code2;
    }
    action SetCode_f2(bit<100> code0, bit<73> code1, bit<70> code2) {
        meta.cw_t0[244:145] = code0;
        meta.cw_t1[195:123] = code1;
        meta.cw_t2[180:111] = code2;
    }
    action SetCode_f3(bit<31> code0, bit<38> code1, bit<23> code2) {
        meta.cw_t0[144:114] = code0;
        meta.cw_t1[122:85] = code1;
        meta.cw_t2[110:88] = code2;
    }
    action SetCode_f4(bit<27> code0, bit<29> code1, bit<12> code2) {
        meta.cw_t0[113:87] = code0;
        meta.cw_t1[84:56] = code1;
        meta.cw_t2[87:76] = code2;
    }
    action SetCode_f5(bit<15> code0, bit<10> code1, bit<6> code2) {
        meta.cw_t0[86:72] = code0;
        meta.cw_t1[55:46] = code1;
        meta.cw_t2[75:70]  = code2;
    }
    action SetCode_f6(bit<5> code0, bit<6> code1, bit<12> code2) {
        meta.cw_t0[71:67] = code0;
        meta.cw_t1[45:40] = code1;
        meta.cw_t2[69:58]  = code2;
    }
    action SetCode_f7(bit<6> code0, bit<7> code1, bit<13> code2) {
        meta.cw_t0[66:61] = code0;
        meta.cw_t1[39:33] = code1;
        meta.cw_t2[57:45] = code2;
    }
    action SetCode_f8(bit<61> code0, bit<33> code1, bit<45> code2) {
        meta.cw_t0[60:0] = code0;
        meta.cw_t1[32:0] = code1;
        meta.cw_t2[44:0]  = code2;
    }


    /* Feature tables for RF*/
	table tbl_f0{
	    key = {meta.hdr_dstport: range @name("f0");}
	    actions = {@defaultonly nop; SetCode_f0;}
	    size = 256;
        const default_action = nop();
	}
	table tbl_f1{
        key = {meta.tcp_window_size: range @name("f1");}
	    actions = {@defaultonly nop; SetCode_f1;}
	    size = 256;
        const default_action = nop();
	}
	table tbl_f2{
	    key = {meta.hdr_srcport: range @name("f2");}
	    actions = {@defaultonly nop; SetCode_f2;}
	    size = 350;
        const default_action = nop();
	}
	table tbl_f3{
	    key = {meta.ip_ttl: range @name("f3");}
	    actions = {@defaultonly nop; SetCode_f3;}
	    size = 84;
        const default_action = nop();
	}
	table tbl_f4{
	    key = {meta.tcp_hdr_len: range @name("f4");}
	    actions = {@defaultonly nop; SetCode_f4;}
	    size = 40;
        const default_action = nop();
	}
	table tbl_f5{
	    key = {meta.flag_ack: range @name("f5");}
	    actions = {@defaultonly nop; SetCode_f5;}
	    size = 2;
        const default_action = nop();
	}
    table tbl_f6{
	    key = {meta.flag_syn: range @name("f6");}
	    actions = {@defaultonly nop; SetCode_f6;}
	    size = 2;
        const default_action = nop();
	}
    table tbl_f7{
	    key = {meta.flag_push: range @name("f7");}
	    actions = {@defaultonly nop; SetCode_f7;}
	    size = 2;
        const default_action = nop();
	}
	table tbl_f8{
	    key = {meta.ip_len: range @name("f8");}
	    actions = {@defaultonly nop; SetCode_f8;}
	    size = 150;
        const default_action = nop();
	}

    /* Code tables for RF*/
	table tbl_cw0{
	    key = {meta.cw_t0: ternary;}
	    actions = {@defaultonly nop; SetClass_t0;}
	    size = 530;
        const default_action = nop();
	}
	table tbl_cw1{
        key = {meta.cw_t1: ternary;}
	    actions = {@defaultonly nop; SetClass_t1;} //
	    size = 500;
        const default_action = nop();
	}
	table tbl_cw2{
        key = {meta.cw_t2: ternary;}
	    actions = {@defaultonly nop; SetClass_t2;} //
	    size = 530;
        const default_action = nop();
	}

    /* Determine classification result by majority vote of RF trees */
    table voting_table {
        key = {
            meta.class_t0: exact;
            meta.class_t1: exact;
            meta.class_t2: exact;
        }
        actions = {set_final_class; @defaultonly nop;}
        size = 10000;
        const default_action = nop();
    }

    /* When there is no majority from voting table, we use 
    the certainty values returned by the trees to decide.
    We take the tree result with the highest certainty value.
    */
    bit<1> diff_0_1;
    bit<1> diff_0_2;
    bit<1> diff_1_0;
    bit<1> diff_1_2;
    bit<1> diff_2_0;
    bit<1> diff_2_1;

    /* Action computes difference between certainty values to help 
    identify which one was the highest and hence the final result.
    */
    action diff_x_y(){
        diff_0_1 = (meta.cert_t1 - meta.cert_t0)[7:7];
        diff_0_2 = (meta.cert_t2 - meta.cert_t0)[7:7];
        diff_1_0 = (meta.cert_t0 - meta.cert_t1)[7:7];
        diff_1_2 = (meta.cert_t2 - meta.cert_t1)[7:7];
        diff_2_0 = (meta.cert_t0 - meta.cert_t2)[7:7];
        diff_2_1 = (meta.cert_t1 - meta.cert_t2)[7:7];
    }

    apply {
        // apply feature tables of 1st stage
        tbl_f0.apply();
        tbl_f1.apply();
        tbl_f2.apply();
        tbl_f3.apply();
        tbl_f4.apply();
        tbl_f5.apply();
        tbl_f6.apply();
        tbl_f7.apply();
        tbl_f8.apply();

        // apply code tables of 1st stage
        tbl_cw0.apply();
        tbl_cw1.apply();
        tbl_cw2.apply();

        // determine group
        if (voting_table.apply().hit) {
        // code here to execute if table experienced a hit
        } else {
        // code here to execute if table experienced a miss
        diff_x_y();

            /* Next we find which tree has the highest certainty value and take its result as final.
               We assign this value to the ttl field for statistical purposes as mentioned above.
            */
            if ((diff_0_1 == 1) && (diff_0_2 == 1)){
                meta.class_final = meta.class_t0;
                hdr.ipv4.ttl = meta.class_final;
            }
            else if ((diff_1_0 == 1) && (diff_1_2 == 1)){
                meta.class_final = meta.class_t1;
                hdr.ipv4.ttl = meta.class_final;

            }
            else if ((diff_2_0 == 1) && (diff_2_1 == 1)){
                meta.class_final = meta.class_t2;
                hdr.ipv4.ttl = meta.class_final;
            }
            else{
                /* this is the case where no tree has a higher certainty - this hardly occurs.
                If it does occur, we mark such packets witt value of 255 for statistical purposes.*/
                hdr.ipv4.ttl = 255;
            }
        // End of the process - packet is forwarded.
        ipv4_forward(260);
        }

    } //END OF APPLY

} //END OF INGRESS CONTROL

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control IngressDeparser(packet_out pkt,
    /* User */
    inout my_ingress_headers_t                       hdr,
    in    my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md)
{
    apply {
        /* we do not update checksum because we used ttl field for stats*/
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.tcp);
        pkt.emit(hdr.udp);
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/
#include "./include/egress.p4"

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/
Pipeline(
    IngressParser(),
    Ingress(),
    IngressDeparser(),
    EgressParser(),
    Egress(),
    EgressDeparser()
) pipe;

Switch(pipe) main;
