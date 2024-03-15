import networkx as nx
import psycopg2
import pickle
import math
import tabulate
import sys

if len(sys.argv)!=4:
    print('python3 draw_directed_graph.py <loop_probe_result_table> <loop_probe_cluster_result> <cycle_result_output>')

loop_probe_table = sys.argv[1]
loop_probe_cluster_table = sys.argv[2]
ip_pair_file = sys.argv[3]



def simple_cycles(G, limit):
    # code from stack_overflow, we are using an outdated networkx (Debian doens't have the latest version)
    # https://stackoverflow.com/questions/46590502/how-to-modify-johnsons-elementary-cycles-algorithm-to-cap-maximum-cycle-length
    subG = type(G)(G.edges())
    sccs = list(nx.strongly_connected_components(subG))
    while sccs:
        scc = sccs.pop()
        startnode = scc.pop()
        path = [startnode]
        blocked = set()
        blocked.add(startnode)
        stack = [(startnode, list(subG[startnode]))]

        while stack:
            thisnode, nbrs = stack[-1]

            if nbrs and len(path) < limit:
                nextnode = nbrs.pop()
                if nextnode == startnode:
                    yield path[:]
                elif nextnode not in blocked:
                    path.append(nextnode)
                    stack.append((nextnode, list(subG[nextnode])))
                    blocked.add(nextnode)
                    continue
            if not nbrs or len(path) >= limit:
                blocked.remove(thisnode)
                stack.pop()
                path.pop()
        subG.remove_node(startnode)
        H = subG.subgraph(scc)
        sccs.extend(list(nx.strongly_connected_components(H)))

def get_edge_info(scan_2nd_table_name,cluster_table_name):
    db_name = "loop_scan"
    db_conn = psycopg2.connect(database=db_name, user="scan")
    db_conn.autocommit = True
    cursor = db_conn.cursor()

    select_command = "SELECT attack_name as input_id, type_id as output_id,IP_list,ARRAY_LENGTH(IP_list,1) \
    FROM (SELECT attack_name,type_id,ARRAY_AGG(DISTINCT rsp_src_ip) as IP_list\
    FROM (SELECT attack_name, rsp_src_ip, type_id FROM %s\
    JOIN %s ON payload=rsp_payload) AS temp GROUP BY attack_name,type_id)\
    AS TEMP2 ORDER bY ARRAY_LENGTH(IP_list,1) DESC;" % (scan_2nd_table_name,cluster_table_name)


    cursor.execute(select_command)
    data = cursor.fetchall()




    edges = []
    edges_attr = {}
    for item in data:
        edges.append((int(item[0]),int(item[1])))
        edges_attr[str(item[0]) + ":" + str(item[1])] = (item[2],len(item[2]))
    
    return edges,edges_attr


def build_directed_graph(nodes,edges):
    G = nx.DiGraph()
    G.add_nodes_from(nodes)
    G.add_edges_from(edges)
    return G



def get_from_edges_attr(edges_attr,start,end):
    return edges_attr[str(start)+':'+str(end)]

def simplify_graph(graph,edges_attr):
    simplified_nodes = set()
    simplified_edges = set()
    all_ips_affected = set()
    cycle_ip_dict = {}

    nx.simple_cycles = simple_cycles
    cycles = nx.simple_cycles(graph,5)

    table_headers = ['cycle','number of involved IPs','min edge IP amount','min edge','number of pairs']
    print_lines = []


    for cycle in cycles:

        if len(cycle)==1:
            simplified_nodes.add(cycle[0])
            simplified_edges.add((cycle[0],cycle[0]))
            edge_attr = get_from_edges_attr(edges_attr,cycle[0],cycle[0])
            if edge_attr[1]<100:
                continue
            cycle.append(cycle[0])
            print_lines.append([cycle,edge_attr[1],edge_attr[1],[cycle[0],cycle[0]],int(math.factorial(edge_attr[1])/(2*math.factorial(edge_attr[1]-2)))])

            all_ips_affected.update(edge_attr[0])
            cycle_ip_dict[str(cycle)] = (edge_attr[0],edge_attr[0])
            

        elif len(cycle)==2:
            simplified_nodes.add(cycle[0])
            simplified_nodes.add(cycle[1])
            simplified_edges.add((cycle[0],cycle[1]))
            simplified_edges.add((cycle[1],cycle[0]))
            edge_A_attr = get_from_edges_attr(edges_attr,cycle[0],cycle[1])
            edge_B_attr = get_from_edges_attr(edges_attr,cycle[1],cycle[0])
            if edge_A_attr[1]<100 or edge_B_attr[1]<100:
                continue
            cycle.append(cycle[0])
            affected_IPs = set(edge_A_attr[0])
            affected_IPs.update(edge_B_attr[0])
            if edge_A_attr[1]<=edge_B_attr[1]:
                print_lines.append([cycle,len(affected_IPs),min(edge_A_attr[1],edge_B_attr[1]),[cycle[0],cycle[1]],edge_A_attr[1]*edge_B_attr[1]-len(set(edge_A_attr[0]).intersection(set(edge_B_attr[0])))*len(set(edge_A_attr[0]).intersection(set(edge_B_attr[0])))])
            else:
                print_lines.append([cycle,len(affected_IPs),min(edge_A_attr[1],edge_B_attr[1]),[cycle[1],cycle[0]],edge_A_attr[1]*edge_B_attr[1]-len(set(edge_A_attr[0]).intersection(set(edge_B_attr[0])))*len(set(edge_A_attr[0]).intersection(set(edge_B_attr[0])))])
            
            all_ips_affected.update(affected_IPs)
            cycle_ip_dict[str(cycle)] = (edge_A_attr[0],edge_B_attr[0])

        else:
            temp_edge_list_A = set()
            temp_edge_list_B = set()
            cycle.append(cycle[0])
            min_number = 0
            min_edge = None

            try:
                for i in range(0,len(cycle)):
                    if i==len(cycle)-1:
                        break
                    if i==0:
                        edge_attr = get_from_edges_attr(edges_attr,cycle[i],cycle[i+1])
                        temp_edge_list_A.update(edge_attr[0])
                        min_number = edge_attr[1]
                        min_edge=[cycle[i],cycle[i+1]]
                    elif i==1:
                        edge_attr = get_from_edges_attr(edges_attr,cycle[i],cycle[i+1])
                        temp_edge_list_B.update(edge_attr[0])
                        if edge_attr[1]<min_number:
                            min_edge=[cycle[i],cycle[i+1]]
                    elif i%2==0:
                        edge_attr = get_from_edges_attr(edges_attr,cycle[i],cycle[i+1])
                        temp_edge_list_A = temp_edge_list_A.intersection(set(edge_attr[0]))
                        if len(temp_edge_list_A)==0:
                            raise Exception('no IPs')
                        if edge_attr[1]<min_number:
                            min_number = edge_attr[1]
                            min_edge=[cycle[i],cycle[i+1]]
                    elif i%2!=0:
                        edge_attr = get_from_edges_attr(edges_attr,cycle[i],cycle[i+1])
                        temp_edge_list_B = temp_edge_list_B.intersection(set(edge_attr[0]))
                        if len(temp_edge_list_B)==0:
                            raise Exception('no IPs')
                        if edge_attr[1]<min_number:
                            min_number = edge_attr[1]
                            min_edge=[cycle[i],cycle[i+1]]

                if len(temp_edge_list_A)<100 or len(temp_edge_list_B)<100:
                    raise Exception('continue')

                affected_IPs = temp_edge_list_A
                affected_IPs.update(temp_edge_list_B)
                print_lines.append([cycle,len(affected_IPs),min(len(temp_edge_list_A),len(temp_edge_list_B)),min_edge,len(temp_edge_list_A)*len(temp_edge_list_B)-len(set(temp_edge_list_A).intersection(set(temp_edge_list_B)))*len(set(temp_edge_list_A).intersection(set(temp_edge_list_B)))])
                all_ips_affected.update(affected_IPs)
                cycle_ip_dict[str(cycle)] = (list(temp_edge_list_A),list(temp_edge_list_B))

                for i in range(0,len(cycle)):
                    if i==len(cycle)-1:
                        break
                    simplified_nodes.add(cycle[i])
                    simplified_edges.add((cycle[i],cycle[i+1]))
                

            except Exception as e:
                if str(e) == 'no IPs':
                    pass
                elif str(e)=='continue':
                    pass
                else:
                    print(cycle,' : ',str(e))
                    pass

    simplified_graph = nx.DiGraph()
    simplified_graph.add_nodes_from(simplified_nodes)
    simplified_graph.add_edges_from(simplified_edges)
    
    print(tabulate.tabulate(print_lines,headers = table_headers))
    print('number of all affected IPs: ',len(all_ips_affected))

    f = open(ip_pair_file,'wb')
    pickle.dump(cycle_ip_dict,f)
    f.close()

    return simplified_graph










edges,edges_attr = get_edge_info(loop_probe_table,loop_probe_cluster_table)

cluster_id_list = set()
for edge in edges:
    cluster_id_list.add(edge[0])
    cluster_id_list.add(edge[1])
cluster_id_list = list(cluster_id_list)
graph = build_directed_graph(cluster_id_list,edges)
simplified_graph = simplify_graph(graph,edges_attr) 
