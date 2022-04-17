global agent_table: table[addr] of set[string] = table();

event http_header(c: connection, is_orig: bool, name: string, value: string) {
    local source_ip: addr = c$id$orig_h;
    if (c$http?$user_agent) {
        local agent: string = to_lower(c$http$user_agent);
        if (source_ip in agent_table) {
            add (agent_table[source_ip])[agent];
        } else {
            agent_table[source_ip] = set(agent);
        }
    }
}

event zeek_done() {
    for (source_ip in agent_table) {
        if (|agent_table[source_ip]| >= 3) {
            print(addr_to_uri(source_ip) + " is a proxy");
        }
    }
}