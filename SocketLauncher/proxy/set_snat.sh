set_snat() {
    FROM=$1; TO=$2
    iptables \
        -A POSTROUTING \
        -t nat \
        -p tcp \
        -d $TO \
        --dport 12345 \
        -j SNAT \
        --to-source $FROM;
}

set_snat 10.0.1.2 10.0.1.1
#set_snat 10.0.2.2 10.0.2.1
