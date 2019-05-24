set_dnat() {
    SELF=$1; TO=$2; N=$3
    iptables \
        -A PREROUTING \
        -t nat \
        -p tcp \
        -d $SELF \
        --dport 12345 \
        -j DNAT \
        --to-destination $TO:12345 \
        -m statistic \
        --mode nth --every $N --packet 0
}

set_dnat 10.0.0.2 10.0.1.1 1
#set_dnat 10.0.0.2 10.0.2.1 1

