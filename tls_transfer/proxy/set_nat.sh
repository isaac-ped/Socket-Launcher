set_snat() {
    FROM=$1; TO=$2;
    iptables \
        -A POSTROUTING \
        -t nat \
        -p tcp \
        -d $TO \
        --dport 12345 \
        -j SNAT \
        --to-source $FROM;

}

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
        --mode nth --every $N --packet 0;
}

S=12.0.0.1
D1=13.0.0.1
D2=14.0.0.1

iptables -t nat -F

set_dnat $S $D1 2
set_dnat $S $D2 1
#set_dnat 10.0.0.2 10.0.1.1 1
#set_dnat 10.0.0.2 10.0.2.1 1

set_snat $S $D1
set_snat $S $D2

iptables -t nat --list
#set_snat 10.0.2.2 10.0.2.1
