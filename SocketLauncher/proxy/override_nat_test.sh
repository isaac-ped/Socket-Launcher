set_dnat() {
    SELF=$1; TO=$2; SIP=$3; SPORT=$4; N=1
    iptables \
        -I PREROUTING \
        -t nat \
        -p tcp \
        -s $SIP \
        -d $SELF\
        --sport $SPORT \
        --dport 12345 \
        -j DNAT \
        --to-destination $TO:12345 \
        -m statistic \
        --mode nth --every $N --packet 0
}

set_snat() {
    FROM=$1; TO=$2; SPORT=$3; SIP=$4
    iptables \
        -A POSTROUTING \
        -t nat \
        -p tcp \
        -d $TO \
        --dport 12345 \
        --sport $SPORT \
        -s $SIP \
        -j SNAT \
        --to-source $FROM;
}

NEW_TO=$1
SELF=$2
SIP=$3
SPORT=$4

if [[ $SPORT == "" ]]; then
    echo usage $0 NEW_TO SELF SIP SPORT
    exit -1
fi

conntrack -L

#conntrack -D -s $SIP -p TCP --sport $SPORT
conntrack -D -s $NEW_TO -p TCP --dport $SPORT
#conntrack -I -p TCP -t 1000 --src $SIP --dst $SELF --sport $SPORT --dport 12345 --src-nat $SELF --dst-nat $NEW_TO --state NONE
conntrack -I -p TCP -t 1000 --src $NEW_TO --dst $SELF --sport 12345 --dport $SPORT --src-nat $SELF --dst-nat $SIP --state NONE

conntrack -L
