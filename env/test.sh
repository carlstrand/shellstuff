#!/bin/bash
export DEBIAN_FRONTEND=noninteractive
export RCM_CUSTOM_RELEASE_URL=
export RCM_DIR=/usr/local/lib/roundcubemail
export RCM_PLUGIN_DIR=${RCM_DIR}/plugins
export RCM_CONFIG=${RCM_DIR}/config/config.inc.php

export LANGUAGE=sv_SE.UTF-8
export LC_ALL=sv_SE.UTF-8
export LANG=sv_SE.UTF-8
export LC_TYPE=sv_SE.UTF-8
export NCURSES_NO_UTF8_ACS=1

export STORAGE_USER=user-data
export STORAGE_ROOT=/home/user-data

export PRIMARY_HOSTNAME=zvea.co
export PUBLIC_IP=$(curl -4 --fail --silent --max-time 15 icanhazip.com 2>/dev/null || /bin/true)
export PUBLIC_IPV6=$(curl -6 --fail --silent --max-time 15 icanhazip.com 2>/dev/null || /bin/true)
export PRIVATE_IP=
export PRIVATE_IPV6=
export EMAIL_ADDR=mathias@zvea.co
export EMAIL_PW=mr2gj3mr2gj3
export DISABLE_FIREWALL=0

export db_path=$STORAGE_ROOT/mail/users.sqlite
export inst_dir=/usr/local/lib/mailinabox
export assets_dir=$inst_dir/vendor/assets

export bootstrap_version=4.2.1
export bootstrap_url=https://github.com/twbs/bootstrap/releases/download/v$bootstrap_version/bootstrap-$bootstrap_version-dist.zip

function hide_output {
	OUTPUT=$(tempfile)

	set +e
	$@ &> $OUTPUT
	E=$?
	set -e

	# If the command failed, show the output that was captured in the temporary file.
	if [ $E != 0 ]; then
		# Something failed.
		echo
		echo FAILED: $@
		echo -----------------------------------------
		cat $OUTPUT
		echo -----------------------------------------
		exit $E
	fi

	# Remove temporary file.
	rm -f $OUTPUT
}


function get_default_privateip {

	target=8.8.8.8

	# For the IPv6 route, use the corresponding IPv6 address
	# of Google Public DNS. Again, it doesn't matter so long
	# as it's an address on the public Internet.
	if [ "$1" == "6" ]; then target=2001:4860:4860::8888; fi

	route=$(ip -$1 -o route get $target | grep -v unreachable)
	address=$(echo $route | sed "s/.* src \([^ ]*\).*/\1/")

	if [[ "$1" == "6" && $address == fe80:* ]]; then
		interface=$(echo $route | sed "s/.* dev \([^ ]*\).*/\1/")
		address=$address%$interface
	fi

	echo $address
}

function ufw_allow {
	if [ -z "${DISABLE_FIREWALL:-}" ]; then
		# ufw has completely unhelpful output
		ufw allow $1 > /dev/null;
	fi
}

function restart_service {
	hide_output service $1 restart
}


function wget_verify {
	# Downloads a file from the web and checks that it matches
	# a provided hash. If the comparison fails, exit immediately.
	URL=$1
	HASH=$2
	DEST=$3
	CHECKSUM="$HASH  $DEST"
	rm -f $DEST
	hide_output wget -O $DEST $URL
	if ! echo "$CHECKSUM" | sha1sum --check --strict > /dev/null; then
		echo "------------------------------------------------------------"
		echo "Download of $URL did not match expected checksum."
		echo "Found:"
		sha1sum $DEST
		echo
		echo "Expected:"
		echo "$CHECKSUM"
		rm -f $DEST
		exit 1
	fi
}

function git_clone {
	REPO=$1
	TREEISH=$2
	SUBDIR=$3
	TARGETPATH=$4
	TMPPATH=/tmp/git-clone-$$
	rm -rf $TMPPATH $TARGETPATH
	git clone -q $REPO $TMPPATH || exit 1
	(cd $TMPPATH; git checkout -q $TREEISH;) || exit 1
	mv $TMPPATH/$SUBDIR $TARGETPATH
	rm -rf $TMPPATH
}


function setup_system () {
    source /etc/mailinabox.conf
    
    echo "$PRIMARY_HOSTNAME" > /etc/hostname
    hostname "$PRIMARY_HOSTNAME"
    chmod g-w /etc /etc/default /usr
    
    if [ ! -f /etc/timezone ]; then
        echo "Etc/UTC+1" > /etc/timezone
        restart_service rsyslog
    fi
    
    dd if=/dev/random of=/dev/urandom bs=1 count=32 2> /dev/null
    pollinate  -q -r
    
    
    if [ ! -f /root/.ssh/id_rsa_miab ]; then
        echo 'Creating SSH key for backup…'
        ssh-keygen -t rsa -b 2048 -a 100 -f /root/.ssh/id_rsa_miab -N '' -q
    fi
    
    if [ -z "${DISABLE_FIREWALL:-}" ]; then
        ufw_allow ssh;
        SSH_PORT=$(sshd -T 2>/dev/null | grep "^port " | sed "s/port //") #NODOC
        
        if [ -n "$SSH_PORT" ]; then
            if [ "$SSH_PORT" != "22" ]; then
                echo Opening alternate SSH port "$SSH_PORT". #NODOC
                ufw_allow "$SSH_PORT" #NODOC
            fi
        fi
        
        ufw --force enable;
    fi
    
    tools/editconf.py /etc/default/bind9 \
    "OPTIONS=\"-u bind -4\""
    if ! grep -q "listen-on " /etc/bind/named.conf.options; then
        sed -i "s/^}/\n\tlisten-on { 127.0.0.1; };\n}/" /etc/bind/named.conf.options
    fi
    
    rm -f /etc/resolv.conf
    tools/editconf.py /etc/systemd/resolved.conf DNSStubListener=no
    echo "nameserver 127.0.0.1" > /etc/resolv.conf
    
    restart_service bind9
    systemctl restart systemd-resolved
    rm -f /etc/fail2ban/jail.local # we used to use this file but don't anymore
    rm -f /etc/fail2ban/jail.d/defaults-debian.conf # removes default config so we can manage all of fail2ban rules in one config
    cat conf/fail2ban/jails.conf | sed "s/PUBLIC_IP/$PUBLIC_IP/g" \
    
}


function setup_ssl () {
    if  [ ! -f /usr/bin/openssl ] || [ ! -f $STORAGE_ROOT/ssl/ssl_private_key.pem ] || [ ! -f $STORAGE_ROOT/ssl/ssl_certificate.pem ] || [ ! -f $STORAGE_ROOT/ssl/dh2048.pem ]; then
        echo "Creating initial SSL certificate and perfect forward secrecy Diffie-Hellman parameters..."
    fi
    
    mkdir -p $STORAGE_ROOT/ssl
    
    if [ ! -f $STORAGE_ROOT/ssl/ssl_private_key.pem ]; then
        (umask 077; hide_output openssl genrsa -out $STORAGE_ROOT/ssl/ssl_private_key.pem 2048)
    fi
    
    if [ ! -f $STORAGE_ROOT/ssl/ssl_certificate.pem ]; then
        CSR=/tmp/ssl_cert_sign_req-$$.csr
        hide_output openssl req -new -key $STORAGE_ROOT/ssl/ssl_private_key.pem -out $CSR -sha256 -subj "/CN=$PRIMARY_HOSTNAME"
        CERT=$STORAGE_ROOT/ssl/$PRIMARY_HOSTNAME-selfsigned-$(date --rfc-3339=date | sed s/-//g).pem
        hide_output openssl x509 -req -days 365 -in $CSR -signkey $STORAGE_ROOT/ssl/ssl_private_key.pem -out $CERT
        rm -f $CSR
        ln -s $CERT $STORAGE_ROOT/ssl/ssl_certificate.pem
    fi
    
    if [ ! -f $STORAGE_ROOT/ssl/dh2048.pem ]; then
        openssl dhparam -out $STORAGE_ROOT/ssl/dh2048.pem 2048
    fi
    
}

function setup_dns () {
    mkdir -p /var/run/nsd
    
cat > /etc/nsd/nsd.conf << EOF;
# Do not edit. Overwritten by Mail-in-a-Box setup.
server:
  hide-version: yes
  logfile: "/var/log/nsd.log"

  # identify the server (CH TXT ID.SERVER entry).
  identity: ""

  # The directory for zonefile: files.
  zonesdir: "/etc/nsd/zones"

  # Allows NSD to bind to IP addresses that are not (yet) added to the
  # network interface. This allows nsd to start even if the network stack
  # isn't fully ready, which apparently happens in some cases.
  # See https://www.nlnetlabs.nl/projects/nsd/nsd.conf.5.html.
  ip-transparent: yes
EOF
    
cat > /etc/logrotate.d/nsd <<EOF;
/var/log/nsd.log {
  weekly
  missingok
  rotate 12
  compress
  delaycompress
  notifempty
}
EOF
    
    for ip in $PRIVATE_IP $PRIVATE_IPV6; do
        echo "  ip-address: $ip" >> /etc/nsd/nsd.conf;
    done
    
    echo "include: /etc/nsd/zones.conf" >> /etc/nsd/nsd.conf;
    mkdir -p "$STORAGE_ROOT/dns/dnssec";
    FIRST=1 #NODOC
    
    for algo in RSASHA1-NSEC3-SHA1 RSASHA256; do
        if [ ! -f "$STORAGE_ROOT/dns/dnssec/$algo.conf" ]; then
            if [ $FIRST == 1 ]; then
                FIRST=0 #NODOC
            fi
            
            KSK=$(umask 077; cd $STORAGE_ROOT/dns/dnssec; ldns-keygen -r /dev/urandom -a $algo -b 2048 -k _domain_);
            ZSK=$(umask 077; cd $STORAGE_ROOT/dns/dnssec; ldns-keygen -r /dev/urandom -a $algo -b 1024 _domain_);
            
	cat > $STORAGE_ROOT/dns/dnssec/$algo.conf << EOF;
KSK=$KSK
ZSK=$ZSK
EOF
        fi
    done
    
cat > /etc/cron.daily/mailinabox-dnssec << EOF;
#!/bin/bash
# Mail-in-a-Box
# Re-sign any DNS zones with DNSSEC because the signatures expire periodically.
`pwd`/tools/dns_update
EOF
    
    chmod +x /etc/cron.daily/mailinabox-dnssec
    ufw_allow domain
}

function setup_postfix () {
    tools/editconf.py /etc/postfix/main.cf \
    inet_interfaces=all \
    smtp_bind_address=$PRIVATE_IP \
    smtp_bind_address6=$PRIVATE_IPV6 \
    myhostname=$PRIMARY_HOSTNAME\
    smtpd_banner="\$myhostname ESMTP Hi, I'm a Mail-in-a-Box (Ubuntu/Postfix; see https://mailinabox.email/)" \
    mydestination=localhost
    delay_warning_time=3h \
    maximal_queue_lifetime=2d \
    bounce_queue_lifetime=1d
    
    tools/editconf.py /etc/postfix/master.cf -s -w \
    "submission=inet n       -       -       -       -       smtpd
	  -o smtpd_sasl_auth_enable=yes
	  -o syslog_name=postfix/submission
	  -o smtpd_milters=inet:127.0.0.1:8891
	  -o smtpd_tls_security_level=encrypt
	  -o smtpd_tls_ciphers=high -o smtpd_tls_exclude_ciphers=aNULL,DES,3DES,MD5,DES+MD5,RC4 -o smtpd_tls_mandatory_protocols=!SSLv2,!SSLv3
    -o cleanup_service_name=authclean" \
    "authclean=unix  n       -       -       -       0       cleanup
	  -o header_checks=pcre:/etc/postfix/outgoing_mail_header_filters
    -o nested_header_checks="
    
    cp conf/postfix_outgoing_mail_header_filters /etc/postfix/outgoing_mail_header_filters
    sed -i "s/PRIMARY_HOSTNAME/$PRIMARY_HOSTNAME/" /etc/postfix/outgoing_mail_header_filters
    sed -i "s/PUBLIC_IP/$PUBLIC_IP/" /etc/postfix/outgoing_mail_header_filters
    tools/editconf.py /etc/postfix/main.cf \
    smtpd_tls_security_level=may\
    smtpd_tls_auth_only=yes \
    smtpd_tls_cert_file=$STORAGE_ROOT/ssl/ssl_certificate.pem \
    smtpd_tls_key_file=$STORAGE_ROOT/ssl/ssl_private_key.pem \
    smtpd_tls_dh1024_param_file=$STORAGE_ROOT/ssl/dh2048.pem \
    smtpd_tls_protocols=\!SSLv2,\!SSLv3 \
    smtpd_tls_ciphers=medium \
    smtpd_tls_exclude_ciphers=aNULL,RC4 \
    smtpd_tls_received_header=yes
    
    
    tools/editconf.py /etc/postfix/main.cf \
    smtpd_relay_restrictions=permit_sasl_authenticated,permit_mynetworks,reject_unauth_destination
    
    tools/editconf.py /etc/postfix/main.cf \
    smtp_tls_protocols=\!SSLv2,\!SSLv3 \
    smtp_tls_mandatory_protocols=\!SSLv2,\!SSLv3 \
    smtp_tls_ciphers=medium \
    smtp_tls_exclude_ciphers=aNULL,RC4 \
    smtp_tls_security_level=dane \
    smtp_dns_support_level=dnssec \
    smtp_tls_CAfile=/etc/ssl/certs/ca-certificates.crt \
    smtp_tls_loglevel=2
    
    tools/editconf.py /etc/postfix/main.cf virtual_transport=lmtp:[127.0.0.1]:10025
    tools/editconf.py /etc/postfix/main.cf \
    smtpd_sender_restrictions="reject_non_fqdn_sender,reject_unknown_sender_domain,reject_authenticated_sender_login_mismatch,reject_rhsbl_sender dbl.spamhaus.org" \
    smtpd_recipient_restrictions=permit_sasl_authenticated,permit_mynetworks,"reject_rbl_client zen.spamhaus.org",reject_unlisted_recipient,"check_policy_service inet:127.0.0.1:10023"
    
    tools/editconf.py /etc/default/postgrey \
    POSTGREY_OPTS=\"'--inet=127.0.0.1:10023 --delay=180'\"
    
    tools/editconf.py /etc/postfix/main.cf \
    message_size_limit=134217728
    
    ufw_allow smtp
    ufw_allow submission
    
    restart_service postfix
    restart_service postgrey
}

function setup_dovecot () {
    tools/editconf.py /etc/dovecot/conf.d/10-master.conf \
    default_process_limit=$(echo "`nproc` * 250" | bc) \
    default_vsz_limit=$(echo "`free -tm  | tail -1 | awk '{print $2}'` / 3" | bc)M \
    log_path=/var/log/mail.log
    
    tools/editconf.py /etc/sysctl.conf \
    fs.inotify.max_user_instances=1024
    
    tools/editconf.py /etc/dovecot/conf.d/10-mail.conf \
    mail_location=maildir:$STORAGE_ROOT/mail/mailboxes/%d/%n \
    mail_privileged_group=mail \
    first_valid_uid=0
    
    cp conf/dovecot-mailboxes.conf /etc/dovecot/conf.d/15-mailboxes.conf
    
    tools/editconf.py /etc/dovecot/conf.d/10-auth.conf \
    disable_plaintext_auth=yes \
    "auth_mechanisms=plain login"
    
    tools/editconf.py /etc/dovecot/conf.d/10-ssl.conf \
    ssl=required \
    "ssl_cert=<$STORAGE_ROOT/ssl/ssl_certificate.pem" \
    "ssl_key=<$STORAGE_ROOT/ssl/ssl_private_key.pem" \
    "ssl_protocols=!SSLv3 !SSLv2" \
    "ssl_cipher_list=ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA:ECDHE-ECDSA-DES-CBC3-SHA:ECDHE-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:DES-CBC3-SHA:!DSS" \
    "ssl_prefer_server_ciphers = yes" \
    "ssl_dh_parameters_length = 2048"
    
    sed -i "s/#port = 143/port = 0/" /etc/dovecot/conf.d/10-master.conf
    sed -i "s/#port = 110/port = 0/" /etc/dovecot/conf.d/10-master.conf
    
    tools/editconf.py /etc/dovecot/conf.d/20-imap.conf \
    imap_idle_notify_interval="4 mins"
    
    tools/editconf.py /etc/dovecot/conf.d/20-pop3.conf \
    pop3_uidl_format="%08Xu%08Xv"
    
    
cat > /etc/dovecot/conf.d/99-local.conf << EOF;
service lmtp {
  #unix_listener /var/spool/postfix/private/dovecot-lmtp {
  #  user = postfix
  #  group = postfix
  #}
  inet_listener lmtp {
    address = 127.0.0.1
    port = 10026
  }
}

protocol imap {
  mail_max_userip_connections = 20
}
EOF
    
    
    tools/editconf.py /etc/dovecot/conf.d/15-lda.conf \
    postmaster_address=postmaster@$PRIMARY_HOSTNAME
    
    sed -i "s/#mail_plugins = .*/mail_plugins = \$mail_plugins sieve/" /etc/dovecot/conf.d/20-lmtp.conf
    
cat > /etc/dovecot/conf.d/99-local-sieve.conf << EOF;
plugin {
  sieve_before = /etc/dovecot/sieve-spam.sieve
  sieve_before2 = $STORAGE_ROOT/mail/sieve/global_before
  sieve_after = $STORAGE_ROOT/mail/sieve/global_after
  sieve = $STORAGE_ROOT/mail/sieve/%d/%n.sieve
  sieve_dir = $STORAGE_ROOT/mail/sieve/%d/%n
}
EOF
    
    cp conf/sieve-spam.txt /etc/dovecot/sieve-spam.sieve
    sievec /etc/dovecot/sieve-spam.sieve
    
    chown -R mail:dovecot /etc/dovecot
    chmod -R o-rwx /etc/dovecot
    
    mkdir -p $STORAGE_ROOT/mail/mailboxes
    chown -R mail.mail $STORAGE_ROOT/mail/mailboxes
    
    mkdir -p $STORAGE_ROOT/mail/sieve
    mkdir -p $STORAGE_ROOT/mail/sieve/global_before
    mkdir -p $STORAGE_ROOT/mail/sieve/global_after
    chown -R mail.mail $STORAGE_ROOT/mail/sieve
    
    ufw_allow imaps
    ufw_allow pop3s
    
    ufw_allow sieve
    
    restart_service dovecot
    
}

function setup_users () {
    db_path=$STORAGE_ROOT/mail/users.sqlite
    
    if [ ! -f $db_path ]; then
        echo Creating new user database: $db_path;
        echo "CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT NOT NULL UNIQUE, password TEXT NOT NULL, extra, privileges TEXT NOT NULL DEFAULT '');" | sqlite3 $db_path;
        echo "CREATE TABLE aliases (id INTEGER PRIMARY KEY AUTOINCREMENT, source TEXT NOT NULL UNIQUE, destination TEXT NOT NULL, permitted_senders TEXT);" | sqlite3 $db_path;
    fi
    
    sed -i "s/#*\(\!include auth-system.conf.ext\)/#\1/"  /etc/dovecot/conf.d/10-auth.conf
    sed -i "s/#\(\!include auth-sql.conf.ext\)/\1/"  /etc/dovecot/conf.d/10-auth.conf
    
cat > /etc/dovecot/conf.d/auth-sql.conf.ext << EOF;
passdb {
  driver = sql
  args = /etc/dovecot/dovecot-sql.conf.ext
}
userdb {
  driver = sql
  args = /etc/dovecot/dovecot-sql.conf.ext
}
EOF
    
cat > /etc/dovecot/dovecot-sql.conf.ext << EOF;
driver = sqlite
connect = $db_path
default_pass_scheme = SHA512-CRYPT
password_query = SELECT email as user, password FROM users WHERE email='%u';
user_query = SELECT email AS user, "mail" as uid, "mail" as gid, "$STORAGE_ROOT/mail/mailboxes/%d/%n" as home FROM users WHERE email='%u';
iterate_query = SELECT email AS user FROM users;
EOF
    chmod 0600 /etc/dovecot/dovecot-sql.conf.ext # per Dovecot instructions
cat > /etc/dovecot/conf.d/99-local-auth.conf << EOF;
service auth {
  unix_listener /var/spool/postfix/private/auth {
    mode = 0666
    user = postfix
    group = postfix
  }
}
EOF
    
    tools/editconf.py /etc/postfix/main.cf \
    smtpd_sasl_type=dovecot \
    smtpd_sasl_path=private/auth \
    smtpd_sasl_auth_enable=no
    
    tools/editconf.py /etc/postfix/main.cf \
    smtpd_sender_login_maps=sqlite:/etc/postfix/sender-login-maps.cf
    
cat > /etc/postfix/sender-login-maps.cf << EOF;
dbpath=$db_path
query = SELECT permitted_senders FROM (SELECT permitted_senders, 0 AS priority FROM aliases WHERE source='%s' AND permitted_senders IS NOT NULL UNION SELECT destination AS permitted_senders, 1 AS priority FROM aliases WHERE source='%s' AND permitted_senders IS NULL UNION SELECT email as permitted_senders, 2 AS priority FROM users WHERE email='%s') ORDER BY priority LIMIT 1;
EOF
    
    tools/editconf.py /etc/postfix/main.cf \
    virtual_mailbox_domains=sqlite:/etc/postfix/virtual-mailbox-domains.cf \
    virtual_mailbox_maps=sqlite:/etc/postfix/virtual-mailbox-maps.cf \
    virtual_alias_maps=sqlite:/etc/postfix/virtual-alias-maps.cf \
    local_recipient_maps=\$virtual_mailbox_maps
    
    
cat > /etc/postfix/virtual-mailbox-domains.cf << EOF;
dbpath=$db_path
query = SELECT 1 FROM users WHERE email LIKE '%%@%s' UNION SELECT 1 FROM aliases WHERE source LIKE '%%@%s'
EOF
    
cat > /etc/postfix/virtual-mailbox-maps.cf << EOF;
dbpath=$db_path
query = SELECT 1 FROM users WHERE email='%s'
EOF
    
cat > /etc/postfix/virtual-alias-maps.cf << EOF;
dbpath=$db_path
query = SELECT destination from (SELECT destination, 0 as priority FROM aliases WHERE source='%s' AND destination<>'' UNION SELECT email as destination, 1 as priority FROM users WHERE email='%s') ORDER BY priority LIMIT 1;
EOF
    
    restart_service postfix
    restart_service dovecot
    
    
    
}


function setup_dkim () {
    mkdir -p /etc/opendkim;
    mkdir -p $STORAGE_ROOT/mail/dkim
    
    # Used in InternalHosts and ExternalIgnoreList configuration directives.
    # Not quite sure why.
    echo "127.0.0.1" > /etc/opendkim/TrustedHosts
    
    # We need to at least create these files, since we reference them later.
    # Otherwise, opendkim startup will fail
    touch /etc/opendkim/KeyTable
    touch /etc/opendkim/SigningTable
    
    if grep -q "ExternalIgnoreList" /etc/opendkim.conf; then
        true # already done #NODOC
    else
        # Add various configuration options to the end of `opendkim.conf`.
	cat >> /etc/opendkim.conf << EOF;
MinimumKeyBits          1024
ExternalIgnoreList      refile:/etc/opendkim/TrustedHosts
InternalHosts           refile:/etc/opendkim/TrustedHosts
KeyTable                refile:/etc/opendkim/KeyTable
SigningTable            refile:/etc/opendkim/SigningTable
Socket                  inet:8891@127.0.0.1
RequireSafeKeys         false
EOF
    fi
    
    # Create a new DKIM key. This creates mail.private and mail.txt
    # in $STORAGE_ROOT/mail/dkim. The former is the private key and
    # the latter is the suggested DNS TXT entry which we'll include
    # in our DNS setup. Note that the files are named after the
    # 'selector' of the key, which we can change later on to support
    # key rotation.
    #
    # A 1024-bit key is seen as a minimum standard by several providers
    # such as Google. But they and others use a 2048 bit key, so we'll
    # do the same. Keys beyond 2048 bits may exceed DNS record limits.
    if [ ! -f "$STORAGE_ROOT/mail/dkim/mail.private" ]; then
        opendkim-genkey -b 2048 -r -s mail -D $STORAGE_ROOT/mail/dkim
    fi
    
    # Ensure files are owned by the opendkim user and are private otherwise.
    chown -R opendkim:opendkim $STORAGE_ROOT/mail/dkim
    chmod go-rwx $STORAGE_ROOT/mail/dkim
    
    tools/editconf.py /etc/opendmarc.conf -s \
    "Syslog=true" \
    "Socket=inet:8893@[127.0.0.1]"
    
    # Add OpenDKIM and OpenDMARC as milters to postfix, which is how OpenDKIM
    # intercepts outgoing mail to perform the signing (by adding a mail header)
    # and how they both intercept incoming mail to add Authentication-Results
    # headers. The order possibly/probably matters: OpenDMARC relies on the
    # OpenDKIM Authentication-Results header already being present.
    #
    # Be careful. If we add other milters later, this needs to be concatenated
    # on the smtpd_milters line.
    #
    # The OpenDMARC milter is skipped in the SMTP submission listener by
    # configuring smtpd_milters there to only list the OpenDKIM milter
    # (see mail-postfix.sh).
    tools/editconf.py /etc/postfix/main.cf \
    "smtpd_milters=inet:127.0.0.1:8891 inet:127.0.0.1:8893"\
    non_smtpd_milters=\$smtpd_milters \
    milter_default_action=accept
    
    # We need to explicitly enable the opendmarc service, or it will not start
    hide_output systemctl enable opendmarc
    
    # Restart services.
    restart_service opendkim
    restart_service opendmarc
    restart_service postfix
    
}

function setup_spamassassin () {
    tools/editconf.py /etc/default/spamassassin \
    CRON=1
    
    # Configure pyzor, which is a client to a live database of hashes of
    # spam emails. Set the pyzor configuration directory to something sane.
    # The default is ~/.pyzor. We used to use that, so we'll kill that old
    # directory. Then write the public pyzor server to its servers file.
    # That will prevent an automatic download on first use, and also means
    # we can skip 'pyzor discover', both of which are currently broken by
    # something happening on Sourceforge (#496).
    rm -rf ~/.pyzor
    tools/editconf.py /etc/spamassassin/local.cf -s \
    pyzor_options="--homedir /etc/spamassassin/pyzor"
    mkdir -p /etc/spamassassin/pyzor
    echo "public.pyzor.org:24441" > /etc/spamassassin/pyzor/servers
    # check with: pyzor --homedir /etc/mail/spamassassin/pyzor ping
    
    # Configure spampd:
    # * Pass messages on to docevot on port 10026. This is actually the default setting but we don't
    #   want to lose track of it. (We've configured Dovecot to listen on this port elsewhere.)
    # * Increase the maximum message size of scanned messages from the default of 64KB to 500KB, which
    #   is Spamassassin (spamc)'s own default. Specified in KBytes.
    # * Disable localmode so Pyzor, DKIM and DNS checks can be used.
    tools/editconf.py /etc/default/spampd \
    DESTPORT=10026 \
    ADDOPTS="\"--maxsize=2000\"" \
    LOCALONLY=0
    
    # Spamassassin normally wraps spam as an attachment inside a fresh
    # email with a report about the message. This also protects the user
    # from accidentally openening a message with embedded malware.
    #
    # It's nice to see what rules caused the message to be marked as spam,
    # but it's also annoying to get to the original message when it is an
    # attachment, modern mail clients are safer now and don't load remote
    # content or execute scripts, and it is probably confusing to most users.
    #
    # Tell Spamassassin not to modify the original message except for adding
    # the X-Spam-Status & X-Spam-Score mail headers and related headers.
    tools/editconf.py /etc/spamassassin/local.cf -s \
    report_safe=0 \
    add_header="all Report _REPORT_" \
    add_header="all Score _SCORE_"
    
    # Bayesean learning
    # -----------------
    #
    # Spamassassin can learn from mail marked as spam or ham, but it needs to be
    # configured. We'll store the learning data in our storage area.
    #
    # These files must be:
    #
    # * Writable by sa-learn-pipe script below, which run as the 'mail' user, for manual tagging of mail as spam/ham.
    # * Readable by the spampd process ('spampd' user) during mail filtering.
    # * Writable by the debian-spamd user, which runs /etc/cron.daily/spamassassin.
    #
    # We'll have these files owned by spampd and grant access to the other two processes.
    #
    # Spamassassin will change the access rights back to the defaults, so we must also configure
    # the filemode in the config file.
    
    tools/editconf.py /etc/spamassassin/local.cf -s \
    bayes_path=$STORAGE_ROOT/mail/spamassassin/bayes \
    bayes_file_mode=0666
    
    mkdir -p $STORAGE_ROOT/mail/spamassassin
    chown -R spampd:spampd $STORAGE_ROOT/mail/spamassassin
    
    # To mark mail as spam or ham, just drag it in or out of the Spam folder. We'll
    # use the Dovecot antispam plugin to detect the message move operation and execute
    # a shell script that invokes learning.
    
    # Enable the Dovecot antispam plugin.
    # (Be careful if we use multiple plugins later.) #NODOC
    sed -i "s/#mail_plugins = .*/mail_plugins = \$mail_plugins antispam/" /etc/dovecot/conf.d/20-imap.conf
    sed -i "s/#mail_plugins = .*/mail_plugins = \$mail_plugins antispam/" /etc/dovecot/conf.d/20-pop3.conf
    
    # Configure the antispam plugin to call sa-learn-pipe.sh.
cat > /etc/dovecot/conf.d/99-local-spampd.conf << EOF;
plugin {
    antispam_backend = pipe
    antispam_spam_pattern_ignorecase = SPAM
    antispam_trash_pattern_ignorecase = trash;Deleted *
    antispam_allow_append_to_spam = yes
    antispam_pipe_program_spam_args = /usr/local/bin/sa-learn-pipe.sh;--spam
    antispam_pipe_program_notspam_args = /usr/local/bin/sa-learn-pipe.sh;--ham
    antispam_pipe_program = /bin/bash
}
EOF
    
    # Have Dovecot run its mail process with a supplementary group (the spampd group)
    # so that it can access the learning files.
    
    tools/editconf.py /etc/dovecot/conf.d/10-mail.conf \
    mail_access_groups=spampd
    
    # Here's the script that the antispam plugin executes. It spools the message into
    # a temporary file and then runs sa-learn on it.
    # from http://wiki2.dovecot.org/Plugins/Antispam
    rm -f /usr/bin/sa-learn-pipe.sh # legacy location #NODOC
cat > /usr/local/bin/sa-learn-pipe.sh << EOF;
cat<&0 >> /tmp/sendmail-msg-\$\$.txt
/usr/bin/sa-learn \$* /tmp/sendmail-msg-\$\$.txt > /dev/null
rm -f /tmp/sendmail-msg-\$\$.txt
exit 0
EOF
    chmod a+x /usr/local/bin/sa-learn-pipe.sh
    
    # Create empty bayes training data (if it doesn't exist). Once the files exist,
    # ensure they are group-writable so that the Dovecot process has access.
    sudo -u spampd /usr/bin/sa-learn --sync 2>/dev/null
    chmod -R 660 $STORAGE_ROOT/mail/spamassassin
    chmod 770 $STORAGE_ROOT/mail/spamassassin
    
    # Initial training?
    # sa-learn --ham storage/mail/mailboxes/*/*/cur/
    # sa-learn --spam storage/mail/mailboxes/*/*/.Spam/cur/
    
    # Kick services.
    restart_service spampd
    restart_service dovecot
    
}

function setup_web () {
    
    # Install nginx and a PHP FastCGI daemon.
    #
    # Turn off nginx's default website.
    
    echo "Installing Nginx (web server)..."
    
    apt_install nginx php-cli php-fpm
    
    rm -f /etc/nginx/sites-enabled/default
    
    # Copy in a nginx configuration file for common and best-practices
    # SSL settings from @konklone. Replace STORAGE_ROOT so it can find
    # the DH params.
    rm -f /etc/nginx/nginx-ssl.conf # we used to put it here
    sed "s#STORAGE_ROOT#$STORAGE_ROOT#" \
    conf/nginx-ssl.conf > /etc/nginx/conf.d/ssl.conf
    
    # Fix some nginx defaults.
    # The server_names_hash_bucket_size seems to prevent long domain names!
    # The default, according to nginx's docs, depends on "the size of the
    # processor’s cache line." It could be as low as 32. We fixed it at
    # 64 in 2014 to accommodate a long domain name (20 characters?). But
    # even at 64, a 58-character domain name won't work (#93), so now
    # we're going up to 128.
    tools/editconf.py /etc/nginx/nginx.conf -s \
    server_names_hash_bucket_size="128;"
    
    # Tell PHP not to expose its version number in the X-Powered-By header.
    tools/editconf.py /etc/php/7.2/fpm/php.ini -c ';' \
    expose_php=Off
    
    # Set PHPs default charset to UTF-8, since we use it. See #367.
    tools/editconf.py /etc/php/7.2/fpm/php.ini -c ';' \
    default_charset="UTF-8"
    
    # Switch from the dynamic process manager to the ondemand manager see #1216
    tools/editconf.py /etc/php/7.2/fpm/pool.d/www.conf -c ';' \
    pm=ondemand
    
    # Bump up PHP's max_children to support more concurrent connections
    tools/editconf.py /etc/php/7.2/fpm/pool.d/www.conf -c ';' \
    pm.max_children=8
    
    mkdir -p /var/lib/mailinabox
    chmod a+rx /var/lib/mailinabox
    cat conf/ios-profile.xml| sed "s/PRIMARY_HOSTNAME/$PRIMARY_HOSTNAME/" | sed "s/UUID1/$(cat /proc/sys/kernel/random/uuid)/" | sed "s/UUID2/$(cat /proc/sys/kernel/random/uuid)/" | sed "s/UUID3/$(cat /proc/sys/kernel/random/uuid)/" | sed "s/UUID4/$(cat /proc/sys/kernel/random/uuid)/" \
    > /var/lib/mailinabox/mobileconfig.xml
    chmod a+r /var/lib/mailinabox/mobileconfig.xml

    cat conf/mozilla-autoconfig.xml | sed "s/PRIMARY_HOSTNAME/$PRIMARY_HOSTNAME/" > /var/lib/mailinabox/mozilla-autoconfig.xml
    chmod a+r /var/lib/mailinabox/mozilla-autoconfig.xml
    
    # make a default homepage
    if [ -d $STORAGE_ROOT/www/static ]; then mv $STORAGE_ROOT/www/static $STORAGE_ROOT/www/default; fi # migration #NODOC
    mkdir -p $STORAGE_ROOT/www/default
    if [ ! -f $STORAGE_ROOT/www/default/index.html ]; then
        cp conf/www_default.html $STORAGE_ROOT/www/default/index.html
    fi
    chown -R $STORAGE_USER $STORAGE_ROOT/www
    
    # Start services.
    restart_service nginx
    restart_service php7.2-fpm
    
    # Open ports.
    ufw_allow http
    ufw_allow https
}

function setup_webmail () {
    tar -C /usr/local/lib --no-same-owner -zxf /tmp/roundcubemail-release-complete.tar.gz
    rm -rf /usr/local/lib/roundcubemail
    mv /usr/local/lib/roundcubemail-$VERSION/ $RCM_DIR
    rm -f /tmp/roundcubemail-release-complete.tar.gz
    
    SECRET_KEY=$(dd if=/dev/urandom bs=1 count=18 2>/dev/null | base64 | fold -w 24 | head -n 1)
    
cat > $RCM_CONFIG <<EOF;
<?php
/*
 * Do not edit. Written by Mail-in-a-Box. Regenerated on updates.
 */
\$config = array();
\$config['log_dir'] = '/var/log/roundcubemail/';
\$config['temp_dir'] = '/var/tmp/roundcubemail/';
\$config['db_dsnw'] = 'sqlite:///$STORAGE_ROOT/mail/roundcube/roundcube.sqlite?mode=0640';
\$config['default_host'] = 'ssl://localhost';
\$config['default_port'] = 993;
\$config['imap_conn_options'] = array(
  'ssl'         => array(
     'verify_peer'  => false,
     'verify_peer_name'  => false,
   ),
 );
\$config['imap_timeout'] = 15;
\$config['smtp_server'] = 'tls://127.0.0.1';
\$config['smtp_port'] = 587;
\$config['smtp_user'] = '%u';
\$config['smtp_pass'] = '%p';
\$config['smtp_conn_options'] = array(
  'ssl'         => array(
     'verify_peer'  => false,
     'verify_peer_name'  => false,
   ),
 );
\$config['support_url'] = 'https://mailinabox.email/';
\$config['product_name'] = '$PRIMARY_HOSTNAME Webmail';
\$config['des_key'] = '$SECRET_KEY';
\$config['plugins'] = array('archive', 'zipdownload', 'password', 'managesieve', 'jqueryui', 'autologon');
\$config['skin'] = 'elastic';
\$config['login_autocomplete'] = 2;
\$config['password_charset'] = 'UTF-8';
\$config['junk_mbox'] = 'Spam';
\$config['identity_select_headers'] = array('Delivered-To');
\$config['redundant_attachments_fallback'] = false;
\$config['redundant_attachments_cache_ttl'] = 12 * 60 * 60;
\$config['zipdownload_attachments'] = 1;
\$config['zipdownload_selection'] = '3GB';
\$config['zipdownload_charset'] = 'ISO-8859-1';
?>
EOF
    
    mkdir -p /var/log/roundcubemail /var/tmp/roundcubemail $STORAGE_ROOT/mail/roundcube
    chown -R www-data.www-data /var/log/roundcubemail /var/tmp/roundcubemail $STORAGE_ROOT/mail/roundcube
    sudo -u www-data touch /var/log/roundcubemail/errors
    cp ${RCM_PLUGIN_DIR}/password/config.inc.php.dist \
    ${RCM_PLUGIN_DIR}/password/config.inc.php
    tools/editconf.py ${RCM_PLUGIN_DIR}/password/config.inc.php \
    "\$config['password_minimum_length']=8;" \
    "\$config['password_db_dsn']='sqlite:///$STORAGE_ROOT/mail/users.sqlite';" \
    "\$config['password_query']='UPDATE users SET password=%D WHERE email=%u';" \
    "\$config['password_dovecotpw']='/usr/bin/doveadm pw';" \
    "\$config['password_dovecotpw_method']='SHA512-CRYPT';" \
    "\$config['password_dovecotpw_with_method']=true;"
    
    
    usermod -a -G dovecot www-data
    chown root.www-data $STORAGE_ROOT/mail
    chmod 775 $STORAGE_ROOT/mail
    chown root.www-data $STORAGE_ROOT/mail/users.sqlite
    chmod 664 $STORAGE_ROOT/mail/users.sqlite
    ${RCM_DIR}/bin/updatedb.sh --dir ${RCM_DIR}/SQL --package roundcube
    chown www-data:www-data $STORAGE_ROOT/mail/roundcube/roundcube.sqlite
    chmod 664 $STORAGE_ROOT/mail/roundcube/roundcube.sqlite
    
    phpenmod -v php mcrypt imap mbstring zlib
    restart_service php7.2-fpm
    
}

function setup_zpush () {
    phpenmod -v php imap
    VERSION=2.4.5
    TARGETHASH=104d44426852429dac8ec2783a4e9ad7752d4682
    needs_update=0 #NODOC
    
    if [ ! -f /usr/local/lib/z-push/version ]; then
        needs_update=1 #NODOC
        elif [[ $VERSION != `cat /usr/local/lib/z-push/version` ]]; then
        # checks if the version
        needs_update=1 #NODOC
    fi
    if [ $needs_update == 1 ]; then
        wget_verify "https://stash.z-hub.io/rest/api/latest/projects/ZP/repos/z-push/archive?at=refs%2Ftags%2F$VERSION&format=zip" $TARGETHASH /tmp/z-push.zip
        
        rm -rf /usr/local/lib/z-push /tmp/z-push
        unzip -q /tmp/z-push.zip -d /tmp/z-push
        mv /tmp/z-push/src /usr/local/lib/z-push
        rm -rf /tmp/z-push.zip /tmp/z-push
        
        rm -f /usr/sbin/z-push-{admin,top}
        ln -s /usr/local/lib/z-push/z-push-admin.php /usr/sbin/z-push-admin
        ln -s /usr/local/lib/z-push/z-push-top.php /usr/sbin/z-push-top
        echo $VERSION > /usr/local/lib/z-push/version
    fi
    
    # Configure default config.
    sed -i "s^define('TIMEZONE', .*^define('TIMEZONE', '$(cat /etc/timezone)');^" /usr/local/lib/z-push/config.php
    sed -i "s/define('BACKEND_PROVIDER', .*/define('BACKEND_PROVIDER', 'BackendCombined');/" /usr/local/lib/z-push/config.php
    sed -i "s/define('USE_FULLEMAIL_FOR_LOGIN', .*/define('USE_FULLEMAIL_FOR_LOGIN', true);/" /usr/local/lib/z-push/config.php
    sed -i "s/define('LOG_MEMORY_PROFILER', .*/define('LOG_MEMORY_PROFILER', false);/" /usr/local/lib/z-push/config.php
    sed -i "s/define('BUG68532FIXED', .*/define('BUG68532FIXED', false);/" /usr/local/lib/z-push/config.php
    sed -i "s/define('LOGLEVEL', .*/define('LOGLEVEL', LOGLEVEL_ERROR);/" /usr/local/lib/z-push/config.php
    
    # Configure BACKEND
    rm -f /usr/local/lib/z-push/backend/combined/config.php
    cp conf/zpush/backend_combined.php /usr/local/lib/z-push/backend/combined/config.php
    
    # Configure IMAP
    rm -f /usr/local/lib/z-push/backend/imap/config.php
    cp conf/zpush/backend_imap.php /usr/local/lib/z-push/backend/imap/config.php
    sed -i "s%STORAGE_ROOT%$STORAGE_ROOT%" /usr/local/lib/z-push/backend/imap/config.php
    
    # Configure CardDav
    # rm -f /usr/local/lib/z-push/backend/carddav/config.php
    # cp conf/zpush/backend_carddav.php /usr/local/lib/z-push/backend/carddav/config.php
    
    # Configure CalDav
    # rm -f /usr/local/lib/z-push/backend/caldav/config.php
    # cp conf/zpush/backend_caldav.php /usr/local/lib/z-push/backend/caldav/config.php
    
    # Configure Autodiscover
    rm -f /usr/local/lib/z-push/autodiscover/config.php
    cp conf/zpush/autodiscover_config.php /usr/local/lib/z-push/autodiscover/config.php
    sed -i "s/PRIMARY_HOSTNAME/$PRIMARY_HOSTNAME/" /usr/local/lib/z-push/autodiscover/config.php
    sed -i "s^define('TIMEZONE', .*^define('TIMEZONE', '$(cat /etc/timezone)');^" /usr/local/lib/z-push/autodiscover/config.php
    
    mkdir -p /var/log/z-push
    mkdir -p /var/lib/z-push
    chmod 750 /var/log/z-push
    chmod 750 /var/lib/z-push
    chown www-data:www-data /var/log/z-push
    chown www-data:www-data /var/lib/z-push
    
cat > /etc/logrotate.d/z-push <<EOF;
/var/log/z-push/*.log {
	weekly
	missingok
	rotate 52
	compress
	delaycompress
	notifempty
}
EOF
    
    restart_service php7.2-fpm
    hide_output z-push-admin -a fixstates
    
}

function setup_management () {
    while [ -d /usr/local/lib/python3.4/dist-packages/acme ]; do
        pip3 uninstall -y acme;
    done
    
    hide_output pip2 install --upgrade boto
    
    inst_dir=/usr/local/lib/mailinabox
    mkdir -p $inst_dir
    venv=$inst_dir/env
    
    if [ ! -d $venv ]; then
        virtualenv -ppython3 $venv
    fi
    
    hide_output $venv/bin/pip install --upgrade pip
    hide_output $venv/bin/pip install --upgrade \
    rtyaml "email_validator>=1.0.0" "exclusiveprocess" \
    flask dnspython python-dateutil \
    "idna>=2.0.0" "cryptography==2.2.2" boto psutil
    
    mkdir -p $STORAGE_ROOT/backup
    if [ ! -f $STORAGE_ROOT/backup/secret_key.txt ]; then
        $(umask 077; openssl rand -base64 2048 > $STORAGE_ROOT/backup/secret_key.txt)
    fi
    
    assets_dir=$inst_dir/vendor/assets
    rm -rf $assets_dir
    mkdir -p $assets_dir
    
    jquery_version=2.1.4
    jquery_url=https://code.jquery.com
    wget_verify $jquery_url/jquery-$jquery_version.min.js 43dc554608df885a59ddeece1598c6ace434d747 $assets_dir/jquery.min.js
    bootstrap_version=4.2.0
    bootstrap_url=https://github.com/twbs/bootstrap/releases/download/v$bootstrap_version/bootstrap-$bootstrap_version-dist.zip
    wget_verify $bootstrap_url e6b1000b94e835ffd37f4c6dcbdad43f4b48a02a /tmp/bootstrap.zip
    unzip -q /tmp/bootstrap.zip -d $assets_dir
    mv $assets_dir/bootstrap-$bootstrap_version-dist $assets_dir/bootstrap
    rm -f /tmp/bootstrap.zip
    
    # Create an init script to start the management daemon and keep it
    # running after a reboot.
cat > $inst_dir/start <<EOF;
#!/bin/bash
source $venv/bin/activate
exec python `pwd`/management/daemon.py
EOF
    
    chmod +x $inst_dir/start
    hide_output systemctl link conf/mailinabox.service
    hide_output systemctl daemon-reload
    hide_output systemctl enable mailinabox.service
    
cat > /etc/cron.d/mailinabox-nightly << EOF;
# Mail-in-a-Box --- Do not edit / will be overwritten on update.
# Run nightly tasks: backup, status checks.
0 3 * * *	root	(cd `pwd` && management/daily_tasks.sh)
EOF
    
    restart_service mailinabox
    
}

function setup_munin () {
cat > /etc/munin/munin.conf <<EOF;
dbdir /var/lib/munin
htmldir /var/cache/munin/www
logdir /var/log/munin
rundir /var/run/munin
tmpldir /etc/munin/templates

includedir /etc/munin/munin-conf.d

# path dynazoom uses for requests
cgiurl_graph /admin/munin/cgi-graph

# a simple host tree
[$PRIMARY_HOSTNAME]
address 127.0.0.1

# send alerts to the following address
contacts admin
contact.admin.command mail -s "Munin notification \${var:host}" administrator@$PRIMARY_HOSTNAME
contact.admin.always_send warning critical
EOF
    
    chown munin. /var/log/munin/munin-cgi-html.log
    chown munin. /var/log/munin/munin-cgi-graph.log
    
    tools/editconf.py /etc/munin/munin-node.conf -s \
    host_name=$PRIMARY_HOSTNAME \
    log_level=1
    
    munin-node-configure --shell --remove-also 2>/dev/null | sh || /bin/true
    find /etc/munin/plugins/ -lname /usr/share/munin/plugins/ntp_ -print0 | xargs -0 /bin/rm -f
    
    for f in $(find /etc/munin/plugins/ \( -lname /usr/share/munin/plugins/if_ -o -lname /usr/share/munin/plugins/if_err_ -o -lname /usr/share/munin/plugins/bonding_err_ \)); do
        IF=$(echo $f | sed s/.*_//);
        if ! ifquery $IF >/dev/null 2>/dev/null; then
            rm $f;
        fi;
    done
    
    mkdir -p /var/lib/munin-node/plugin-state/
    
    ln -sf $(pwd)/management/munin_start.sh /usr/local/lib/mailinabox/munin_start.sh
    chmod 0744 /usr/local/lib/mailinabox/munin_start.sh
    hide_output systemctl link conf/munin.service
    hide_output systemctl daemon-reload
    hide_output systemctl unmask munin.service
    hide_output systemctl enable munin.service
    restart_service munin
    restart_service munin-node
    sudo -H -u munin munin-cron
    
}

function setup_services {
    
    git clone --depth 1 https://github.com/carlstrand/mailinabox $HOME/mailinabox < /dev/null 2> /dev/null




	# Create the user's mail account. This will ask for a password if none was given above.
	tools/mail.py user add $EMAIL_ADDR ${EMAIL_PW:-}

	# Make it an admin.
	hide_output tools/mail.py user make-admin $EMAIL_ADDR

	# Create an alias to which we'll direct all automatically-created administrative aliases.
	tools/mail.py alias add administrator@$PRIMARY_HOSTNAME $EMAIL_ADDR > /dev/null
    # source setup/zpush.sh
    # source setup/management.sh
    # source setup/munin.sh
    
}

function setup_zsh {
    apt-fast install -q -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confnew" tilda tmux meld xclip vim-gui-common vim-runtime nano vim zsh
    
    mkdir -p ~/.config/tilda
    mkdir -p /opt/.zsh/ && chmod ugo+w /opt/.zsh/
    
    cp ./config_files/.vimrc ~
    cp ./config_files/.tmux.conf ~
    cp ./config_files/.tmux.conf.local ~
    cp ./config_files/config_0 ~/.config/tilda/
    
    git clone --recursive --quiet https://github.com/Eriner/zim.git /opt/.zsh/zim
    git clone --quiet https://github.com/zsh-users/zsh-autosuggestions /opt/.zsh/zsh-autosuggestions
    
    ln -s /opt/.zsh/zim/ ~/.zim
    ln -s /opt/.zsh/zim/templates/zimrc ~/.zimrc
    ln -s /opt/.zsh/zim/templates/zlogin ~/.zlogin
    ln -s /opt/.zsh/zim/templates/zshrc ~/.zshrc
    
    touch /opt/.zsh/bash_aliases
    
    echo "source /opt/.zsh/zsh-autosuggestions/zsh-autosuggestions.zsh" >> ~/.zshrc
    command -v zsh | tee -a /etc/shells
    chsh -s "$(command -v zsh)" "${USER}"
}

function initialize_env {

    apt-get update -q && apt-get upgrade -y && apt-get dist-upgrade -y
    
    ## Setup the atp repos
    apt-get install -q -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confnew" software-properties-common python-software-properties
    add-apt-repository -y ppa:apt-fast/stable
    add-apt-repository -y ppa:certbot/certbot
    curl -sL https://deb.nodesource.com/setup_11.x | -E bash -
    
    ## Install atp-fast
    apt-get install -q -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confnew" aria2 apt-fast
    
    ## Install relevant packages
    apt-fast install -q -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confnew" \
    locales python3 python3-dev python3-pip netcat-openbsd wget curl git sudo coreutils bc \
    haveged pollinate unzip unattended-upgrades cron ntp fail2ban rsyslog build-essential \
    zlib1g-dev libpcre3 libpcre3-dev unzip uuid-dev openssl libssl-dev zlibc zlib1g libxml2-dev \
    libxslt-dev libgd-dev gcc google-perftools libgoogle-perftools-dev libperl-dev libgeoip1 \
    libgeoip-dev ufw opendkim opendkim-tools opendmarc nsd ldnsutils openssh-client dovecot-core \
    dovecot-imapd dovecot-pop3d dovecot-lmtpd dovecot-sqlite sqlite3 dovecot-sieve dovecot-managesieved \
    postfix postfix-sqlite postfix-pcre postgrey ca-certificates duplicity python-pip virtualenv \
    certbot munin munin-node libcgi-fast-perl bind9-host sed netcat-openbsd spampd razor pyzor \
    dovecot-antispam libmail-dkim-perl nginx php-cli php-fpm php-soap php-imap libawl-php php-xsl \
    dbconfig-common php-sqlite3 php-intl php-json php-common php-curl php-gd php-pspell tinymce \
    libjs-jquery libjs-jquery-mousewheel libmagic1 php-mbstring php-pear nodejs
    
    
    setup_zsh
    
    ### System maintainece stuff...
    
    if [ -f /etc/update-manager/release-upgrades ]; then
        tools/editconf.py /etc/update-manager/release-upgrades Prompt=never
        rm -f /var/lib/ubuntu-release-upgrader/release-upgrade-available
    fi
    
    if [ -f /etc/apt/apt.conf.d/50unattended-upgrades ]; then
        if ! grep -q "$1" /etc/apt/apt.conf.d/50unattended-upgrades; then
            sudo sed -i "/Allowed-Origins/a \
            \"$1\";" /etc/apt/apt.conf.d/50unattended-upgrades
        fi
    fi
    
    # ### Package maintenance - allow system updates automatically every day.
    cat > /etc/apt/apt.conf.d/02periodic <<EOF;
    APT::Periodic::MaxAge "7";
    APT::Periodic::Update-Package-Lists "1";
    APT::Periodic::Unattended-Upgrade "1";
    APT::Periodic::Verbose "0";
EOF
    
}

function update_env {
    # Update & Upgrade & Dist Upgrade
    apt-fast update && apt-fast upgrade -y && apt-fast dist-upgrade -y
}



cd /root || exit 1

if [ ! -f "${PWD}"/has-first-boot.marker ]
then
    initialize_env
    touch "${PWD}"/has-first-boot.marker
else
    echo "First boot-script already executed. Run updates..."
    update_env
fi
