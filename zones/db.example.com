$TTL 300
$ORIGIN example.com.
@   IN SOA ns1.example.com. hostmaster.example.com. (2025110601 3600 900 1209600 300)
    IN NS ns1.example.com.
ns1 IN A 10.0.0.53
@   IN MX 10 mail.example.com.
mail IN A 10.0.0.25
@   IN TXT "v=spf1 ip4:10.0.0.25/32 -all"
_dmarc IN TXT "v=DMARC1; p=quarantine; rua=mailto:postmaster@example.com; ruf=mailto:postmaster@example.com; pct=100"
