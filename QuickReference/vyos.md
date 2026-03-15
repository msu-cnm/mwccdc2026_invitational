# *Let the router route, firewalls firewall*

**FIRST 5 MINUTES**

```
# Backup router config
show configuration > /config/config.backup

# Verify interfaces
show interfaces

# Verify routing
show ip route

# Verify connectivity to next hop
ping <gateway>

# Check arp
show arp
```

## IP Table
| Name               | IP             | Public IP        |
| ------------------ | -------------- | ---------------- |
| Ubuntu Ecom        | 172.20.242.30  | 172.25.2{t#}.11  |
| Fedora Webmail     | 172.20.242.40  | 172.25.2{t#}.39  |
| Splunk             | 172.20.242.20  | 172.25.2{t#}.9   |
| Ubuntu Wks         | dhcp           | dynamic          |
| Server 2019 AD/DNS | 172.20.240.102 | 172.25.2{t#}.155 |
| Server 2019 Web    | 172.20.240.101 | 172.25.2{t#}.140 |
| Server 2022 FTP    | 172.20.240.104 | 172.25.2{t#}.162 |
| Windows 11 Wks     | 172.20.240.100 | 172.25.2{t#}.144 |


## Static Routes (if needed)
> Layer-3 routing only
> Public IPs NAT'd by firewalls using two /25 static routes

### Default Route (Upstream)
```bash
configure
set protocols static route 0.0.0.0/0 next-hop 172.31.2{t#}.1
```

### Internal Networks via PA1 (eth1)
```bash
set protocols static route 172.20.242.0/24 next-hop 172.16.101.254
set protocols static route 172.25.2{t#}.0/25 next-hop 172.16.101.254
```

### Internal Networks via PA2 (eth2)
```bash
set protocols static route 172.20.240.0/24 next-hop 172.16.102.254
set protocols static route 172.25.2{t#}.128/25 next-hop 172.16.102.254
```

### If route was missing, commit
```bash
commit
save
exit
```

