# Firewall DSL Syntax Reference
## Team Members
Pablo García López: pablo.glopez@udc.es
David Javier Montes Fernández: david.j.montes@udc.es
## Overview
This firewall DSL (Domain Specific Language) allows you to write firewall rules in a natural, human-readable format that gets compiled into iptables commands.

---

## Basic Structure

- `firewall.l`
- `firewall.y`
- `Makefile`

### Rule Format (Two Variants)

**Variant 1: From-To First**

`<action> from <source> to <destination> [proto <protocol>] [port <port>] [when state <state>]`


**Variant 2: Protocol First**
`<action> [proto <protocol>] [port <port>] from <source> to <destination> [when state <state>]`


**Simple Format:**
`<action> from <source>`


---

## Actions

| Keyword | Description | iptables Equivalent |
|---------|-------------|---------------------|
| `allow` | Accept the packet | `-j ACCEPT` |
| `accept` | Accept the packet | `-j ACCEPT` |
| `drop` | Silently drop the packet | `-j DROP` |
| `block` | Silently drop the packet | `-j DROP` |
| `deny` | Silently drop the packet | `-j DROP` |
| `reject` | Drop and send rejection | `-j REJECT` |

---

## Source and Destination

| Syntax | Description | Example |
|--------|-------------|---------|
| `any` | Match any address | `from any` |
| `all` | Match any address | `from all` |
| `IP_ADDRESS` | Single IP | `from 192.168.1.1` |
| `IP/CIDR` | Network range | `from 192.168.1.0/24` |
| `default` | Set default policy | `drop from default` |
| `INTERFACE` | Network interface | `from eth0` |

---

## Protocols

`proto <protocol_name>`


**Supported protocols:**
- `tcp` - TCP protocol
- `udp` - UDP protocol  
- `icmp` - ICMP protocol
- Any valid protocol name from `/etc/protocols`

**Examples:**
`
proto tcp
proto udp
proto icmp
`

---

## Port Specifications

### Single Port
`
port <number>
`
**Example:** `port 22` → `--dport 22`

### Port Range
`
port <start>-<end>
`
**Example:** `port 8000-8080` → `--dport 8000:8080`

### Multiple Ports (Comma-separated)
`
port <port1>,<port2>
`
**Example:** `port 80,443` → `-m multiport --dports 80,443`

### Source Port
`
sport <number>
`
**Example:** `sport 1024` → `--sport 1024`

**Note:** Port specifications require a protocol (tcp/udp). ICMP does not support ports.

---

## Connection States

`
when state <STATE>
`

**Valid states:**
- `NEW` - New connection
- `ESTABLISHED` - Established connection
- `RELATED` - Related to existing connection
- `INVALID` - Invalid packet

**Example:**
`
accept from any to any when state ESTABLISHED
`
Generates: `-m state --state ESTABLISHED`

---

## Default Policy

Set the default policy for the firewall:

`
drop from default
accept from default
`

**Examples:**
- `drop from default` → `iptables -P INPUT DROP`
- `accept from default` → `iptables -P INPUT ACCEPT`

---

## Comments

Two styles of comments are supported:
```bash
# Shell-style comment
// C-style comment
```

Both styles extend to the end of the line.

---

## Complete Examples

### 1. Allow SSH from Local Network
`
allow from 192.168.1.0/24 to any proto tcp port 22
`

### 2. Allow Web Traffic
`
allow proto tcp port 80 from any to any
allow proto tcp port 443 from any to any
`

### 3. Allow Established Connections
`
accept from any to any when state ESTABLISHED
`

### 4. Block Specific IP
`
block from 10.0.0.50 to any
`

### 5. Allow Port Range
`
allow from any to any proto tcp port 8000-8080
`

### 6. Allow Multiple Ports
`
allow proto tcp port 80,443 from any to any
`

### 7. Set Default Policy
`
drop from default
`

---

## Full Example File

### Allow SSH from management network
`allow from 192.168.100.0/24 to any proto tcp port 22
`
### Allow established connections
`
accept from any to any when state ESTABLISHED
`
### Allow HTTP and HTTPS

`allow proto tcp port 80 from any to any`
`allow proto tcp port 443 from any to any`
### Allow localhost
`allow from 127.0.0.1
`
### Block suspicious IP
`deny from 203.0.113.0/24
`
### Allow DNS
`
allow proto udp port 53 from any to any
`
### Drop everything else
`
drop from default
`

---

## Error Detection

The compiler will detect and report:

1. **Invalid port ranges** - Start port higher than end port
   `
   Error: Invalid port range 443-80 at line X
   `

2. **Invalid connection states** - Unrecognized state names
   `
   Error: Unrecognized connection state 'CONNECTED' at line X
   `

3. **Protocol conflicts** - ICMP used with port specifications
   `
   Error: Protocol ICMP is incompatible with port specification at line X
   `

4. **Syntax errors** - Malformed rules
   `
   Parse error: syntax error at line X
   `

---

## Usage

### Compile the DSL
`
make
`

### Generate iptables script
`
./firewall < myconfig.txt > firewall-rules.sh
`

### Check for errors
`
./firewall < myconfig.txt
`
If there are errors in rules, they will be displayed and those rules won't be generated.

### Apply the rules
`
chmod +x firewall-rules.sh
`
`
sudo ./firewall-rules.sh
`

### Verify active rules
`
sudo iptables -L -n -v
`

---

## Tips

1. Always set a default policy at the end of your configuration
2. Put more specific rules before general rules
3. Allow established connections early for better performance
4. Test your rules in a safe environment first
5. Keep localhost traffic allowed to prevent lockouts
6. Document your rules with comments
