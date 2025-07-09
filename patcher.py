#!/usr/bin/env python3
import argparse
import re

def patch_gamespy(input):
    search_pattern = b"gamespy.com"
    write_pattern = b"openspy.net"
    pattern = re.compile(search_pattern)
    matches = pattern.findall(input)
    if len(matches) == 0:
        print("[X] Unable to find gamespy.com")
    print(f"[+] Patching {len(matches)} gamespy.com matches")
    output = pattern.sub(write_pattern,input)
    return output

def patch_public_key(input):
    search_pattern = b"BF05D63E93751AD4A59A4A7389CF0BE8A22CCDEEA1E7F12C062D6E194472EFDA5184CCECEB4FBADF5EB1D7ABFE91181453972AA971F624AF9BA8F0F82E2869FB7D44BDE8D56EE50977898F3FEE75869622C4981F07506248BD3D092E8EA05C12B2FA37881176084C8F8B8756C4722CDC57D2AD28ACD3AD85934FB48D6B2D2027"
    write_pattern = b"afb5818995b3708d0656a5bdd20760aee76537907625f6d23f40bf17029e56808d36966c0804e1d797e310fedd8c06e6c4121d963863d765811fc9baeb2315c9a6eaeb125fad694d9ea4d4a928f223d9f4514533f18a5432dd0435c5c6ac8e276cf29489cb5ac880f16b0d7832ee927d4e27d622d6a450cd1560d7fa882c6c13"
    pattern = re.compile(search_pattern)
    matches = pattern.findall(input)
    if len(matches) == 0:
        print("[X] Unable to find public key")
    print(f"[+] Patching {len(matches)} public key matches")
    output = pattern.sub(write_pattern,input)
    return output

def patch_auth_service(input):
    search_pattern = b"https://%s.auth.pubsvs.openspy.net/AuthService/AuthService.asmx"
    write_pattern = b"http://%s.auth.pubsvs.openspy.net/AuthService/AuthService.asmx\0"
    pattern = re.compile(search_pattern)
    matches = pattern.findall(input)
    if len(matches) == 0:
        print("[X] Unable to find auth service")
    print(f"[+] Patching {len(matches)} auth service matches")
    output = pattern.sub(write_pattern,input)
    return output

def patch(target, inline, outfile):
    print(f"[+] Patching {target}")
    try:
        fp = open(target, "rb")
    except Exception as e:
        print(f"Unable to open {target}: {e}")

    binary = fp.read()

    fp.close()

    print(f"[i] {target} size is {len(binary)}")

    print("[+] Patching gamespy.com to openspy.net")
    binary = patch_gamespy(binary)

    print("[+] Patching Public Key")
    binary = patch_public_key(binary)

    print("[+] Patching Auth Service")
    binary = patch_auth_service(binary)



    if inline:
        output = open(target,"wb")
    else:
        if outfile:
            output = open(outfile, "wb")
        else:
            output = open((target + ".patched"), "wb")

    print(f"[+] Writing output to {output.name}")

    output.write(binary)

    print("[+] Complete")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
            prog="Openspy Patcher",
            description="Easy patcher utility to add openspy compatability to binaries")
    parser.add_argument("filename")
    parser.add_argument("-i","--inline",help="Patch binary inline (modifies original file)", default=False, action='store_true')
    parser.add_argument("-o","--output",help="What filename to write the output to")
    args = parser.parse_args()
    patch(args.filename,args.inline, args.output)
