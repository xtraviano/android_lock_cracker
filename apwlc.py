#!/usr/bin/env python

import os
import sys
import time
import multiprocessing
import hashlib
import itertools

PIN_MAX = 4
PASSWD_MAX = 4
FOUND = multiprocessing.Event()

def lookup(params):
    global FOUND
    lenhash = params[0]
    target = params[1]
    salt = params[2]
    positions = params[3]

    if FOUND.is_set() is True:
        return None

    perms = itertools.permutations(positions, lenhash)
    for item in perms:
        if FOUND.is_set() is True:
            return None
        p = None
        if "".join(str(v) for v in item) == "1234":
            p = 1
        passwd = "".join(str(v) for v in item)
        salted = passwd + salt
        sha1 = hashlib.sha1(salted).hexdigest()
        md5 = hashlib.md5(salted).hexdigest()
        digest = sha1 + md5
        if digest == target or digest.upper() == target:
            FOUND.set()
            return passwd
    return None

def crack(target_hash, salt):
    ncores = multiprocessing.cpu_count()

    # First try pin
    positions = list("0123456789")#abcdefghigklmnopqrstuvwxyzABCDEFGHIGKLMNOPQRSTUVWXYZ")
    pool = multiprocessing.Pool(ncores)
    params = []
    count = 1
    for i in range(0, PIN_MAX):
        params.append([count, target_hash, salt, positions])
        count += 1

    result = pool.map(lookup, params)
    pool.close()
    pool.join()

    ret = None
    for r in result:
        if r is not None:
            ret = r
            break
    if ret:
        return ret

    # Then try passwd
    positions = list("0123456789abcdefghigklmnopqrstuvwxyzABCDEFGHIGKLMNOPQRSTUVWXYZ")
    pool = multiprocessing.Pool(ncores)
    params = []
    count = 1
    for i in range(0, PASSWD_MAX):
        params.append([count, target_hash, salt, positions])
        count += 1

    result = pool.map(lookup, params)
    pool.close()
    pool.join()

    ret = None
    for r in result:
        if r is not None:
            ret = r
            break
    return ret

def main():
    print ""
    print "#################################"
    print "# Android Password Lock Cracker #"
    print "#            v0.1               #"
    print "# ----------------------------- #"
    print "#       Written by NTiger       #"
    print "#################################"
    print ""

    # Check parameters
    if len(sys.argv) != 3:
        print "[+] Usage: %s /path/to/password.key" % sys.argv[0]
        sys.exit(0)

    # Check password.key file
    if not os.path.isfile(sys.argv[1]):
        print "[+] Cannot access to %s file" % sys.argv[1]
        sys.exit(0)

    # Load digest from file
    hashLen = hashlib.sha1().digest_size + hashlib.md5().digest_size
    f = open(sys.argv[1], "rb")
    digest = f.read(hashLen * 2)
    f.close()

    # Check hash length
    if len(digest) != hashLen * 2:
        print "[+] Invalid passwd file?"
        sys.exit(0)

    # Get salt
    salt1 = hex(int(sys.argv[2]) & 0xffffffff)
    salt2 = hex(int(sys.argv[2]) >> 32 & 0xffffffff)
    salt = salt2[2:] + salt1[2:]

    # Try to crack the passwd
    t0 = time.time()
    passwd = crack(digest, salt)
    t1 = time.time()

    if passwd is None:
        print "[:(] The password was not found..."
    else:
        print "[:)] The password has been FOUND!! => %s" % passwd
    print "It took: %.4f seconds" % (t1 - t0)

    sys.exit(0)

if __name__ == "__main__":
    main()
