#!/usr/bin/env python

import os, sys, fcntl, json, tempfile, select

def decrypt(key,  data):
    cstate = [0x48,  0x74,  0x65,  0x6D,  0x70,  0x39,  0x39,  0x65]
    shuffle = [2, 4, 0, 7, 1, 6, 5, 3]
    
    phase1 = [0] * 8
    for i, o in enumerate(shuffle):
        phase1[o] = data[i]
    
    phase2 = [0] * 8
    for i in range(8):
        phase2[i] = phase1[i] ^ key[i]
    
    phase3 = [0] * 8
    for i in range(8):
        phase3[i] = ( (phase2[i] >> 3) | (phase2[ (i-1+8)%8 ] << 5) ) & 0xff
    
    ctmp = [0] * 8
    for i in range(8):
        ctmp[i] = ( (cstate[i] >> 4) | (cstate[i]<<4) ) & 0xff
    
    out = [0] * 8
    for i in range(8):
        out[i] = (0x100 + phase3[i] - ctmp[i]) & 0xff
    
    return out

def hd(d):
    return " ".join("%02X" % e for e in d)

if __name__ == "__main__":
    # Key retrieved from /dev/random, guaranteed to be random ;)
    key = [0xc4, 0xc6, 0xc0, 0x92, 0x40, 0x23, 0xdc, 0x96]
   
    if len(sys.argv) < 3: 
        print("Usage: {} </dev/hidraw0> <result.json>".format(sys.argv[0]))
        sys.exit(1)
    fp = open(sys.argv[1], "a+b",  0)
    jsonfile = sys.argv[2]
    
    HIDIOCSFEATURE_9 = 0xC0094806
    set_report = "\x00" + "".join(chr(e) for e in key)
    fcntl.ioctl(fp, HIDIOCSFEATURE_9, set_report)
    
    values = {}
    
    jdata = {}

    jdata['seq'] = 0
    dirty = False

    update_delay = .5

    while True:
        r, w, e = select.select([ fp ], [], [], update_delay)
        if not r and dirty:
            dirty = False
            jdata['seq'] += 1
            with tempfile.NamedTemporaryFile('w', delete=False) as outfile:
                json.dump(jdata, outfile)
                os.chmod(outfile.name, 0644)
                os.rename(outfile.name, jsonfile)
            continue
        data = list(ord(e) for e in fp.read(8))
        decrypted = decrypt(key, data)
        if decrypted[4] != 0x0d or (sum(decrypted[:3]) & 0xff) != decrypted[3]:
            print hd(data), " => ", hd(decrypted),  "Checksum error"
        else:
            op = decrypted[0]
            val = decrypted[1] << 8 | decrypted[2]
            
            values[op] = val
            
            # Output all data, mark just received value with asterisk
            #print ", ".join( "%s%02X: %04X %5i" % ([" ", "*"][op==k], k, v, v) for (k, v) in sorted(values.items())), "  ", 
            ## From http://co2meters.com/Documentation/AppNotes/AN146-RAD-0401-serial-communication.pdf
            if 0x50 in values:
                jdata['co2'] = values[0x50]
                dirty = True
            if 0x42 in values:
                jdata['temp'] = values[0x42]/16.0-273.15
                dirty = True
            if 0x44 in values:
                jdata['rh'] = values[0x44]/100.0
                dirty = True


