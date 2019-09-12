#!/usr/bin/python3

import sys
import eevee
import socket
import argparse
from random import randint

# Adapted from boilerplate code from the docs 
parser = argparse.ArgumentParser(description='Exercise the EEVEE system')
parser.add_argument('-b',
                    dest='broadcast',
                    help='flag that the given address is a broadcast and attempt to discover boards',
                    action='store_true')
parser.add_argument('-p',
                    dest='udpsport',
                    metavar='udp source port',
                    default=None,
                    type=int,
                    help='explicitly specify the originating UDP port (e.g. useful for netcat/ssh tunnels)')
parser.add_argument('ip',
                    help='IP address of a specific board or subnet broadcast')

args = parser.parse_args()

# A place holder
boards = None

# Get some boards
if args.broadcast:
    if not args.udpsport is None:
        print("Broadcast, in general, will find multiple boards.  It is unwise to control multiple boards from the same socket.  Quitting.")
        exit(1)

    # Otherwise, find the boards
    boards = eevee.discover(args.ip)
else:
    boards = [eevee.board(args.ip, udpsport=args.udpsport)]
        
print("")
print("EEVEE Evolvable Embedded Vehicle for Execution and Egress:  Python 3 test stub")
print("----------------------------------")

for myboard in boards:
    print("Connected to board: %s @ %s\n-------------------------" % (myboard.dna.hex(), myboard.dest))

    # Try to point it to google
    myboard.aimNBIC(socket.gethostbyname("google.com"))
    
    # It should be pointing to the gateway
    maclow = myboard.peeknow(eevee.NBIC_OFFSET | eevee.REG_NBIC_DESTMAC_LOW)
    machigh = myboard.peeknow(eevee.NBIC_OFFSET | eevee.REG_NBIC_DESTMAC_HIGH)

    print("Board %s NBIC target MAC low: %s, high: %s" % (myboard.dna.hex(), hex(maclow), hex(machigh)))

    input()

    # Debug, so set a delay (1hr ;))
    myboard.delay = 3600

    # Run a register write (with readback, as its the default)
    print(myboard.pokenow(eevee.INTERNAL_OFFSET | eevee.REG_INTERNAL_SCRATCH, 128))
    
    # Run a register write without readback
    print(myboard.pokenow(eevee.INTERNAL_OFFSET | eevee.REG_INTERNAL_SCRATCH, 256, readback=False))

    
                    
print("\nOkay, now try pointing the boards at each other.  This should mac resolve individuals.")
# Multiboard shenanegains
N = len(boards)
if N > 1:

    for i in range(0,N):
        success = False
        while not success:
            try:  
                boards[i].aimNBIC(boards[(i + 1) % N].dest)
                success = True
            except Exception:
                print("Board %s failed to aim at board %s" % (boards[i].dna, boards[(i + 1) % N].dna))

    # Verify that they are pointing at each other
    for i in range(0,N):
        maclow = boards[i].peeknow(eevee.NBIC_OFFSET | eevee.REG_NBIC_DESTMAC_LOW)
        machigh = boards[i].peeknow(eevee.NBIC_OFFSET | eevee.REG_NBIC_DESTMAC_HIGH)

        print("Board %s NBIC target MAC low: %s, high: %s" % (boards[i].dna.hex(), hex(maclow), hex(machigh)))
