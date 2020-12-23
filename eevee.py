#!/usr/bin/python3

#
# eevee.py
#
# Interface for the register controller of the eevee
#
# You can include this, and then write python that uses it
#
import os
import sys
import socket
import select
import random
import struct

# Struct incantations for 
eevee_packet_format = "!I I I"
eevee_transaction_format = "!H H"
eevee_register_format = "I I"

eevee_packet = struct.Struct(eevee_packet_format)
eevee_transaction = struct.Struct(eevee_transaction_format)
eevee_register = struct.Struct(eevee_register_format)

#
# This imports the registers, control directives, magic, and port from the header files
# into the python global namespace.
# You can then refer to these just as you would in C
#
headersLoaded = False
    
def loadHeaders():
    global headersLoaded
    
    # Search an environment variable for EEVEE_SRC_PATH
    mungypath = os.environ.get('EEVEE_SRC_PATH')
    if mungypath is None:
        mungypath = "./"
        
    path = os.path.abspath(mungypath)

    if not os.path.exists(path):
        print("Error: Could not find %s." % path)
        exit(2)

    # I don't feel like learning a language (pyparsing grammars) to parse one language (C preprocessor) into a different language (python)
    # So lets just do it manually
    evaluations = []

    # Load the register map
    try:
        registers = open(path + "/eevee_regmap.h")
    except Exception as e:
        print("Could not open eevee_regmap.h", e, file=sys.stderr)
        raise
    
    for n,line in enumerate(registers):
        words = line.strip().split()

        try:
            # Note that 0 given as parameter to int() turns on C-like base intuiting
            if words and words[0] == "#define" and str.isidentifier(words[1]):
                globals()[words[1]] = int(words[2], 0)
        except IndexError as e:
            # Silently skip bad lines
            pass
            
    registers.close()

    # Load the control map and protocol definition
    try:
        commands = open(path + "/eevee_control.h")
    except Exception as e:
        print("Could not open eevee_control.h", e, file=sys.stderr)
        raise
    
    for n,line in enumerate(commands):
        words = line.strip().split()

        try:
            if words and words[0] == "#define" and str.isidentifier(words[1]):
                globals()[words[1]] = int(words[2], 0)                
        except Exception as e:
            pass

    commands.close()

    headersLoaded = True
    
# Subclass Exception, because we are exceptional. Heh.
class EEVEEException(Exception):
    pass


# Discover the EEVEE boards on a subnet
def discover(broadcast, version="cafe0003", timeout=0.2):

    if not headersLoaded:
        loadHeaders()

    # Broadcast a null version string, so that everyone complains with their own
    # version string
    #
    # Note that SO_REUSEADDR is not needed
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    # Set a timeout, so we don't recvfrom() indefinitely
    s.settimeout(timeout)

    # Broadcast the request
    # Maximally transparent request
    s.sendto(eevee_packet.pack(EEVEE_MAGIC_COOKIE, 0, 0xffffffff),
             (broadcast, int(EEVEE_SERVER_PORT)))
    
    # Handle responses    
    print("Discovery sent.  Collecting responses...")
    responses = []
    try:
        while True:
            # Argument is presumably the timeout?
            resp = s.recvfrom(11)
            what,where = resp
            print(where)
            responses.append(resp)
    except socket.timeout as e:
        print("Done.")

    print("Filtering for version %s and registering boards..." % version)
    boards = []
    for what, where in responses:
        bver = what[4:8]
        if not bver == bytes.fromhex(version):
            print("Dropping %s with version %s" % (where[0], bver))

        try:
            boards.append(board(where[0]))
        except EEVEEException as e:
            print("A board at %s with version %s exists, but subsequent communication seems broken?" % (where[0], bver), e, file=sys.stderr) 

    print("Final board list:")
    for b in boards:
        # Stored in big endian, MAC address is the bottom 6 bytes
        print(b.dna[2:].hex())
        
    return boards

#
# A protocol v2 payload
#
# The user doesn't usually interact at this level, unless
# they are writing a new type of payload (i.e. not a register
# transaction)
#
class eevee_op(object):

    ##
    ## Factory methods
    ##

    # The natural way to do register maps is with dictionaries.
    #
    # For example:
    #  { INTERNAL_OFFSET | x : 0x0 for x in ( REG_INTERNAL_VERSION, REG_INTERNAL_EFUSE, REG_INTERNAL_SCRATCH) }
    # 
    #
    
    # Create a register payload
    def makeRegisterWrite(regDict, flags=0x0):
        tmp = eevee_op(EEVEE_OP_REGISTER & (EEVEE_WRITE | flags))

        for key,value in regDict.items():
            # Perform the explicit cast
            tmp.data.extend(eevee_register.pack(key, value + (1<<32) if value < 0 else value))
            
        return tmp

    def makeRegisterRead(regDict, flags=0x0):
        tmp = eevee_op(EEVEE_OP_REGISTER & (EEVEE_READ | flags))

        for key, value in regDict.items():
            # Perform the explicit cast
            tmp.data.extend(eevee_register.pack(key, value + (1<<32) if value < 0 else value))

        return tmp

    #
    # Return a dictionary based on a transaction payload, assuming it is
    # a register transaction
    #
    def bytesToRegDict(pairsinbytes):
        tmp = {}

        for k in range(0, int(len(pairsinbytes) / (2*EEVEE_WIDTH_REGISTER))):
            offset = k*2*EEVEE_WIDTH_REGISTER
            addr, word = eevee_register.unpack(pairsinbytes[offset:offset+8])
            tmp[addr] = word
            
        return tmp
        
    def __init__(self, op, payload=None):

        # Sanity check the parameters
        if not isinstance(op, int):
            raise TypeError("Operation must be a %d-byte wide integer" % EEVEE_WIDTH_OP)
        
        # Define the operation    
        self.op = op

        # Make a new bytearray()
        self.data = bytearray()

        if isinstance(payload, bytes) or isinstance(payload, bytearray):
            self.data.extend(payload)
            
            if (op & EEVEE_OP_REGISTER > 0) and not (op & EEVEE_OP_MASK_OTHER):
                # Its a register operation, sanity check the width
                if (len(self.data) % EEVEE_WIDTH_REGISTER*2) > 0:
                    raise ValueError("Register operation payloads must come in integer numbers of addr:word pairs")
                elif not (op & EEVEE_OP_REGISTER > 0) and (op & EEVEE_OP_MASK_OTHER):
                    # Its some other operation
                    pass
            else:
                # Its either a double specification, or its empty!
                raise EEVEEException("Invalid operator specifier")
        elif not payload is None:
            raise TypeError("Payloads, if given, must be type bytes or bytearray")

                
class board(object):

    def __init__(self, machine, port=None, udpsport=None, anonymous=False):

        # Try to load the headers
        if not headersLoaded:
            loadHeaders()
            
        # Set the machine
        self.dest = None

        # We now have a list of payloads that are supposed to be shipped
        self.transactions = list()
            
        # Try to resolve the name
        try:
            self.dest = socket.gethostbyname(machine)
        except Exception as e:
            print("TROUBLE: could not resolve %s" % machine, e)
            raise
        
        # Try to set up a socket
        try:
            self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            # If we want to use a persistent source port (e.g. for netcat tunnels)
            # do it here.
            if isinstance(udpsport, int):
                self.s.bind(('0.0.0.0', udpsport))

            if port is None:
                port = EEVEE_SERVER_PORT
            elif not isinstance(port, int):
                raise Exception("Given port is not an integer")
            
            self.s.connect((self.dest, port))
        except Exception as e:
            print("TROUBLE: could not grab a datagram socket", e)
            raise

        # pdb.set_trace()
        
        # Give a delay
        self.delay = 0.0
        
        # Retrieve the device DNA so we know what board we are looking at
        if not anonymous:
            self.dna = bytearray()

            # Switched endianness here...
            self.dna.extend(self.peeknow(INTERNAL_OFFSET | REG_INTERNAL_DNA_HIGH).to_bytes(4, 'big'))
            self.dna.extend(self.peeknow(INTERNAL_OFFSET | REG_INTERNAL_DNA_LOW).to_bytes(4, 'big'))

    #
    # peek() push register reads into the pending transaction
    #
    def peek(self, arg1):

        # Add the outgoing bytes
        if not isinstance(arg1, dict):
            arg1 = { arg1 : 0x0 }

        # Make it
        self.transactions.append(eevee_op.makeRegisterRead(arg1))
    #
    # poke() push register writes into the pending transaction
    #
    def poke(self, arg1, arg2=None, silent=False, readback=True):

        flags = 0x0
        if silent:
            flags |= EEVEE_OP_MASK_SILENT
        if not readback:
            flags |= EEVEE_OP_MASK_NOREADBACK

        # Add the outgoing bytes
        if not isinstance(arg1, dict):
            arg1 = { arg1 : arg2 }

        self.transactions.append(eevee_op.makeRegisterWrite(arg1, flags=flags))
        
    #
    # pokenow() do a one off register write
    # 
    def pokenow(self, addr, word, silent=False, readback=True):

        # pdb.set_trace()

        # Save the current transaction pile
        tmp = self.transactions

        # Make a new one
        self.transactions = []
        self.poke(addr, word, silent, readback)
        result = self.transact()

        # Restore the previous transaction pile
        self.transactions = tmp

        # Return what came back
        if silent:
            return
        else:
            return result[0].data[addr]

    #
    # peeknow() do a one off register read
    #
    def peeknow(self, addr):

        # Save the current transaction pile
        tmp = self.transactions

        # Make a new one
        self.transactions = []
        self.peek(addr)
        result = self.transact()

        # Restore the previous transaction pile
        self.transactions = tmp

        # pdb.set_trace()
        
        # Return what came back
        return result[0].data[addr]

    #
    # transact() tries to flush the request queue and return a tuple
    #
    def transact(self):

        # Are we associated to a card yet?
        if self.dest is None:
            error = EEVEEException("Not yet pointed to a target board")
            error.board = self
            raise error

        # Are there any pending transactions?
        if len(self.transactions) == 0:
            raise EEVEEException("There are no pending transactions.")
        
        # Note that we cannot use the "with" construct here, as it always garbage
        # collects theconnection, and we want a persistent one
        frame = bytearray()

        # Make the header
        random.seed()
        msgid = random.randrange(0, 1 << 8*EEVEE_WIDTH_SEQNUM)
        version = (EEVEE_VERSION_HARD << 16) | EEVEE_VERSION_SOFT
        frame.extend(eevee_packet.pack(EEVEE_MAGIC_COOKIE,
                                       version,
                                       msgid))
        
        # Data.  Load it all up
        response = 0

        for action in self.transactions:
            frame.extend(eevee_transaction.pack(action.op, len(action.data)))
            frame.extend(action.data)
            
            # Keep track if we expect a response...
            if not (action.op & EEVEE_OP_MASK_SILENT):
                response += 1

            
        # If we exceed maximum length, clear the request and except
        if len(frame) > EEVEE_MAX_PAYLOAD:
            error = EEVEEException("Length (%d) of assembled outgoing EEVEE frame exceeds header-defined maximum (%d).  Discarded." % (len(frame), EEVEE_MAX_PAYLOAD))
            error.board = self
            raise error

        # First, we've not sent anything yet.
        # Make sure to pull off anything stale sitting in the UDP port buffer
        # This can occur if a previous command was timing out, but finally returned
        # right before *we* timed out.
        garbage = True
        while garbage:
            # See if we have an entire packet immediately on the buffer
            # (zero timeout is a poll in python, see the docs)
            ready = select.select([self.s], [], [], 0)
            if not ready[0]:
                garbage = False
            else:
                # Pop a packet off
                data, addr = self.s.recvfrom(1 << 16)

        # Port buffer should be empty now
        
        # Attempt to push this through
        attempts = 3        
        while attempts > 0:
            
            # Transmit
            self.s.sendall(frame)

            # If we're not expecting any responses, don't wait for them
            # but still return an iterable type
            if response == 0:
                # Clear the transactions
                self.transactions = []

                # Return an iterable
                return list()
            
            # Otherwise wait for the response
            # This is UDP, so we are actually waiting for an entire
            # response datagram.  So once we can read, we read the maxiumum
            # IP datagram: 1 << 16, even though the eevee boards will never
            # send more than max ethernet frame.
            ready = select.select([self.s], [], [], self.delay + 0.2)

            if ready[0]:
                # We attempt to read magic, version, and message id
                data, addr = self.s.recvfrom(1 << 16)

                # Verify that addr came from what we expected...
                if not addr[0] == self.dest:
                    raise EEVEEException("Expected response from %s, but received response from %s" % (self.dest, addr))
                
                # Verify that the message has the correct magic
                cookie, echover, echoid = eevee_packet.unpack(data[0:12])
                
                # (note that we undo network byte ordering by just reading it backwards)
                if not cookie == EEVEE_MAGIC_COOKIE:
                    raise EEVEEException("Received magic %s that was not in eevee protocol" % cookie.hex())

                # Verify that the message has the correct version
                if not echover == version:
                    raise EEVEEException("Expecting version %s, received %s" % (version.hex(), echover.hex()))
                
                # If the message has the incorrect ID, but looks like valid everything else
                # it can't be stale stuff, since we cleared the OS buffer before
                # sending our request....
                if not echoid == msgid + 1:
                    raise EEVEEException("Received msgid %d, expecting msgid %d.  Corrupt?" % (echoid, msgid+1))

                # Leave the while loop
                break
            else:
                # Didn't get a response.  Try again.
                attempts -= 1
                print("Response timed out... Trying %d more times." % attempts, file=sys.stderr)
                continue

        # If we timed out, raise an exception
        if attempts == 0:
            raise EEVEEException("Responsed timed out repeatedly, giving up")
        
        # Throw away the header, so we can relative index
        data = data[12:]
        
        # We know the number of payloads to expect, since this is a response to
        # something we did.
        for n in range(0, len(self.transactions)):

            # If this payload was supposed to be silent, continue
            if self.transactions[n].op & EEVEE_OP_MASK_SILENT > 0:
                continue

            op, width = eevee_transaction.unpack(data[:4])

            # Verify message operation integrity
            if not self.transactions[n].op == op:
                raise EEVEEException("Received unexpected operation %s instead of %s" % (op.hex(), transaction[n].op.hex()))

            # Verify message width integrtiy
            if not len(self.transactions[n].data) == width:
                raise EEVEEException("Received a payload width %d not in agreement with expectation %d" % (width, len(transaction[n].data)))

            # Did this operation fail?  If so, append its index to the failures list
            if op & EEVEE_OP_MASK_FAILURE > 0:
                self.failures.append(n)

            # Index to the payload
            data = data[4:]

            # If its a register operation, process it as such
            if op & EEVEE_OP_REGISTER > 0:

                # Make sure the width makes sense
                if width % (EEVEE_WIDTH_REGISTER*2) > 0:
                    raise EEVEEException("Width of register operation list %d did not divide correctly" % width)

                # Overwrite the transaction list entries with dictionaries, instead of bytes
                self.transactions[n].data = eevee_op.bytesToRegDict(data[:width])

                # Reindex
                data = data[width:]
                
            else:
                # Not yet implemented
                pass

        # Stash a copy of the transactions
        tmp = self.transactions.copy()

        # Clear the transactions internally
        self.clearTransactions()
        
        return tmp

    #
    # Clear pending transactions or the response
    #
    def clearTransactions(self):
        self.transactions = []
        
    #############################
    #
    # Useful userspace functions
    #
    #############################

    #
    # aimNBIC(): aim the NBIC
    #   Takes a (hostname, port) tuple (consistent with the other python socket stuff)
    #
    def aimNBIC(self, host=None, port=None):

        # See if we should act reflexively
        if host is None:
            ipaddr = self.s.getsockname()
            ipaddr = socket.inet_aton(ipaddr[0])
        else:
            ipaddr = socket.inet_aton(socket.gethostbyname(host))

        # Can't define this in the declaration because these
        # variables aren't in the namespace until loadHeaders() is called
        if port is None:
            port = EEVEE_NBIC_PORT
        
        #
        ## ENDIANNESS AHEAD
        #
        # To make it faster for hardware to build frames
        # we store these things in network order, so they can just be
        # repeatedly blasted, without twiddling.
        #
        # XXX wtf was that +1 doing there?
        nbicports = (port << 16) | port
        self.pokenow(NBIC_OFFSET | REG_NBIC_PORTS, nbicports)

        # Even though ipaddr is a bigendian byte string
        # It needs to be written to the register as a big endian byte string
        # So its network order is actually little endian.  endianness sucks.
        self.pokenow(NBIC_OFFSET | REG_NBIC_DESTIP, int.from_bytes(ipaddr, byteorder='big'))
        
