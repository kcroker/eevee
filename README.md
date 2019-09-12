# EEVEE Embedded Server and Hardware Control
The Evolvable Embedded Vehicle for Execution of Experiments (EEVEE) is a portable and generic data acquisition (DAQ) platform for Xilinx-based boards using the NishiPHY Gigabit Ethernet soft (firmware) core.
This suite is developed at the University of Hawaii at Manoa, by the Nishimura Instrumentation Cohort.  
The server-side implements ARP, ICMP ping, IP, UDP, DHCP, and supports manual configuration by pinging at the desired address.
It also implements a very light-weight control protocol, documented in `eevee_os.h`.
The client-side provides a paired Python 3 library that speaks this protocol.

## Building the server ELF

We have confirmed successful ELF builds with Xilinx SDK that comes with the Spartan6 "appliance" and Vivado 2018.1.
When creating your SDK project, just link the files from your local git repository.
Your ISE or Vivado can export the appropriate "board support package" for your SDK project.
The following values for stack and heap are set by default in `platform_definition.h.`

Region | Size
--- | ---
Heap | 0x1000
Stack | 0x1000

They have been verified with the current version, through both can probably be trimmed.

### Technical notes
For ELF size, a number of simplifying design decisions have been made.
Ethernet jumbo frames are not supported.
The board will never send fragmented IP packets.
It also is not capable of reassembling fragmented IP packets and drops them.

## Configuration
Boards running this software support automatic network configuration and manual network configuration.
Note that the NishiPHY operates in promiscous mode, so the use of a dumb ethernet hub may result in severe packet loss at high congestion.

### Automatic configuration

1. Set up a DHCP server on the segment of your network to which you will connect boards.
2. Plug the board into your network and turn it on.

To find your board at the command line, you can just `ping` the broadcast address or dig into your DHCP server's documentation.
If you want to assign fixed IP addresses to your boards _a priori_, you can configure your DHCP server based on the boards' MAC addresses.
These addresses are determined from the lowest 48-bits of Xilinx Device DNA, in the order that Vivado displays the Device DNA.
Note that the least-significant bit of the most significant byte, in network order, is zeroed out.
This prevents the MAC address from looking like a broadcast address (and almost surely getting filtered by your switch)

### Manual configuration

If a board is unable to DHCP configure, it will automatically drop into "headless" mode.
An IP address can be assigned to a board in this mode by pinging the desired address.
1. The board _must be physically connected to the source of the ping_ in order for this to work, since it takes place using ARP.
2. If there are multiple boards, each board must be manually configured in this way before connecting another board to the network segment, or they will race.

Note that there is no way to manually assign a gateway.

For example, to assign IP address 10.0.6.56 to a board in "headless" mode just ping at the desired address

```bash
   $ ping 10.0.6.56
```

`ping` sends ICMP echo requests to the specified host.
This triggers an ARP lookup by *your* machine.
The board uses these ARP lookups to figure out it should become the specified host.
Note that this is non-standard usage of ARP!

#### Releasing a manually configured IP address (requires root)
If, for some reason, you want a board to forget the IP address you've given it (perhaps by accident), you can get
the board to detach by pretending to be a different machine with the same IP address.
For example, to disassociate a board with mac address 6a:27:d5:89:3d:01 in headless mode that has seized onto 10.0.6.90

```bash
   # /usr/sbin/arping -P -A 10.0.6.90 -S 10.0.6.90 -t 6a:27:d5:89:3d:01 -s 54:12:12:12:12:12 -c 1  
```

Thing | Meaning
--- | ---
`arping` | sends raw ARP packets (layer 2)
`-P` | says send an ARP Reply (as if someone asked who we were)
`-A` | does something I don't quite get, but its definitely necessary
`-S` | sets the source IP in the packet (we're making a packet that looks like it didn't come from ourselves)
`-t` | sets the target MAC address in the packet
`-s` | sets the source MAC address in the packet
`-c 1` |  says only send out one of them

The board watches for anyone else telling it that its IP address is already taken.
When it first seizes the address, it sends a Request for the address.
You can send a fake response at any later time to get it to "release" the address.
The board will remember (up to arp cache depth, usually 10) that this one was off limits and not seize it again.

# Using the Python 3 client library
`eevee.py` should be imported as a library

```python
import eevee
```

Before running any library code, you may export a path to the files `eevee_regmap.h` and `eevee_control.h`.

```bash
export EEVEE_SRC_PATH=/home/boardland/eevee
```

By default, the search path is the current working directory.
The defintions, given in `eevee_control.h` and `eevee_regmap.h` are automatically imported into the `eevee` namespace.
This should allow your existing code to keep working seamlessly, even if the underlying protocol format changes.
For example

```python
addr = eevee.EEVEE_WRITE | eevee.EEVEE_OP_MASK_NOREADBACK
```

In future versions, the `EEVEE_` prefix will probably be automatically stripped from the python for simplicity (since its natural to already say `eevee.PREFIX`).
Within your code, please never hardcode register addresses, masks, and offsets for the eevee hardware register maps.

Boards can be automatically found on the local subnet or directly assigned

```python
# Find them all
boards = eevee.discover('192.168.5.255')

# Manually make one
badboard = eevee.board('192.168.5.69')
```

You may optionally specify the originating UDP source port for the control socket

```python
# bind() to 8989 on the client side
singleboard = eevee.board('127.0.0.1', udpsport=8989)
```

This is necessary when using netcat+SSH to directly address a target board on a private subnetwork of a remote machine.
This procedure is [detailed below](Interfacing-with-a-remote-board-locally).

## Targetting the board
To obtain the highest possible speeds, the firmware uses a different hardware path for data output.
To control where this data is sent, you must aim the board

```python
# Aim at the computer executing the client-side Python, at the default data port 1338
board.aimNBIC()

# Target at hooli.com's HTTP port
board.aimNBIC("hooli.com", 80)
```

The board will automatically ARP resolve, so if you point it off of the local subnet, it will blast the default gateway provided by DHCP.
_If the board is in headless mode, the behaviour is undefined if you point it off of the local subnet._
See below for how to run a barebones packet catcher.

## Register transactions
The board embedded software supports high-efficiency register operations and may be readily extended to perform other non-register opertations.
Register interactions can be done transactionally for maximal efficiency, or you can one-off using the `pokenow()` and `peeknow()` commands.

Transactions use a single UDP packet to execute many operations at once.
The register operation is currently the only implemented operation, but in general transactions support a mixture of arbitrary operations.
The cleanest way to build register transactions is to use any Python dictionary type

```python
   regmap = {}
   regmap[eevee.INTERNAL_OFFSET | eevee.REG_INTERNAL_SCRATCH] = 0x89abcdef
   regmap[eevee.EEVEE_OFFSET | eevee.REG_EEVEE_SRCIP] = 0x0a0006fe
   board.poke(regmap)
```

If you need execution in a guaranteed order, use an ordered dictionary (since this is not the default behaviour prior to Python 3.7)

```python
   import collections
   regmap = collections.OrderedDict()
```

If you need to assign different values to the same register within one transaction, use multiple `poke()` commands

```python
   regmap = {}
   regmap[eevee.INTERNAL_OFFSET | eevee.REG_INTERNAL_SCRATCH] = 0x89abcdef
   regmap[eevee.EEVEE_OFFSET | eevee.REG_EEVEE_SRCIP] = 0x0a0006fe
   board.poke(regmap)

   # Now set scratch to something else
   board.poke(eevee.INTERNAL_OFFSET | eevee.REG_INTERNAL_SCRATCH, 0xf8f8aeae)

   # Execute the transaction
   response = board.transact()
```

Note that `poke(addr, word)` is also understood.
The same considerations apply to `peek()`.

### Delays
After initiating a transaction, the client will block and wait for a response.
Sometimes a particular transaction will require additional time.
The client side defaults to a 200ms timeout before retrying transmission of the transaction.
This can be overridden by setting an _additional_ `board.delay` in seconds as follows

```python
   # For an entire transaction
   board.delay = 1.5
   board.transact()
   board.delay = 0.0

   # For a single peek() operation
   board.delay = 0.25
   efuse = board.peeknow(eevee.INTERNAL_OFFSET | eevee.REG_INTERNAL_EFUSE)
   board.delay = 0.0
```

Leaving a large delay won't affect performance, as it only adjusts the timeout given to the socket's `select()` call.

### Disabling read-back
A register write, by default, is a write operation followed by a separate read operation.
This value is then returned to the client, and can be used to verify correct behaviour.
There are situations where a read-back is not supported in hardware, or not necessary.
In these situations, the read-back can be explicitly disabled

```python
   board.poke(eevee.INTERNAL_OFFSET | eevee.REG_INTERNAL_SCRATCH, 0xf8f8aeae, readback=False)
```

This will execute only a single register operation, and the client will receive the word it sent.


### Disabling respose (silent mode)
By default, the board will respond to all queries with a packet mirroring the one received, but with the message id incremented by 1 and with various requests serviced.
Sometimes, it is desirable to suppress these responses from the board.
For example, the EEVEE firmware data path (connected to your project specific stuff) gets AXI stream muxed with the EEVEE control path.
If the data path is improperly configured, the simultaneous access by both paths may result in strange behavior.
This can be diagnosed with silent mode

```python
   board.poke(eevee.GETTAWONK_OFFSET | eevee.SOFT_TRIGGER, 0xf8f8aeae, silent=True)
```

## Responses
The `response` is a list of `payload` objects.
A `payload` consists of an operation `op`, like a register manipulation, and a `payload` (sorry for the naming) containing whatever data was returned by the board for that operation.
In the case of register transactions, each `payload` is returned as a `dict()` type.
If something within a transaction was run in silent mode

```python
	board.poke(eevee.INTERNAL_OFFSET | eevee.REG_INTERNAL_SCRATCH, 0x0, silent=True)
```

then the returned dictionary for that entry will still contain a key-value pair, but the value will remain as the `bytes()` object sent to the board.

A minimal working example is given in `test_eevee.py`.

### Summary of flag and operation combinations

Operation | Silent | No readback | Behavior
--- | --- | --- | --- 
Write | 0 | 0 | Value is written.  Register is then read.  The readback value is returned to the client
Write | 0 | 1 | Value is written.  The write command is echoed back to the client
Write | 1 | * | Value is written.  Nothing is returned to the client
Read | 0 | 0 | Register is read.  This value is returned to the client
Read | 0 | 1 | NOP. The read command is echoed back to the client
Read | 1 | * | NOP. Nothing is returned to the client

# Command-line interaction

Here are some useful UNIX games to play when working with the boards running this software.
We expect you to be using a sane UNIX.

## Interfacing with a remote board locally

Usually, boards will sit on a private subnet connected to a machine elsewhere.
One's local development repository usually sits on one's own computer.
So, its nice to be able to communicate with a board as if it were connected directly to your computer.
This can be done, without root access, by following the procedure below adapted from [here](http://zarb.org/~gc/html/udp-in-ssh-tunneling.html).

### Preliminaries

The trick is to exploit persistent FIFOs (named pipes) to get duplex streaming on the command line.

1. (Remote) Make a permanent pipe

```bash
$ mkfifo board_pipe
```

2. (Client) Make a permanent pipe

```bash
$ mkfifo board_pipe
```

These command need only be run once, since the unix fifos are now persistent files.

### Using the channel

The order of Steps 1 and 2 is not important, but Step 3 must always be run after both have been completed .

1. (Client) SSH into the remote machine that can talk to the board, forwarding a local TCP port.  E.g. 

```bash
$ ssh -L 7331:localhost:7331 user@remote
```

Note that, as written, this listens on the client at TCP localhost:7331 and transmits this to remote TCP localhost:7331


2. (Remote) Use netcat to push pipe flow between the SSH TCP forward and the board itself.  E.g.

```bash
$ nc -l localhost -p 7331 < board_pipe | nc -u 192.168.5.69 1337 > board_pipe &
```

This sets up 2 netcats.
The first listens for the incoming client connection from the tunnel.
When data comes in over the tunnel, it is sent to the second `netcat`.
When data comes in from board_pipe, it is shipped out back through the tunnel.
The second takes data received from the tunnel and sends it, via UDP, to the default EEVEE port on a board sitting at 192.168.5.69.
Any data received from the board is pushed into board_pipe, to be shipped back over the tunnel via the first `netcat`.

3. (Client) Use `netcat` to push pipe flow between the SSH TCP forward and the Python client-side control. E.g. 

```bash
$ nc localhost 7331 < board_pipe | nc -u -l localhost 1337 > board_pipe &
```

**You must consistently use the same source port for any control connections on the client.**
Note that `-k` flag won't help you here, because `netcat` will `fork()` and the child gets its own standard file descriptors.

6. (Client-python) Instantiate a board _using a consistent port_

```python
myboard = eevee.board('localhost', udpsport=8989)
```

You must use a consistent port, because the client-side `netcat`, listening for Python control,  will `connect()` on the UDP socket.
So your operating system will remember the source port, and subsequently drop anything that comes to the same destination with a different source.


## Working with data

You could, in principle, play the above game with data output from the board.
You would need to forward a distinct port, create distinct pipes, and set up similar interleaved netcats.
**DO NOT** blast 10Gps data in this way: you'll just kill your own SSH session.

This assumes that you have targetted the board at the machine where you are running the command.

### Capturing data being sent to the default port 1338, into 'dumpfile':

```bash
   $ nc -u -l -p 1338 > dumpfile
```

#### Explanation:
`nc` is netcat, which makes a bridge between stdin stdout and a socket

Thing | Meaning
--- | ---
`-u` |  means UDP protocol
`-l` | means listen
`-p` | 1338 gives the port to listen to
`> dumpfile` |  means redirect stdout to a file named `dumpfile` (this will overwrite `dumpfile` if it already exists)

*NOTE:* At a minimum, this must be running on whatever computer the board is targetted at, or else all the streamed packets will ICMP error out.
___

### Viewing data as 32-bit hex words as it comes in:

```bash
   $ nc -u -l -p 1338 | xxd -p -c 4
```

#### Explanation:
See description above for netcat.

Thing | Meaning
--- | ---
`\|` | a pipe, means redirect stdout from the process on the left of the `\|` to stdin of the process on the right
`xxd` | converts between binary and hex representation in ASCII.  It operates on a per-byte level, so does not confuse you (c.f. `hexdump`) with endianness (WYSIWYGot)
`-p` | means expect/produce a stream
`-c 4` | means give it in rows of 4 bytes
___

### Seeing what version a board is

```bash
   $ echo "1337ca75 00000000 fffffffe" | xxd -r -p | nc -u 10.0.6.193 1337 | xxd -p -c 4
```

#### Explanation:

Thing | Meaning
--- | ---
`echo "whatever"` |  outputs "whatever" on stdin.  The hex string is interpreted as follows.
`1337ca75` | the first 32bits is the EEVEE protocol magic (see `eevee_os.h`)
`00000000` | the second 32bits is the version.  If it does not match the hardware version of the target board, the board will ecbo back with its version.
`fffffffe` | the third 32bits is a message id.  The board will increment this number by 1, and echo it back.
`-r` | this flag to `xxd` means to produce binary from ASCII representation hex
`-p` | this flag to `xxd` means to process as it comes in, not just blast 0x0 (for some reason).
`nc` | without the `-l` flag means to initiate an outgoing connection, instead of listening.


**WARNINGS:**
Don't try to pass `-rp` to `xxd`, or forget the `-p` flag.  `xxd` will not parse the combined flag correctly.
It will then search for an EOF on the echo, but since its an echo there won't be one.
So it will spew 0x0 as fast as possible at the card.
This will probably kill your card.

# Common issues and how to fix them

### Problem: `tcpdump` shows expected frames from the board, but `nc` (netcat) or other custom programs listening on the port do not receive all the data.
This is a buffering issue at the OS level.
It can be fixed by following these instructions, originally found at [https://medium.com/@CameronSparr/increase-os-udp-buffers-to-improve-performance-51d167bb1360].

Adjust/add the following lines in/to your `/etc/sysctl.conf` file

```
net.core.rmem_max=26214400
net.core.rmem_default=26214400
```

The default values for these are quite a bit smaller and lead to lost packets at the IP level, even for small amounts of data, if the data comes in at high rates.
The above values have been verified to work with 25K of data at full gigabit speed and will probably work under much more strenuous situations.

You may either restart (silly!) or just explicitly run

```bash
# sysctl -w net.core.rmem_max=26214400
# sysctl -w net.core.rmem_default=26214400
```

to activate the changes.
I am not sure if Linux will reallocate any presently allocated buffers for open sockets, but I would not expect it to.

### Problem: `tcpdump` does not show all expected frames.
If packets disappear at the `tcpdump` level, you are probably dropping at your PC's hardware MAC (ethernet controller).
The fix there may be hardware specific, but can usually be done with `ifconfig` or related tools.

### Problem: `netcat` behaves badly in other strange ways
There are two versions of `netcat` floating around, the OpenBSD one and something else.
This usually manifests as `/bin/nc` being a symlink to something else.
We recommend using the OpenBSD `netcat`.
For production systems, we typically just write a UDP server (its literally 5 lines in Python 3).

# Evolving EEVEE: The "stone" module system

EEVEE is designed to be easily extensible for particular applications.
For example, particular use cases might want the ability to dynamically update device firmware OTA.
Such extensions are called stones, in reference to evolution stones for Eevee within the Pokemon universe.

While all critical path operations are performed with static memory allocations, stones work dynamically with the heap.
Using preprocessor directives, the use of typical `free()` and `alloc()` within stones is forbidden.
Instead, stone memory usage is explicitly tracked and garbage collected.

At compile time, the user selects via preprocessor `#define` which (if any) stones are desired.

## The telemetry stone

A working template stone has been included, `eevee_telemetry_stone.c` and `eevee_telemetry_stone.h`.
This stone uses a hardware timer to send user-defined telemetry packets to a user-defined location at a user-defined rate.
Each telemetry packet contains a list of registers and their associated values.

### A sample telemetry request/response packet

```
1337ca75   # EEVEE protocol magic
cafe0003   # EEVEE hardware and software version
fffffffe   # Sequence id, will be incremented by 1 in the control response acknowledging activation of telemetry
0040       # EEVEE operation (telemetry)
0030       # EEVEE payload length (of contents below)  

0a0006fe   # (+4) Request: IP address to receive telemetry
1000       # (+2) Request: UDP port to receive telemetry
cece       # (+2) Request: Padding (2 bytes)
00000000   # (+4) Request: Padding (4 bytes)
00000001   # (+4) Request: Transmission rate (e.g. 1x every user-defined clock tick)

00000000   # (+4) Request: Register address (e.g. EEVEE Version)
ffffffff   # (+4) Request: ignored
00000120   # (+4)
ffffffff   # (+4) ...
00000128   # (+4)  (This format continues)
ffffffff   # (+4) ...
00000124   # (+4)
ffffffff   # (+4) 
           # --------------------
           #  48 bytes = 0x30 hex
```

Telemetry responses will then be of the same size, but

1. have IP and UDP port replaced with board ID
2. have Transmission rate and the 4 bytes of padding before it replaced with a 64-bit hardware timestamp
3. have the actual register values at the timestamp written into the ignored fields in the request packet

## Writing your own stones

1. Copy the template files to new ones
2. Write your stone, following the template example
3. Add an appropriately proprocessor-wrapped `registerStone(...)` call to `main()` in `eevee_os.c` to load your stone
4. Enable this wrapping in `platform_definition.h`

Of course, the language is C, so you can easily break whatever you want.
If you follow the template interface, however, you should not (easily) affect system stability (though you can still DoS yourself).
