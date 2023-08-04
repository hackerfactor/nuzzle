/*************************************************************
 Nuzzle: Log indicators of intent: attacks, scans, and reconnaisance.
 It's a little packet sniffer that looks for stinky packets.

 =============================================================
 Copyright (c) 2023, Neal Krawetz, Hacker Factor

 Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

 1. This software is for not for resale, commercial bundling, or commercial distribution. For commercial use or distribution, contact the copyright holder for a license.

 2. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

 3. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

 4. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 =============================================================

 To compile:

   g++ -Wall -o nuzzle nuzzle.c

 Why g++ when it's written in C?
   - Because g++ gives better compiler warnings.
   - Because g++ natively defines 'true', 'false', and 'bool'.

 Tested and works with g++ and gcc 4.8 and 9.4. It should compile clean and
 work with all version.

 This code uses the interface in promiscuous mode. Promiscuous mode requires
 root access on Linux systems. After configuring the network, this code
 drops privileges back to the user's level.

 To run:

   # Get the list of interfaces
   ./nuzzle -i list
   # You should see output like:
   Available interfaces: eth0 eth1

   # Monitor an interface, such as eth0
   # The '-t' includes a timestamp on each line.
   sudo ./nuzzle -i eth0 -t

   # Monitor the interface and permit connections on TCP 22, 80, and 443:
   sudo ./nuzzle -i eth0 -t -T 22,80,443

   # Monitor in daemon mode and log to syslog as service "nuzzle"
   # "-d" enters the daemon mode and runs as a background process.
   # syslog already includes timestamps, so "-t" is not necessary.
   sudo ./nuzzle -i eth0 -d -T 22,80,443

 *************************************************************/

#include <stdlib.h>
#include <stdbool.h> // for gcc support of bool
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h> // for vfprintf
#include <sys/types.h>
#include <time.h>
#include <fcntl.h>
#include <syslog.h>
#include <sys/time.h>
#include <pwd.h> // For dropping user privileges
#include <signal.h> // for catching ^C

#include <netpacket/packet.h> // for reading interfaces
#include <net/ethernet.h> // for ETHERTYPE_IP and ETHERTYPE_IPV6
#include <sys/ioctl.h> // for reading sockets
#include <arpa/inet.h> // for IPPROTO definitions
#include <net/if.h> // for interface prototypes
#include <ifaddrs.h> // for getifaddrs
#include <netdb.h> // for unknown protocol names

#define MAXPACKET 65536 /* Max packet size for reading */
#define MAXOUTPUT 600 /* Max output size for buffering */

/* typedef unnecessary for g++, but needed for gcc */
typedef struct in_addr in_addr;
typedef struct in6_addr in6_addr;

const char *VERSION="nps-1.4"; // Nuzzle packet sniffer
int Verbose=0;
bool Anonymize=false; // should local network address be anonymized?

/*****
 TCP tracking is easy:
 I have a list of permitted open (incoming) services.
 Any other incoming traffic is logged.
 *****/
time_t TCPpermit[65536]; // List of permitted IP addresses

/*****
 UDP tracking is harder:
 Some services use dynamic UDP ports.
 Outgoing may need to be permitted temporarily as the local client
 waits for a reply.
 *****/
#define UDPtimeout 30 /* duration in seconds for temporary permit */
time_t UDPpermit[65536];
time_t UDPLITEpermit[65536];

bool GREpermit=false; // Permit GRE?
bool PRIVpermit=false; // Permit private network ranges (non-routable)?

struct timeval PacketTime; // for tracking time
bool LineFlush=false; // True if line flushing
bool IncludeTime=false; // True if output should include timestamps
uint32_t link_type=0; // type of link layer

// For Daemonizing
bool GoDaemon=false; // True if running as daemon
int OutputPipe[2]; // for output control (used by daemon)
char OutputBuf[MAXOUTPUT]; // buffer for stdout (used by daemon)

// For printing flags (uint16_t)
typedef enum {
  FLAG_NONE=0,
  FLAG_TRUNC=0x01, // packet is truncated
  FLAG_TRACEROUTE=0x02, // packet is a traceroute
  // not ping and not scanner = permitted
  FLAG_PING=0x04, // packet is a known ping
  FLAG_SCANNER=0x08, // packet is a scan
  FLAG_PRIVATE=0x80, // packet is from a private address
  FLAG_SEQ=0x100, // packet has sequence number
  FLAG_PERMIT=0x8000 // packet is permitted, but show it anyway (debugging)
  } printflags;

/* Track my own IP addresses */
typedef union
  {
  in_addr v4;
  in6_addr v6;
  uint8_t b[16]; // access addresses as bytes
  } vnetaddress;
typedef struct
  {
  uint16_t proto;
  vnetaddress addr;
  } vaddress;
typedef struct
  {
  uint16_t proto;
  vnetaddress addr;
  vnetaddress mask;
  } vmask;
vmask *PermitHost=NULL; /* this is me (or permitted) */
int MaxPermitHost=0;
struct ifaddrs *ifaddr=NULL; // list of network interfaces

/* List of known private addresses */
struct privaterange
  {
  uint16_t proto;
  vnetaddress RangeStart,RangeEnd; // inclusive range
  struct privaterange *Next;
  };
typedef struct privaterange privaterange;
privaterange *PrivateRange=NULL;

#define swap32endian(num) ( ((num>>24)&0xff) | ((num<<8)&0xff0000) | ((num>>8)&0xff00) | ((num<<24)&0xff000000) )

/******************************************
 Usage(): Display usage
 ******************************************/
void	Usage	(char *Name)
{
  printf("Nuzzle, Copyright 2013-2023 Hacker Factor\n");
  printf("Version: %s\n",VERSION);
  printf("Usage: %s [options]\n",Name);
  printf("  Required: -i interface. If you don't know, use '-i list'.\n");
  printf("  -i list :: List all interfaces.\n");
  printf("  -i [interface] :: Listen on interface for packets.\n");
  printf("  Runtime:\n");
  printf("  -A      :: Anonymize the destination (local) address\n");
  printf("  -d      :: Run as daemon. (Requires -i interface; stdout=syslog)\n");
  printf("  -l      :: fflush output\n");
  // syslog already includes a timestamp.
  // I don't recommend logging the timestamp twice per line.
  printf("  -t      :: include timestamps in output (don't use with -d)\n");
  printf("  Permitting (don't report):\n");
  printf("  -H host :: Add another permitted network address (IPv4 or IPv6)\n");
  printf("  -H host/mask :: Add a permitted network range in CIDR format\n");
  printf("  -T [port[,port,...]]  :: List of permitted TCP ports\n");
  printf("  -U [port[,port,...]]  :: List of permitted UDP ports\n");
  printf("  -u [port[,port,...]]  :: List of permitted UDPLITE ports\n");
  printf("     If list begins with '-', then permit all EXCEPT the port list.\n");
  printf("     E.g., to only log email ports, use: -T -25,587\n");
  printf("  -G      :: permit GRE\n");
  printf("  -P      :: permit private address ranges\n");
  printf("  Debugging:\n");
  printf("  -v      :: Verbose (debugging; probably not what you want).\n");
  printf("\n");
  return;
} /* Usage() */

/******************************************
 SafeUser(): Don't run as root!
 ******************************************/
void    SafeUser	()
{
  char *User;
  struct passwd *pwd;

  if (geteuid() != 0) return; /* Safe! */

  /* Running via suid bit */
  if (getuid() != 0)
    {
    if (!seteuid(getuid())) return;
    }

  /* Running via sudo */
  User=getenv("SUDO_USER");
  if (User)
    {
    pwd = getpwnam(User);
    if (pwd && (pwd->pw_uid > 0))
      {
      if (!setegid(pwd->pw_gid) && seteuid(pwd->pw_uid)) return;
      }
    }

  /* Running via other mode */
  User=getenv("USER");
  if (User)
    {
    pwd = getpwnam(User);
    if (pwd && (pwd->pw_uid > 0))
      {
      if (!setegid(pwd->pw_gid) && !seteuid(pwd->pw_uid)) return;
      }
    }

  /* Punt! Run as nobody! */
  pwd = getpwnam("nobody");
  if (pwd && (pwd->pw_uid > 0))
    {
    if (!setegid(pwd->pw_gid) && seteuid(pwd->pw_uid)) return;
    }

  return; // Sorry, nothing I can do.
} /* SafeUser() */

/******************************************
 PrintMsg(): Display a message for logging.
 ******************************************/
void	PrintMsg	(uint16_t ether_type, uint8_t ttl, uint16_t flags,
			 vnetaddress saddr, vnetaddress daddr,
			 const char *HasSPort, uint16_t sport,
			 const char *HasDPort, uint16_t dport,
			 uint32_t seq,
			 const char *Msg, ...)
{
  /*****
   This function writes the log line to a buffer.
   If it's a daemon, the buffer goes to syslog.
   Otherwise, it goes to stdout.
   *****/
  char ipstr[INET6_ADDRSTRLEN*2];
  if (IncludeTime)
    {
    memset(ipstr,0,INET6_ADDRSTRLEN*2); // reuse string buffer
    strftime(ipstr,INET6_ADDRSTRLEN*2,"%F %T",gmtime(&PacketTime.tv_sec));
    printf("%s.%.06ld GMT ",ipstr,(long int)(PacketTime.tv_usec));
    }

  switch(ether_type)
    {
    case ETHERTYPE_IP: // IPv4
	{
	printf("%s",inet_ntoa(saddr.v4));
	if (HasSPort) { printf("[%d/%s]",sport,HasSPort); }
	if (Anonymize) { printf(" -> hostipv4"); }
	else
	  {
	  printf(" -> %s",inet_ntoa(daddr.v4));
	  }
	if (HasDPort) { printf("[%d/%s]",dport,HasDPort); }
	}
	break;

    case ETHERTYPE_IPV6: // IPv6
    	{
	memset(ipstr,0,INET6_ADDRSTRLEN*2);
	inet_ntop(AF_INET6,&(saddr.v6.s6_addr),ipstr,INET6_ADDRSTRLEN);
	printf("%s",ipstr);
	if (HasSPort) { printf("[%d/%s]",sport,HasSPort); }
	if (Anonymize) { printf(" -> hostipv6"); }
	else
	  {
	  memset(ipstr,0,INET6_ADDRSTRLEN*2);
	  inet_ntop(AF_INET6,&(daddr.v6.s6_addr),ipstr,INET6_ADDRSTRLEN);
	  printf(" -> %s",ipstr);
	  }
	if (HasDPort) { printf("[%d/%s]",dport,HasDPort); }
	}
	break;

    default: // other
	break;
    }

  if (ttl > 0) { printf(" ttl=%u",ttl); }

  /*****
   Some scanners use the TCP sequence number for tracking burst scans.
   They use it like a SYN-cookie, so they don't have to store all of
   the IP addresses that they are scanning. They know who is responding by
   looking at the reply sequence number.  This technique is used by the
   Mirai bot family.
   *****/
  if (flags & FLAG_SEQ)
    {
    if (ether_type==ETHERTYPE_IP)
      {
      if (seq == daddr.v4.s_addr) { printf(" seq=4vip.dst"); } // ipv4 little-endian
      else if (seq == swap32endian(daddr.v4.s_addr)) { printf(" seq=ipv4.dst"); } // ipv4 big-endian
      else { printf(" seq=%08x",seq); }
      }
    else { printf(" seq=%08x",seq); }
    }

  printf(" : ");
  va_list argp;
  va_start(argp,Msg);
  vfprintf(stdout,Msg,argp);

  // Show flags
  if (flags & FLAG_TRUNC) { printf(", truncated"); }
  if (flags & FLAG_PING) { printf(", ping"); }
  if (flags & FLAG_TRACEROUTE) { printf(", traceroute"); }
  if (flags & FLAG_SCANNER) { printf(", scanner"); }
  if (flags & FLAG_PRIVATE) { printf(", private"); }
  if (flags & FLAG_PERMIT) { printf(", permitted"); }

  printf("\n");
  if (GoDaemon)
    {
    int len;
    memset(OutputBuf,0,MAXOUTPUT);
    len=read(OutputPipe[0],OutputBuf,MAXOUTPUT);
    if (len > 0) { syslog(LOG_INFO,"%.*s",len,OutputBuf); }
    }
  else if (LineFlush) { fflush(stdout); }
} /* PrintMsg() */

/******************************************
 FreeInterface(): Free global interface structure.
 ******************************************/
void    FreeInterface   ()
{
  if (ifaddr) { freeifaddrs(ifaddr); ifaddr=NULL; }
} /* FreeInterface() */

/******************************************
 Shutdown(): Catch a signal and mark this as done.
 sig = incoming signal, or negative to exit with non-zero return code.
 ******************************************/
void	Shutdown	(int sig)
{
  /* Free linked list of private range addresses */
  privaterange *pr;
  while(PrivateRange)
    {
    pr=PrivateRange->Next;
    free(PrivateRange);
    PrivateRange=pr;
    }

  /* Free hosts */
  FreeInterface();
  if (PermitHost) { free(PermitHost); }
  PermitHost=NULL;
  MaxPermitHost=0;

  /* Flush output */
  fflush(stdout);
  endprotoent(); /* Deallocate any protocol memory (for a clean exit) */

  if (sig < 0) { exit(-sig); }
  exit(0);
} /* Shutdown() */

/******************************************
 SetPorts(): From command-line: Set ports to ignore.
 If the string begins with "-", then set ports to watch.
 List ports with any non-numeric character as separator.
 ******************************************/
void	SetPorts	(time_t Permit[65536], const char *arg)
{
  int v,i;
  uint8_t Watch=1;

  if (!arg) { return; }
  if (arg[0]=='-') // permit all; arg is an unpermit list
	{
	for(i=0; i < 65536; i++) { Permit[i]=1; }
	Watch=0;
	}

  i=0;
  while(arg[i])
    {
    if (!isdigit(arg[i])) { i++; continue; }
    v = atoi(arg+i);
    if ((v > 0) && (v <= 65535)) { Permit[v]=Watch; }
    while(isdigit(arg[i])) { i++; }
    }
} /* SetPorts() */

/******************************************
 IsPermitAddress(): Is this IP (IPv4/IPv6) address permitted?
 (Me or a known permitted address.)
 Returns: true if it's permitted.
 ******************************************/
int     IsPermitAddress     (int proto, vnetaddress addr)
{
  register int B,b,h;
  for(h=0; h < MaxPermitHost; h++)
    {
    if (proto != PermitHost[h].proto) { continue; }

    // How many bytes in the address?
    if (proto==ETHERTYPE_IP) { B=4; }
    else if (proto==ETHERTYPE_IPV6) { B=16; }
    else { continue; } // should never happen

    // Does the address match the given address+mask?
    for(b=0; b < B; b++)
      {
      if ((addr.b[b] & PermitHost[h].mask.b[b]) != PermitHost[h].addr.b[b]) { break; }
      }
    if (b >= B) { return(1); } // it matched!
    }

  return(0);
} /* IsPermitAddress() */

/******************************************
 AddPrivateRange(): Add an address range to the list of private addresses.
 Sets the global list PrivateRange;
 ******************************************/
void	AddPrivateRange	(uint16_t proto, const char *Start, const char *End)
{
  privaterange *NewRange;

  // Allocate memory
  NewRange = (privaterange*)calloc(sizeof(privaterange),1);
  if (!NewRange) { return; } // failed to allocate

  // Store new values
  NewRange->proto = proto;
  if (proto==ETHERTYPE_IP) // IPv4
	{
	inet_pton(AF_INET,Start,&(NewRange->RangeStart.v4));
	inet_pton(AF_INET,End,&(NewRange->RangeEnd.v4));
	}
  else if (proto==ETHERTYPE_IPV6) // IPv6
	{
	inet_pton(AF_INET6,Start,&(NewRange->RangeStart.v6));
	inet_pton(AF_INET6,End,&(NewRange->RangeEnd.v6));
	}
  else // unknown protocol (should never happen)
	{
	free(NewRange);
	return;
	}

  // Insert it into the list
  NewRange->Next = PrivateRange;
  PrivateRange = NewRange;
} /* AddPrivateRange() */

/******************************************
 IsPrivateRange(): Is this IP (IPv4/IPv6) address private?
 Returns: true if it's private.
 ******************************************/
int	IsPrivateRange	(int proto, vnetaddress *addr)
{
  privaterange *pr;
  // Check if addr is a known private address
  for(pr=PrivateRange; pr; pr=pr->Next)
    {
    if (pr->proto != proto) { continue; } // next protocol
    if (proto==ETHERTYPE_IP) // IPv4
	{
	if (memcmp(&(addr->v4),&(pr->RangeStart.v4),4) < 0) { continue; } // out of range
	if (memcmp(&(pr->RangeEnd.v4),&(addr->v4),4) < 0) { continue; } // out of range
	return(1); // matched!
	}
    else if (proto==ETHERTYPE_IPV6) // IPv6
	{
	if (memcmp(&(addr->v6),&(pr->RangeStart.v6),16) < 0) { continue; } // out of range
	if (memcmp(&(pr->RangeEnd.v6),&(addr->v6),16) < 0) { continue; } // out of range
	return(1); // matched!
	}
    // else: Should never happen!
    }
  return(0); // did not match
} /* IsPrivateRange() */

/******************************************
 AddPermitHost(): Mark a host as permitted.
 ******************************************/
void	AddPermitHost	(int Family, void *addr, int MaskBits, bool IsRawAddress)
{
  if (Family == AF_INET) // set ipv4
      {
      struct sockaddr_in *in;
      in = (struct sockaddr_in*)addr;
      PermitHost = (vmask*)realloc(PermitHost,sizeof(vmask)*(MaxPermitHost+1));
      if (IsRawAddress) { memcpy(&PermitHost[MaxPermitHost].addr.v4,addr,sizeof(in_addr)); }
      else { memcpy(&PermitHost[MaxPermitHost].addr.v4,&in->sin_addr,sizeof(in_addr)); }
      PermitHost[MaxPermitHost].proto = ETHERTYPE_IP;
      if ((MaskBits < 1) || (MaskBits > 32)) { MaskBits=32; }
      if (Verbose)
	{
	printf("Permit Host[%d] = %s/%d\n",MaxPermitHost,inet_ntoa(PermitHost[MaxPermitHost].addr.v4),MaskBits);
	}
      }

  else if (Family == AF_INET6) // set ipv6
      {
      struct sockaddr_in6 *in;
      char ipstr[INET6_ADDRSTRLEN+1];
      in = (struct sockaddr_in6*)addr;
      if (((uint8_t*)(&(in->sin6_addr)))[0]==0xfe) { return; } // no local
      if (((uint8_t*)(&(in->sin6_addr)))[0]==0x00) { return; } // no unset
      PermitHost = (vmask*)realloc(PermitHost,sizeof(vmask)*(MaxPermitHost+1));
      if (IsRawAddress) { memcpy(&PermitHost[MaxPermitHost].addr.v6,addr,sizeof(in6_addr)); }
      else { memcpy(&PermitHost[MaxPermitHost].addr.v6,&in->sin6_addr,sizeof(in6_addr)); }
      PermitHost[MaxPermitHost].proto = ETHERTYPE_IPV6;
      if ((MaskBits < 1) || (MaskBits > 128)) { MaskBits=128; }
      if (Verbose)
	{
	memset(ipstr,0,sizeof(ipstr));
	inet_ntop(AF_INET6,&(PermitHost[MaxPermitHost].addr.v6.s6_addr),ipstr,INET6_ADDRSTRLEN);
	printf("Permit Host[%d] = %s/%d\n",MaxPermitHost,ipstr,MaskBits);
	}
      }

  else { return; } // not IPv4 or IPv6 (skip it)

  // If it make it this far, then it's an allocated IPv4/IPV6 address.
  // Set Mask Bits
  register int m,b;
  m=MaskBits;
  for(b=0; b < 16; b++)
    {
    if (m == 0) { PermitHost[MaxPermitHost].mask.b[b]=0; }
    else if (m >= 8) { PermitHost[MaxPermitHost].mask.b[b]=255; m-=8; }
    else // m is [1,7]
      {
      PermitHost[MaxPermitHost].mask.b[b] = 255 << (8-m);
      m=0;
      }
    // Reduce permitted host to minimum value
    PermitHost[MaxPermitHost].addr.b[b] &= PermitHost[MaxPermitHost].mask.b[b];
    }
  MaxPermitHost++;
} /* AddPermitHost() */

/******************************************
 MyAddresses(): Given an interface name, identify
 every IP address that is mine.
 ******************************************/
void    MyAddresses     ()
{
  struct ifaddrs *ifa;
  for(ifa=ifaddr; ifa; ifa=ifa->ifa_next)
    {
    if (!(ifa->ifa_flags & IFF_UP)) continue; // must be up
    if (ifa->ifa_flags & IFF_NOARP) continue; // needs Layer2
    if (ifa->ifa_flags & IFF_LOOPBACK) continue; // no loopback
    AddPermitHost(ifa->ifa_addr->sa_family,ifa->ifa_addr,-1,false);
    }
} /* MyInterface() */

/******************************************
 ProcessPacket(): Given a packet (from pcap), parse it!
 Skip fractional/truncated packets.
 Skip anything that looks iffy, wrong, unknown, bad, etc.
 Assume all data is potentially corrupt!
 The main thing here is SPEED!
 ******************************************/
void	ProcessPacket	(size_t packetlen, const uint8_t *packet)
{
  vnetaddress saddr,daddr; /* source and destination addresses */
  uint16_t sport=0,dport=0; /* source and destination port */
  uint16_t ether_type=0; /* v4 or v6 */
  uint16_t pflags=0; /* print message flags */
  uint8_t ip_proto=0; /* TCP, UDP, etc. */
  uint8_t ip_ttl=0; /* IP TTL */
  uint32_t seq=0; /* TCP sequence */
  size_t PacketStart=0; /* For tracking how much of the packet has been processed */
  const char *ip_proto_name=NULL;
  int HasPort=0; /* 1 if sport, 2 if dport also set */

  /* Layer 1: Physical. No impact on packet */

  /*****
   Layer 2: Data Link.
   Simple header:
     6 bytes: dst mac
     6 bytes: src mac
     2 bytes: ether type
   *****/
  if (PacketStart+14 > packetlen) { return; } // truncated
  ether_type = packet[PacketStart+12]*256 + packet[PacketStart+13];
  PacketStart = 14; // mark 14 bytes as processed

  pflags = FLAG_SCANNER; // be pessimistic: assume it is a scanner

  /* Layer 3! Determined by layer2 ether_type */
  /* Extract ip header and offsets */
  switch(ether_type)
    {

    case ETHERTYPE_IP: /* IPv4: minimum 20 byte header */
	{
	if (PacketStart+20 > packetlen) { return; } // truncated; should never happen
	ip_ttl = packet[PacketStart + 8]; /* TTL value */
	if (ip_ttl <= 1) { pflags |= FLAG_TRACEROUTE; }
	ip_proto = packet[PacketStart + 9]; /* TCP, UDP, etc. */
	memcpy(&saddr,packet+PacketStart+12,4); /* Store source address */
	memcpy(&daddr,packet+PacketStart+16,4); /* Store destination address */

	/* Reference: https://en.wikipedia.org/wiki/Link-Local_Multicast_Name_Resolution */
	/* Ignore IPv4 Link-Local Multicast Name Resolution */
	if (!memcmp(&daddr,"\xE0\x00\x00\xFC",4) &&
	    !memcmp(packet,"\x01\x00\x5E\x00\x00\xFC",6)) // known MAC address
	  { return; }

	PacketStart += 20;
	}
	break;

    case ETHERTYPE_IPV6: /* IPv6: minimum 40 byte header */
	{
	if (PacketStart+40 > packetlen) { return; } // truncated; should never happen
	if ((packet[PacketStart+0] >> 4) != 6) { return; } // not IPv6

	ip_ttl = packet[PacketStart + 7]; /* TTL value is the IPv6 "Hop Limit" (hlim) */
	if (ip_ttl <= 1) { pflags |= FLAG_TRACEROUTE; }
	memcpy(&saddr,packet+PacketStart+8,16); /* Store source address */
	memcpy(&daddr,packet+PacketStart+24,16); /* Store destination address */

	/* Reference: https://en.wikipedia.org/wiki/Link-Local_Multicast_Name_Resolution */
	/* Ignore IPv6 Link-Local Multicast Name Resolution */
	if (!memcmp(&daddr,"\xff\x02\x00\x00",4)) { return; }
	if (!memcmp(&saddr,"\xfe\x80",2)) { return; } // ignore local-link
	if (!memcmp(&daddr,"\xfe\x80",2)) { return; } // ignore local-link

	/*****
	 With IPv4, it's pretty simple to determine the payload.  There's
	 a protocol field.  If it says "TCP", then the payload is TCP.

	 With IPv6, life becomes much more interesting...
	 IPv6 can chain fields together through "extensions".
	 This is handled by the "next" field.
	 *****/
	uint8_t next;
	ip_proto = next = packet[PacketStart + 6];
	PacketStart += 40; // IPv6 header has been processed
	while(next != IPPROTO_NONE)
	  {
	  /*****
	   Every extension begins with 2 bytes:
	   Next header type and length of current header in 8-byte increments.
	   For this scanner, I only care about a few protocols.
	   *****/
	  if (PacketStart + 2 > packetlen) { return; } // truncated
	  switch(ip_proto)
	    {
	    case IPPROTO_ICMPV6:
	    case IPPROTO_TCP:
	    case IPPROTO_UDP:
	    case IPPROTO_UDPLITE:
	    case IPPROTO_GRE:
	    case IPPROTO_SCTP:
		next=IPPROTO_NONE; // exit loop
		break;
	    case IPPROTO_NONE: break; // IPv6-only packet; no data (should never happen)
	    default: /* It's an extension. Don't know, don't care. Skip it. */
		ip_proto = packet[PacketStart+0]; // next data type
		PacketStart += packet[PacketStart+1]*8;
		break;
	    }
	  }
	}
	break;

    default: // other ethernet packet
	return; // exit; don't care
    }


  /**********
   Quick note about traceroute tracking and corrupt packets.
   Traceroute only cares if the TTL is 1.
   TTL of 0 should never happen.
   But what happens if the network layer is corrupt / truncated?
   Well, the TTL can still be 1, causing the packet to work like traceroute.
   The difference is: are there ports loaded?

   For example: TCP uses source and destination ports.
   If the TCP header is intact, then we have traceroute going to a port.
   If the TCP header is truncated, then we have traceroute without ports.
   This code checks for both!

   The "HasPort" flag determines if the network layer protocol loaded ports.
   **********/

  /*****
   Is this one of my packets? (coming to me?)
   NOTE: UDP is a special case since outgoing can be use to track incoming.
   *****/
  if (ip_proto == IPPROTO_UDP) { ; } // special case, handled later
  else if (!IsPermitAddress(ether_type,daddr)) { return; } // not for me!

  switch(ip_proto)
    {
    case IPPROTO_TCP:
	{
	uint16_t flags;
	ip_proto_name="tcp";
	if (IsPermitAddress(ether_type,saddr)) { return; } // permitted client (don't log)
	if (PacketStart + 20 > packetlen) { pflags |= FLAG_TRUNC; break; } // truncated
	sport = (packet[PacketStart+0] << 8) + packet[PacketStart+1];
	dport = (packet[PacketStart+2] << 8) + packet[PacketStart+3];
	seq = (packet[PacketStart+4] << 24) + (packet[PacketStart+5] << 16) + (packet[PacketStart+6] << 8) + packet[PacketStart+7];
	HasPort=2;
	flags = (packet[PacketStart+12] << 8) | packet[PacketStart+13];
	pflags |= FLAG_SEQ; // has sequence number

	/*****
	 Check if someone is trying to connect (SYN) to a port
	 that isn't known-open.
	 *****/
	if ((flags & 0x01f) != 0x002) { return; } /* Not SYN? */
	if (TCPpermit[dport]) /* if it is permitted */
	  {
	  pflags &= ~FLAG_SCANNER; // remove scanner flag
	  pflags |= FLAG_PERMIT; // it's permitted
	  }
	}
	break;

    case IPPROTO_UDP:
	{
	ip_proto_name="udp";
	if (PacketStart + 8 > packetlen) { pflags |= FLAG_TRUNC; break; } // truncated
	sport = packet[PacketStart+0]*256 + packet[PacketStart+1];
	dport = packet[PacketStart+2]*256 + packet[PacketStart+3];
	HasPort=2;

	/* Check if this is one of my packets */
	if (IsPermitAddress(ether_type,saddr))
	  {
	  /* Outgoing from me? Permit responses back */
	  if (UDPpermit[sport]==1) { ; } // already permitted
	  else { UDPpermit[sport] = PacketTime.tv_sec; } // temporary permit
	  pflags &= ~FLAG_SCANNER; // Not a scanner
	  pflags |= FLAG_PERMIT; // It's me, I'm permitted
	  }
	else if (IsPermitAddress(ether_type,daddr))
	  {
	  /* Incoming to me? Check for permits! */
	  if ((UDPpermit[dport]==1) || // permanent permit
	      (UDPpermit[dport]+UDPtimeout >= PacketTime.tv_sec)) // temporary permit
	    {
	    pflags &= ~FLAG_SCANNER; // Not a scanner
	    pflags |= FLAG_PERMIT; // it's permitted
	    /*****
	     Here's a fun little note...
	     Most UDP services have bidirectional communication fairly often.
	     E.g., ASAP (like NTP) or every few seconds (like Microsoft Teams).
	     Zoom and Google are oddballs, with replies potentially less often
	     than every 10 seconds.  (Lots of incoming, very little outgoing if
	     you're not doing anything.)

	     Solution?
	     Renew any temporary permit each time a permitted packet is seen.
	     *****/
	    if (UDPpermit[sport] > 1) { UDPpermit[dport] = PacketTime.tv_sec; }
	    }
	  }
	else { return; } // not for me
	}
	break;

    case IPPROTO_UDPLITE:
	{
	/*****
	 UDP-Lite (RFC3828) is proposed for streaming audio/video.
	 I've never seen it used outside of test environments.
	 If you run a UDPlite service, then you'll want to add a permit list.
	 (See how it's handled for UDP. Use "-u" for the command-line parameter.)
	 It's very rare, but there are some scanners that look for it.
	 My honeypot sees a UDPlite scan every few months.
	 (I've never seen a server that runs something with UDPlite.)
	 *****/
	ip_proto_name="udplite";
	if (PacketStart + 8 > packetlen) { pflags |= FLAG_TRUNC; break; } // truncated
	sport = packet[PacketStart+0]*256 + packet[PacketStart+1];
	dport = packet[PacketStart+2]*256 + packet[PacketStart+3];
	HasPort=2;

	/* Check if this is one of my packets */
	if (IsPermitAddress(ether_type,saddr))
	  {
	  /* Outgoing from me? Permit responses back */
	  if (UDPLITEpermit[sport]==1) { ; } // already permitted
	  else { UDPLITEpermit[sport] = PacketTime.tv_sec; } // temporary permit
	  pflags &= ~FLAG_SCANNER; // Not a scanner
	  pflags |= FLAG_PERMIT; // It's me, I'm permitted
	  }
	else if (IsPermitAddress(ether_type,daddr))
	  {
	  /* Incoming to me? Check for permits! */
	  if ((UDPLITEpermit[dport]==1) || // permanent permit
	      (UDPLITEpermit[dport]+UDPtimeout >= PacketTime.tv_sec)) // temporary permit
	    {
	    pflags &= ~FLAG_SCANNER; // Not a scanner
	    pflags |= FLAG_PERMIT; // it's permitted
	    /*****
	     Assume udplite works like udp.
	     Renew the temporary permit.
	     *****/
	    if (UDPLITEpermit[sport] > 1) { UDPLITEpermit[dport] = PacketTime.tv_sec; }
	    }
	  }
	else { return; } // not for me
	break;
	}

    case IPPROTO_ICMP:
	{
	if (IsPermitAddress(ether_type,saddr)) { return; } // comes from a permitted; ignore it
	if (ether_type != ETHERTYPE_IP) { ip_proto_name="unknown (icmp not over IPv4)"; break; }
	ip_proto_name="icmp";

	// for logging, show the ICMP type as a port number
	HasPort=1;
	sport = packet[PacketStart];

	if (PacketStart + 4 > packetlen) { pflags |= FLAG_TRUNC; break; } // truncated
	switch(packet[PacketStart]) /* what type of ICMP? */
	  {
	  case 8: /* Echo Request aka ping */
	  case 42: /* Extended Echo Request */
	    pflags &= ~FLAG_SCANNER; // Not a scanner
	    pflags |= FLAG_PING; // explicitly a ping
	    break;
	  case 30: /* ICMP Traceroute */
	    pflags &= ~FLAG_SCANNER; // Not a scanner
	    pflags |= FLAG_TRACEROUTE; // explicitly a traceroute!
	    break;
	  case 5: /* Redirection; usually hostile */
	    {
	    /*****
	     Most linux boxes are configured to ignore ICMP redirect.
	     If you don't ignore it, then someone can redirect your traffic
	     through their man-in-the-middle.
	     Log any redirects!
	     *****/
	    if (PacketStart + 36 > packetlen) { pflags |= FLAG_TRUNC; break; } // truncated
	    const char *ICMPRediectCodeStr[]={"network","host","service+network","service+host","unknown"};
	    uint8_t ICMPRediectCode;
	    vnetaddress Gateway;
	    char GatewayStr[20]; // only needs to be 16 bytes

	    memset(GatewayStr,0,20); // clear string buffer
	    memcpy(&Gateway.v4,packet+PacketStart+32,4); /* Store gateway address */
	    strncpy(GatewayStr,inet_ntoa(Gateway.v4),18); // Ensure null at end of string
	    ICMPRediectCode = packet[PacketStart+1]; // get code

	    pflags &= ~FLAG_SCANNER; // Not a scanner; this is likely an attack
	    if (IsPrivateRange(ether_type,&saddr)) { pflags |= FLAG_PRIVATE; }

	    /*****
	     Redirection is a very special case, so handle it now.
	     *****/
	    PrintMsg(ether_type,ip_ttl,pflags,saddr,daddr,ip_proto_name,packet[PacketStart],NULL,0,
		seq,"%s, redirect %s to %s", ip_proto_name,
		(ICMPRediectCode < 4) ? ICMPRediectCodeStr[ICMPRediectCode] : ICMPRediectCodeStr[4],
		GatewayStr);
	    return; // Done processing
	    }
	    break; // never gets here, but included for completeness.
	  case 0: /* Echo reply (server sent a ping) */
	  case 3: /* Destination unreachable (happens naturally) */
	  case 9: /* Router advertisement */
	  case 10: /* Router solicitation */
	  case 11: /* TTL expired (happens naturally) */
	  case 14: /* Timestamp reply */
	  /* 16 and 18 are deprecated, so let them be flagged */
	  case 43: /* Extended echo reply */
	    pflags &= ~FLAG_SCANNER; // Not a scanner
	    break;
	  default: /* Anything else is probably a scanner */
	    break;
	  }
	}
	break;

    case IPPROTO_ICMPV6:
	{
	/*****
	 IPv6 uses ICMPv6 for lots of purposes.
	 If you just disable ICMPv6, then IPv6 will stop routing!
	 If you disable ICMPv6 echo-request (ping), then Teredo will stop working.
	 (But Teredo is a transitional protocol, and almost nobody uses Teredo anymore.)
	 IsPermitAddress() already ruled out neighbor discovery addresses. 
	 Any remaining 'echo request' must be a ping.
	 *****/
	if (IsPermitAddress(ether_type,saddr)) { return; } // comes from permitted; ignore it
	if (ether_type != ETHERTYPE_IPV6) { ip_proto_name="unknown (icmpv6 not over IPv6)"; break; }

	ip_proto_name="icmpv6";

	// for logging, show the ICMPv6 type as a port number
	HasPort=1;
	sport = packet[PacketStart];

	if (PacketStart + 4 > packetlen) { pflags |= FLAG_TRUNC; break; } // truncated
	switch(packet[PacketStart]) // what type of ICMPv6?
	  {
	  case 128: /* Echo Request aka ping */
	    pflags &= ~FLAG_SCANNER; // Not a scanner
	    pflags |= FLAG_PING; // explicitly a ping
	    break;
	  case 1: /* Destination unreachable (local system sent unreachable packet) */
	  case 2: /* Packet too big (local system generated too big of a packet) */
	  case 3: /* Time exceeded (local system caused a problem) */
	  case 4: /* Parameter problem (local system caused a problem) */
	  case 129: /* Echo Reply (local system sent a ping, this is the reply) */
	    pflags &= ~FLAG_SCANNER; // Not a scanner
	    break;
	  case 150: break; /* reserved / unused; log it */
	  case 154: break; /* reserved / unused; log it */
	  default: /* Anything else is probably expected */
	    /* Ignore long list of IPv6 management codes */
	    if ((packet[PacketStart] >= 130) && (packet[PacketStart] <= 155))
	      {
	      pflags &= ~FLAG_SCANNER; // Not a scanner
	      }
	    /* else: Anything else gets logged */
	    break;
	  }
	break;
	}

    case IPPROTO_SCTP:
	{
	/*****
	 SCTP (RFC9260) is a proposed replacement for TCP.
	 It's intended for connection-oriented audio/video streaming.
	 I've never seen it used outside of test environments.
	 If you run a SCTP service, then you'll want to add a permit list.
	 (See how it's handled for TCP. Use "-S" for the command-line parameter.)
	 It's rare, but there are some scanners that look for it.
	 My honeypot sees an SCTP scan every few days.
	 *****/
	ip_proto_name="sctp";
	if (PacketStart + 12 > packetlen) { pflags |= FLAG_TRUNC; break; } // truncated
	sport = packet[PacketStart+0]*256 + packet[PacketStart+1];
	dport = packet[PacketStart+2]*256 + packet[PacketStart+3];
	HasPort=2;
	break;
	}

    case IPPROTO_GRE:
	{
	/*****
	 Generic Routing Encapsulation (GRE) is a tunneling protocol.
	 My honeypot sees a GRE scan every 1-2 days.
	 *****/
	ip_proto_name="gre";
	if (GREpermit)
	  {
	  pflags |= FLAG_PERMIT; // it's permitted
	  break;
	  }

	int len;
	len=4;
	if (PacketStart + len > packetlen) { pflags |= FLAG_TRUNC; break; } // truncated
	if (packet[PacketStart] & 0x80) { len+=4; } // has checksum and reserved
	if (packet[PacketStart] & 0x20) { len+=4; } // has key
	if (packet[PacketStart] & 0x10) { len+=4; } // has sequence number
	if (PacketStart + len > packetlen) { pflags |= FLAG_TRUNC; break; } // truncated
	break;
	}

    default:
	{
	/*****
	 There are many other protocols, but I almost never seen anyone
	 scanning for them.
	 See: /etc/protocols
	 I've seen:
	   ipencap (ip encapsulation; appears weekly-ish)
	   ipv6  (6in4: network is ETHERNET_IP/ipv4 with transport protocol 41=ipv6)
	 If the name is undefined, it will be logged as "unknown[protocol_number]".
	 My honeypot almost never sees other protocols.
	 *****/
	ip_proto_name=NULL;
	struct protoent *p;
	p = getprotobynumber(ip_proto); // static name
	if (p && p->p_name) { ip_proto_name=p->p_name; }
	}
	break;
    }

  /* Show what I've got! */
  if (pflags == FLAG_NONE) { return; } // nothing to show
  if ((pflags & FLAG_PERMIT) && !Verbose) { return; } // don't show permitted

  // Check for a known-private address (slow check, only do when printing)
  if (IsPrivateRange(ether_type,&saddr)) { pflags |= FLAG_PRIVATE; }

  // HasPort always has ip_proto_name
  // If 2 ports, show both
  if (HasPort==2) { PrintMsg(ether_type,ip_ttl,pflags,saddr,daddr,ip_proto_name,sport,ip_proto_name,dport,seq,"%s",ip_proto_name); }
  // If 1 port, show it as src
  else if (HasPort==1) { PrintMsg(ether_type,ip_ttl,pflags,saddr,daddr,ip_proto_name,sport,NULL,0,seq,"%s",ip_proto_name); }
  // No port? show protocol
  else if (ip_proto_name) { PrintMsg(ether_type,ip_ttl,pflags,saddr,daddr,NULL,0,NULL,0,seq,"%s",ip_proto_name); }
  // No protocol? show unknown
  else { PrintMsg(ether_type,ip_ttl,pflags,saddr,daddr,NULL,0,NULL,0,seq,"unknown[%d]",ip_proto); }

  return;
} /* ProcessPacket() */

/******************************************
 GetInterface(): Find an interface, or find the first interface.
 If Name is "list", then lists all interfaces before exiting.
 If Name is NULL, then returns first viable interface.
 Else (Name is set) return the interface with Name.
 Returns NULL if nothing is found.
 NOTE: Caller must free global ifaddr!
 ******************************************/
struct ifaddrs* GetInterface    (const char *Name)
{
  register int family;
  struct ifaddrs *ifa;
  bool ListAll=false;

  if (getifaddrs(&ifaddr) == -1)
	{
	fprintf(stderr,"ERROR: No interfaces found.\n");
	Shutdown(-1);
	}

  if (Name && !strcmp(Name,"list")) { ListAll=true; }
  if (ListAll) fprintf(stderr,"Available interfaces:");
  for(ifa=ifaddr; ifa; ifa=ifa->ifa_next)
    {
    if (!(ifa->ifa_flags & IFF_UP)) continue; // must be up
    if (ifa->ifa_flags & IFF_NOARP) continue; // needs Layer2
    if (ifa->ifa_flags & IFF_LOOPBACK) continue; // no loopback
    family=ifa->ifa_addr->sa_family;
    if (family!=AF_PACKET) continue; // must support packets
    if (ListAll)
	{
	fprintf(stderr," %s",ifa->ifa_name);
	}
    else if (Name && strcasecmp(Name,ifa->ifa_name)) continue;
    break;
    }

  if (ListAll)
    {
    fprintf(stderr,"\n");
    Shutdown(0); // frees memory, calls exit(0)
    }
  if (ifa) return(ifa);
  if (Name) fprintf(stderr,"ERROR: Interface '%s' not found.\n",Name);
  else fprintf(stderr,"ERROR: No interfaces found.\n");
  Shutdown(-1);
  exit(1); // never reached, but included to make it compile cleanly.
} /* GetInterface() */

/******************************************
 ReadInterface(): Given an interface, read packets!
 Returns: true on file read, false on error.
 ******************************************/
bool	ReadInterface	(const char *dev)
{
  struct ifaddrs *iface;
  int sockraw; /* socket for interface */
  int sockopt=0;
  struct sockaddr_ll interfaceAddr,addr;
  socklen_t addr_len;
  struct ifreq ifopts; // used for promiscuous mode

  size_t PacketSize; // Packet Buffer Size
  uint8_t PacketData[MAXPACKET]; // Packet Buffer

  /*****
   Raw sockets require root access.
   *****/

  /* Use a raw socket */
  iface = GetInterface(dev);
  sockraw = socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
  if (sockraw == -1)
    {
    perror("ERROR: Unable to open raw socket");
    Shutdown(-1);
    }

  /* Use promiscuous mode to capture all packets */
  strncpy(ifopts.ifr_name,iface->ifa_name,IFNAMSIZ-1);
  ioctl(sockraw,SIOCGIFFLAGS,&ifopts);
  ifopts.ifr_flags |= IFF_PROMISC;
  ioctl(sockraw,SIOCSIFFLAGS,&ifopts);

  /* Permit socket reuse */
  if (setsockopt(sockraw,SOL_SOCKET,SO_REUSEADDR,&sockopt,sizeof(sockopt)) == -1)
    {
    perror("ERROR: Unable to set socket");
    close(sockraw);
    Shutdown(-1);
    }

  /* Bind to device */
  memset(&interfaceAddr,0,sizeof(interfaceAddr));
  interfaceAddr.sll_ifindex = if_nametoindex(iface->ifa_name);
  interfaceAddr.sll_family = AF_PACKET;

  /* print capture info */
  if (Verbose) { printf("Device: %s\n",iface->ifa_name); }
  if (bind(sockraw,(struct sockaddr *)&interfaceAddr,sizeof(interfaceAddr)) < 0)
    {
    perror("ERROR: Unable to bind to socket");
    close(sockraw);
    Shutdown(-1);
    }

  /*****
   Store all of my local network addresses.
   Why? I might see packets intended for other systems on the same network.
   I only care about packets intended for me.
   *****/
  MyAddresses();
  FreeInterface(); // done with listing

  /*****
   Prior to this line of code: must run as root to monitor connections.
   Now that I have the socket, I no longer need root access.
   *****/
  /* DO NOT RUN AS ROOT! */
  SafeUser();

  if (GoDaemon)
    {
    if (daemon(0,1)) { Shutdown(-1); } /* chdir(/) and leave file descriptors alone. */

    /* Make pipe that goes from stdout to my buffer. */
    // if (pipe2(OutputPipe,O_NONBLOCK|O_CLOEXEC)) // pipe2 is linux-specific
    if (pipe(OutputPipe))
	{
	fprintf(stderr,"ERROR: Unable to create output pipe.\n");
	Shutdown(-1);
	}
    /* Make sure the pipe never hangs the sniffer! */
    fcntl(OutputPipe[0],F_SETFL,fcntl(OutputPipe[0],F_GETFL) | O_NONBLOCK | O_CLOEXEC);
    fcntl(OutputPipe[1],F_SETFL,fcntl(OutputPipe[1],F_GETFL) | O_NONBLOCK | O_CLOEXEC);

    /* Redirect stdout to my pipe. My pipe will send it to syslog. */
    if (dup2(OutputPipe[1],STDOUT_FILENO) != STDOUT_FILENO)
	{
	fprintf(stderr,"ERROR: Unable to redirect stdout to output pipe.\n");
	Shutdown(-1);
	}
    fclose(stdin);  /* close: unused */
    fclose(stderr); /* close: unused */
    setvbuf(stdout,NULL,_IONBF,0); // no buffering!
    openlog("nuzzle",LOG_NDELAY,LOG_USER);
    }

  /* Capture packets and send to my callback function */
  struct timeval Timeout;
  fd_set rfds;
  int MaxSocket;
  MaxSocket=sockraw;
  while(1)
    {
    Timeout.tv_sec = 2;
    Timeout.tv_usec = 0;
    FD_ZERO(&rfds);
    FD_SET(sockraw,&rfds);
    select(MaxSocket+1,&rfds,NULL,NULL,&Timeout);

    if (FD_ISSET(sockraw,&rfds)) // if reading from raw socket
      {
      addr_len = sizeof(addr);
      memset(PacketData,0,MAXPACKET);
      PacketSize = recvfrom(sockraw,PacketData,MAXPACKET,0,(struct sockaddr*)&addr, &addr_len);
      gettimeofday(&PacketTime,NULL); // get packet time
      if (PacketSize > 0) { ProcessPacket(PacketSize,PacketData); }
      }
    } /* while reading forever */

  /* cleanup (never reached, but included for completeness) */

  /* If promiscuous mode */
  ifopts.ifr_flags &= ~IFF_PROMISC; // disable
  if (ioctl(sockraw,SIOCSIFFLAGS,&ifopts) != 0) { perror("ERROR"); }

  close(sockraw);
  return(true);
} /* ReadInterface() */

/*******************************************************/
/*******************************************************/
/*******************************************************/
int	main	(int argc, char *argv[])
{
  register int c;
  char *dev=NULL;  /* capture device name */

  signal(SIGINT,Shutdown); // Control-C flushes outputs like pcap
  signal(SIGHUP,Shutdown);
  signal(SIGUSR1,Shutdown);

  /* Default values */
  memset(TCPpermit,0,sizeof(TCPpermit));
  memset(UDPpermit,0,sizeof(UDPpermit));
  memset(UDPLITEpermit,0,sizeof(UDPLITEpermit));

  // IP address ranges that should NEVER be seen on the WAN.
  AddPrivateRange(ETHERTYPE_IP,"0.0.0.0","0.255.255.255"); // reserved
  AddPrivateRange(ETHERTYPE_IP,"10.0.0.0","10.255.255.255"); // RFC1918
  AddPrivateRange(ETHERTYPE_IP,"127.0.0.0","127.255.255.255"); // localhost
  AddPrivateRange(ETHERTYPE_IP,"172.16.0.0","172.31.255.255"); // RFC1918
  AddPrivateRange(ETHERTYPE_IP,"192.168.0.0","192.168.255.255"); // RFC1918
  AddPrivateRange(ETHERTYPE_IP,"100.64.0.0","100.127.255.255"); // CGN, RFC6598
  AddPrivateRange(ETHERTYPE_IP,"169.254.0.0","169.254.255.255"); // LocalLink, RFC3927
  AddPrivateRange(ETHERTYPE_IP,"192.0.0.0","192.0.0.255"); // Private
  AddPrivateRange(ETHERTYPE_IP,"192.0.2.0","192.0.2.255"); // Test1, RFC5737
  AddPrivateRange(ETHERTYPE_IP,"198.18.0.0","198.19.255.255"); // Test, RFC2544
  AddPrivateRange(ETHERTYPE_IP,"198.51.100.0","198.51.100.255"); // Test2, RFC5737
  AddPrivateRange(ETHERTYPE_IP,"203.0.113.0","203.0.113.255"); // Test3, RFC5737
  AddPrivateRange(ETHERTYPE_IP,"240.0.0.0","255.255.255.255"); // Class-E, reserved
  AddPrivateRange(ETHERTYPE_IPV6,"0000::","1fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"); // Reserved IETF
  AddPrivateRange(ETHERTYPE_IPV6,"fc00::","fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"); // Local Unicast
  AddPrivateRange(ETHERTYPE_IPV6,"fe00::","fe7f:ffff:ffff:ffff:ffff:ffff:ffff:ffff"); // Reserved
  AddPrivateRange(ETHERTYPE_IPV6,"fe80::","febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff"); // Link Unicast
  AddPrivateRange(ETHERTYPE_IPV6,"fec0::","feff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"); // Reserved

  /* check for capture device name on command-line */
  while((c = getopt(argc,argv,"AdGH:i:lPtT:U:u:v")) != -1)
    {
    switch(c)
      {
      case 'A': Anonymize=true; break;
      case 'd': GoDaemon=true; break;
      case 'i':	dev=optarg; break;
      case 'l':	LineFlush=true; break;
      case 't':	IncludeTime=true; break;

      case 'G': GREpermit=true; break; // permit GRE

      case 'H': // A permitted address!
	{
	vnetaddress Addr;
	int m=-1;
	char *p;
	p=strchr(optarg,'/');
	if (p) { m=atoi(p+1); p[0]='\0'; }
	if (inet_pton(AF_INET,optarg,&(Addr.v4)) == 1) { AddPermitHost(AF_INET,&(Addr.v4),m,true); }
	else if (inet_pton(AF_INET6,optarg,&(Addr.v6)) == 1) { AddPermitHost(AF_INET6,&(Addr.v6),m,true); }
	else { Usage(argv[0]); Shutdown(0); }
	}
	break;

      case 'P': PRIVpermit=true; break; // permit private network ranges

      case 'T': // permit TCP ports
	SetPorts(TCPpermit,optarg);
	break;

      case 'U': // permit UDP ports
	SetPorts(UDPpermit,optarg);
	break;

      case 'u': // permit UDPlite ports
	SetPorts(UDPLITEpermit,optarg);
	break;

      case 'v': Verbose++; break;
      default:
	Usage(argv[0]);
	Shutdown(-1); // free all memory, calls exit()
      }
    }

  if (!dev)
    {
    fprintf(stderr,"ERROR: No -i defined.\n");
    Usage(argv[0]);
    Shutdown(-1); // free all memory, calls exit()
    }

  if (Verbose)
    {
    printf("DEBUG: Permitted TCP ports:");
    for(c=0; c < 65535; c++) { if (TCPpermit[c]) { printf(" %d",c); } }
    printf("\n");

    printf("DEBUG: Permitted UDP ports:");
    for(c=0; c < 65535; c++) { if (UDPpermit[c]) { printf(" %d",c); } }
    printf("\n");

    printf("DEBUG: Permitted UDPlite ports:");
    for(c=0; c < 65535; c++) { if (UDPLITEpermit[c]) { printf(" %d",c); } }
    printf("\n");
    }

  /* Process packets! */
  setprotoent(1);
  ReadInterface(dev);
  if (GoDaemon) { closelog(); }
  else { endprotoent(); }
  return(0);
} /* main() */

