![A picture of a Kestrel](https://i.imgur.com/r6iIFxd.jpg)

Kestrel
=======

Another cjdns router implementation.

## Background

Cjdns is the name of a [meshnet routing protocol](https://github.com/cjdelisle/cjdns/blob/master/doc/Whitepaper.md) and [router implementation](https://github.com/cjdelisle/cjdns) from [cjd](https://github.com/cjdelisle).

Kestrel is an attempt at a new, simpler cjdns router in Golang.

Why a new router? Because I think simpler routers will make it easier to debug, troubleshoot and develop cjdns.

## Known Issues/Limitations

1. I'm writing Kestrel in Golang. I have no experience with Golang prior to this project
2. Cjdns is an encrypted network protocol. I haven't implemented encrypted network protocols  
2. Kestrel is being written first for Linux/x64. If you need multiplatform support, stick with cjdroute. If you would like to help make Kestrel work on other platforms, please get in contact.

## FAQ

**Q: Is this a fork of cjdns?**

*A: No. This is an attempt at an interoperable cjdns router in golang.*

**Q: What is the status of Kestrel?** 

*A: Kestrel is not ready for testing or production use as of Q1 2015*

**Q: Why not work on cjdroute instead?**

*A: 1) I felt like learning Golang, and 2) writing Kestrel is a great way to learn how the cjdns protocol works by implementing it from the ground up.*

**Q: Why not insert other language here?**

*A: Golang felt like the sweet spot for porting a C-based network daemon (there's many success stories of companies porting network services to Golang). The combination of static-typing, garbage collection and C-like syntax makes code more readable and significantly harder to screw up than C.*

**Q: What's with the name Kestrel? Will you change the name again?**

*A: I like birds. Pray I do not change the name further.*

**Q: Why did you move this repo from github.com/jphackworth to github.com/nsjph? Is it the same dev?**

*A: Yes it's the same author. I changed it because jphackworth is too long, and nsjph matches my twitter.*

## For Developers

There's not much to see at the moment.
