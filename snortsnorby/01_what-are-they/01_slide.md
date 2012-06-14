!SLIDE 
# Intrusion Detection for Websites With Snort / Snorby #

!SLIDE
# Snort is a rule-based IDS/IPS #

!SLIDE bullets incremental
# Snort : Modes #

* sniffer
* packet logger
* intrusion detection

!SLIDE bullets incremental
# Snort : Sniffing Mode #

* logs to console
* lightweight
* useful for debugging/testing

!SLIDE bullets incremental
# Snort : Logging Mode #

* logs to disk
* tcpdump/pcap is rather ubiquitous
* replay packet capture to N
* caveat - defaults to ASCII
* caveat - verbose, logs everything

!SLIDE bullets incremental
# Snort : Intrusion Detection #

* granular / rule-based
* caveat - verbose mode = slow
* caveat - requires tuning for high performance

!SLIDE bullets incremental
# Snort : Alert Order #

* Pass
* Drop
* Alert
* Log

!SLIDE bullets incremental
# Snort : Bustin a Pcap #

Snort uses an abstraction layer called DAQ for packet aquisition.

* pcap (optional mmap version also)
* afpacket (mmaped like ^ but no external reqs)
* NFQ/IPQ (new/old iptables processing)
* IPFW (BSD)
* Dump (testing)

!SLIDE bullets incremental
# Snort : Preprocessors #

Act as plugins that run after the packet is decoded but before the detection engine is called. Out-of-band modification/analysis.

* defragmentation
* session tracking (tcp/udp)
* portscan
* protocol inspection (http/sip/rpc/etc)
* reputation

!SLIDE
# Snort : Sample Rules #

alert tcp any any -> any any (msg:"NOOP Sled"; content:"|90909090909090|"; reference:h2g2,42; classtype:snorby-demo-noop; sid:987654321; rev:1;)

alert tcp any any -> any 1234 (msg:"TECHTALK blasphemer"; content:"TECHTALK SUCKZ"; reference:austin,316; classtype:techtalk-blasphemer; sid:123456789; rev:1;)

alert tcp any any -> any 21 (flow:to_server,established; content:"root"; pcre:"/user\s+root/i";)

alert tcp any any -> $HOME_NET 1337 (msg:"Unicode Right-to-Left Override"; flow:to_server,established; content:"POST"; http_method; uricontent:"%u202e"; nocase; http_client_body; classtype:website-vuln; sid:13370001; rev:1;)

!SLIDE bullets incremental
# Snort : Rule Explaination #

alert tcp any any -> any 21 (flow:to_server,established; content:"root"; pcre:"/user\s+root/i";)

* alert (from alert order, pass/drop/alert/log)
* protocol
* source network and port
* destination network and port
* flow of traffic (established+/to_server/from_server)
* payload (here content and pcre [yay, regex])

!SLIDE bullets incremental
# Snort : More Rule Goodies #

alert tcp any any -> any 1234 (msg:"TECHTALK blasphemer"; content:"TECHTALK SUCKZ"; reference:austin,316; classtype:techtalk-blasphemer; sid:123456789; rev:1;)

* msg (alert message)
* reference (can be cve, other lookup/id)
* classtype (used to classify/prioritize severity)
* sid/rev (identifier and revision number)

!SLIDE
# Demo Time! #

!SLIDE bullets
# For More Information #

* http://snorby.org/
* http://snort.org/
* http://perldancer.org/
* https://github.com/schacon/showoff
* https://github.com/jpearsall/presentations (coming soon)
