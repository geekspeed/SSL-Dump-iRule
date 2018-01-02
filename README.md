# SSL-Dump-iRule
## F5 iRule for dumping SSL client handshakes

This repo contains two F5 iRules for dealing with troubleshooting client SSL negotiations. 

### The problem
When dealing with changing of SSL cipher strings, it became apparent that our Application Owners needed to have an understanding of what Ciphers their clients were currently connecting with. Far too often the SSL configuration was left with "Default", and visibility into the client handshake process was needed.

### The Solution
The two F5 iRules provided here give us some of that insight:
* ssl.dump.irule-HR.tcl
* ssl.dump.irule-MR.tcl

These irules are essentially the same with the only difference being the verbose output. The "HR" irule is "Human Readable" and is meant to be used along side the included python script (in the bin directory), for human data analysis of incoming connections. The "MR" irule is a straight pipe delimeted output suitable for throwing into a SEIM or other log analysis engine.

These irules log during the SSL handshaking process:
* During the initial SSL handshake, we log the Ciphers offered by the client
* Once the SSL handshake has concluded we log on what the agreed upon Cipher is between our F5 and the Client
* If the agreed upon Cipher is a member of the "SSL" cipher suite, or contains DES, RC4, or SHA in the Cipher we log a seperate entry and also log the bit size and the User Agent String. We do the same if the bit size is 128 or below, and if SHA is present as a MAC within wthin the Cipher string

### Examples
Example log entries are below:
#### Client Cipher Negotiation:
>Dec 17 01:26:08 example-waf01 info tmm1[11161]: Rule /Common/ssl-dump-HR <CLIENT_DATA>: VIP: /Common/test-site Client: 198.18.73.4 attempts SSL with ciphers: c024,c028,003d,c026,c02a,006b,006a,c00a,c014,0035,c005,c00f,0039,0038,c023,c027,003c,c025,c029,0067,0040,c009,c013,002f,c004,c00e,0033,0032,c02c,c02b,c030,009d,c02e,c032,009f,00a3,c02f,009c,c02d,c031,009e,00a2,c008,c012,000a,c003,c00d,0016,0013,00ff
#### Client Handshake:
>Dec 17 01:26:08 example-waf01 info tmm1[11161]: Rule /Common/ssl-dump-HR <CLIENT_DATA>: VIP: /Common/test-site Client: 198.18.73.4 successfully negotiates ECDHE-RSA-AES256-GCM-SHA384
#### Client 'Failed':
>Dec 17 01:26:08 example-waf01 info tmm1[11161]: Rule /Common/ssl-dump-HR <CLIENT_DATA>: VIP: /Common/test-site Client: 198.18.73.4 Client using unsupported SSL Handshake using TLSv1, AES256-SHA and 256 bits using the Agent Java/1.5.0_85

In this sense __failed__ means that the handshake violated one of the rules set forth on lines 42-46 of the iRule file.

### Extracting the log files
The easiest way to get log data needed for analysis is to install the irule within a given virtual server, let it "bake" for some time to get the needed log entries. After which extract out the relevant log data:
> cat /var/log/ltm | grep "Rule /Common/ssl-dump-HR" > /tmp/ssl-dump.log 
This will place the file _ssl-dump.log_ in the /tmp directory of your F5. Pull down this fie to your analysis workstation. The "HR" iRule will need to be cleaned up with the included _ssl-dump-log-analyzer.py_ script.

### Generating CSV files for analysis
#### ssl-dump-log-analyzer.py
This script takes the output of the SSL Dump iRule and formats it into 3 different pipe "|" seperated files. These files include:

* Combined File: The raw data from the log reformated for easier readability and machine processing
* Failure File: SSL Connections that would have failed given the rules set forth in the irule.
	* User Agent strings are included in all failures within the failure file for added research
* Cipher File: All client ciphers as presented during the intial handshale. The OpenSSL hex codes are cross referenced with the F5 representation of the cipher. This uses the included openssl-ciphers.tsv file and can be regenerated with the included shell script. 
* Handshake File: All successful client handshakes.

To execute this script:
./ssl-dump-log-analyzer.py --help: general help message
./ssl-dump-log-analyzer.py --version: version info

./ssl-dump-log-analyzer.py <infile> -of <failure file> -oc <cipher file> -oh <handshake file> -o <combined output file>:

This will process <infile> and create the files <failure file> <cipher file> <handshake file> <combined output file> 

#### Example
./ssl-dump-log-analyzer.py ssl-dump.log -of ssl-failure.csv -oc ssl-ciphers.csv -oh ssl-handshakes.csv -o ssl-combined.csv 



