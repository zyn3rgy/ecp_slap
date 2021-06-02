
# ecp_slap
This proof-of-concept for [CVE-2020-0688](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-0688)  includes functions for the scanning and exploitation of a vulnerable on-prem Exchange instance.  

## Usage
**scan** - provide credentials and target information to obtain cookies required for exploitation and saves them to 'cookies.txt'. Also checks for exposure of the Exchange Control Panel (ECP) service for the targeted Exchange server, attempts authentication to this service, and checks for a match of the appropriate VIEWSTATEGENERATOR value. If authentication is successful, output of the session cookie value for serialized payload creation will be be displayed.

**generate** -  provide session cookie value obtained from 'scan' function, as well as a command for code execution. This will format your input for [ysoserial.net](https://github.com/pwntester/ysoserial.net) to generate a serialized payload for code execution. Save the output of ysoserial to a file such as 'payload.txt'.

**exploit** - takes the input of your cookies file obtained while using the 'scan' function with successful authentication, and URL-encodes the contents of your payload file. The exploit conducts the appropriate authenticated request to trigger code execution against vulnerable instances of on-prem Exchange.
```
$./ecp_slap
scan - Scan an Exchange host and obtain cookies needed for exploitation:
./ecp_slap scan -t 10.1.1.5 -d corp.local -u admin -p badpassword 
./ecp_slap scan -t mail.corp.com -d CORP -u admin -p badpassword 

generate - Generate the ysoserial.net command for payload creation:
./ecp_slap generate -s [ASP.NET_SessionId] -c [COMMAND]
./ecp_slap generate -s 81c35474-6a73-4a1c-af45-b3985e7d7ad1 -c "echo test > C:/temp/test.txt"

exploit - Exploitation of a vulnerable Exchange server:
./ecp_slap exploit -t 192.168.5.22 -c cookies.txt -p payload.txt
./ecp_slap exploit -t mail.corp.com -c cookies.txt -p payload.txt

```
## Notes for Exploitation 

If you've verified the version of on-prem Exchange you are attempting to exploit:
1. has ECP authentication exposed from the internal or external network perspective you are testing from 
2. allows the credentials you have to access ECP specifically (https://mail.corp.com/ecp)
3. is a build number which is vulnerable

but you are still not able to verify successful code execution, consider executing simple commands to evaluate if the code execution is working, such as:
- HTTP GET request to your machine with an [lolbin](https://lolbas-project.github.io/)
- DNS query with 'nslookup' to an authoritative DNS server you own
- ping and monitor ICMP 


## Manual Validation and Exploitation of Vulnerability 

Start with the [MSRC security advisory](https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-0688)  which will include specifics about patches and vulnerable versions of on-prem Exchange. Cross-referencing patches with [Microsoft's Exchange build numbers](https://docs.microsoft.com/en-us/exchange/new-features/build-numbers-and-release-dates?view=exchserver-2019) will help determine vulnerability.
To manually reproduce exploitation of this vulneribility, follow the incredible [ZDI write-up](https://www.thezdi.com/blog/2020/2/24/cve-2020-0688-remote-code-execution-on-microsoft-exchange-server-through-fixed-cryptographic-keys).

## GoLang Setup and Compilation

If you choose to compile this project from source, instead of snagging [the compiled release](https://github.com/zyn3rgy/ecp_slap/releases/tag/1.0.0), setting up your Go environment is often as easy as installing GoLang and setting the approriate environment variable. The steps to do so are [documented here](https://medium.com/@saumya.ranjan/how-to-install-go-language-and-set-environment-variables-properly-573222f9ae91).

## To-Do

- scan - add functionality to account for the authenticated Exchange build number
- scan & exploit - account for potential NTLMSSP during non-standard on-prem Exchange authentication
  - code written, logic for this needs to be added to check and authenticate differently in this case


## Credits

- Simon Zuckerbraun / ZDI - for the awesome [write-up](https://www.thezdi.com/blog/2020/2/24/cve-2020-0688-remote-code-execution-on-microsoft-exchange-server-through-fixed-cryptographic-keys) explaining how this exploit works and how easy practical exploitation can be
- [actuated](https://github.com/actuated) - for the troubleshooting, brainstorming, and question answering while scripting this out
