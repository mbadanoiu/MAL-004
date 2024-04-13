# MAL-004: Command Injection Bypass for CVE-2020-12641 in Roundcube Webmail

A bypass was found for "CVE-2020-12641: Command Injection via "_im_convert_path" in Roundcube Webmail" affecting versions before 1.4.5, 1.3.12.

The php “escapeshellcmd” function, implemented to prevent “CVE-2020-12641: Command Injection via “_im_convert_path” Parameter”, performs insufficient sanitization and therefore this “filter” can be bypassed by using:
- Command specific flags (both Linux and Windows environments)
- Remote SMB paths (only in Windows environments)

A successful attack results in the execution of arbitrary system commands whenever a valid Roundcube user opens a mail containing a non-standard image.

### Vendor Disclosure:

The vendor's disclosure and fix for this vulnerability can be found [here](https://roundcube.net/news/2020/06/02/security-updates-1.4.5-and-1.3.12).

### Why no CVE?

This bypass was included as a "better fix for CVE-2020-12641" and was not given a separete CVE-ID.

### Requirements:

This vulnerability requires:
<br/>
- Access to the Roundcube Webmail installer component
- Waiting for a Roundcube user to open an email containg a non-standard image


### Proof Of Concept:

More details and the exploitation process can be found in this [PDF](https://github.com/mbadanoiu/MAL-004/blob/main/Roundcube%20DIsclosures%20-%20MAL-004.pdf).

### Additional Resources:

Initial [vulnerability (CVE-2020-12641)](https://nvd.nist.gov/vuln/detail/CVE-2020-12641) and [GitHub disclosure](https://github.com/mbadanoiu/CVE-2020-12641)
