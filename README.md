# SpookySSL PCAPs and Network Coverage

> PCAPs or it didn't happen

In the wake of the recently disclosed vulnerability in OpenSSL v3.0 through v3.0.6 (CVE-2022-3602), we have looked into how an exploitation attempt appears 'on the wire'. This repository contains PCAPs of various exploitation scenarios, as well as detection rules for Suricata.

Also included is a PCAP containing the exchange of a legitimate certificate with a punycode-encoded e-mail address in the subject alternative name. We used this pcap to test whether rules do not trigger false positive on certificates that only have a short subject alternative name, instead of a very long one that we would expect in an exploitation attempt.

## PCAPs

We have used the following resources to create PCAP files containing traffic that triggers the OpenSSL CVE-2022-3602 bug:

* https://github.com/DataDog/security-labs-pocs
* https://github.com/colmmacc/CVE-2022-3602


<table>
  <thead>
    <th>PCAP</th>
    <th>Description</th>
  </thead>
  <tbody>
    <tr>
        <td><a href=https://github.com/fox-it/spookyssl-pcaps/raw/main/pcaps/spookyssl-windowscrash.pcap>spookyssl-windowscrash.pcap</a></td>
        <td>Created using the Windows Crash PoC from DataDog</td>
    </tr>
    <tr>
        <td><a href=https://github.com/fox-it/spookyssl-pcaps/raw/main/pcaps/spookyssl-malicious_client.pcap>spookyssl-malicious_client.pcap</a></td>
        <td>Created using the malicious_client PoC from DataDog</td>
    </tr>
    <tr>
        <td><a href=https://github.com/fox-it/spookyssl-pcaps/raw/main/pcaps/spookyssl-malicious_server.pcap>spookyssl-malicious_server.pcap</a></td>
        <td>Created using the malicious_server PoC from DataDog</td>
    </tr>
    <tr>
        <td><a href=https://github.com/fox-it/spookyssl-pcaps/raw/main/pcaps/not-spookyssl-certificate.pcap>not-spookyssl-certificate.pcap</a></td>
        <td>Legitimate punycode certificate (not malicous)</td>
    </tr>
  </tbody>
</table>

## Network Coverage

The following `Suricata` signatures was written to detect the OpenSSL `CVE-2022-3602` bug:

```suricata
alert tls any any -> any any (msg:"FOX-SRT - Exploit - Possible SpookySSL Certificate Observed (CVE-2022-3602)"; \
    flow: established; \
    content:"|2b 06 01 05 05 07 08 09|"; fast_pattern; \
    content:"|06 03 55 1d 1e|"; content:"xn--"; \
    content:!"|81|"; distance:-6; within:1; byte_test:2,>=,500,-6,relative; \
    classtype:attempted-user; priority:3; threshold:type limit, track by_src, count 1, seconds 3600; \
    reference:url, www.openssl.org/news/secadv/20221101.txt; \
    reference:url, https://github.com/fox-it/spookyssl-pcaps; \
    metadata:ids suricata; \
    metadata:created_at 2022-11-02; sid:21004268; rev:3;)
```

To break down the content matches:

 * `|2b 06 01 05 05 07 08 09|` -- Detects the `type-id: 1.3.6.1.5.5.7.8.9 (id-pkix.8.9)` (id-on-SmtpUTF8Mailbox)
 * `|06 03 55 1d 1e|` -- Detects `Extension Id: 2.5.29.30 (id-ce-nameConstraints)` (nameConstraints extension)
 * `"xn--"` -- Detects punycode, in combination with size of the punycode value using a `byte_test` keyword:
   * `byte_test:2,>=,500,-6,relative;`

We also explicitly check for small punycode values, in that case the signature should not trigger using:

 * `content:!"|81|"; distance:-6; within:1;`

## TLSv1.3

The network signatures will not work for sessions using TLSv1.3 as the Certificates are then encrypted.

## Example

You can also see a reset packet in the [spookyssl-windowscrash.pcap](https://github.com/fox-it/spookyssl-pcaps/raw/main/pcaps/spookyssl-windowscrash.pcap) due to the client crashing.

![SpookySSL Wireshark](spookyssl-wireshark.png?raw=true "SpookySSL PCAP")
