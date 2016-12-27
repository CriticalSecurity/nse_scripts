local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local vulns = require('vulns')
local ssh2 = stdnse.silent_require "ssh2"

description = [[
Reports if the ssh2 server supports the diffie-hellman-group1-sha1 key exchange.

OpenSSH developers consider 1024-bit Diffie-Hellman groups 'legacy'.

https://www.openssh.com/legacy.html

]];

---
-- @usage
-- nmap --script ssh2-dh-g1-sha1 target
--
-- @output
-- PORT   STATE SERVICE
-- 22/tcp open  ssh
-- | ssh2-dh-g1-sha1:
-- |   VULNERABLE:
-- |   The ssh2 server supports the diffie-hellman-group1-sha1 key exchange.
-- |     State: VULNERABLE
-- |     Risk factor: Low
-- |     Description:
-- |       Based on the whitepaper (imperfect-forward-secrecy-ccs15.pdf) the author suggests that it is a
-- |       possibility that state-level adversaries would have the resources to perform precomputations
-- |       for at least a small number of 1024-bit Diffie-Hellman groups. This would allow them to break
-- |       any key exchanges made with those groups in close to real time.
-- |
-- |       Using the (Logjam attack against the TLS protocol) as a starting point I added 'Temporal Score Metrics'
-- |       of (E:U/RL:OF/RC:UC) to reach an Overall CVSS Score of 2.9.
-- |
-- |       OpenSSH developers consider 1024-bit Diffie-Hellman groups 'legacy'.
-- |
-- |     References:
-- |       https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2015-4000
-- |       https://weakdh.org/imperfect-forward-secrecy-ccs15.pdf
-- |       https://weakdh.org/
-- |_      https://www.openssh.com/legacy.html
--
---

author = {
    "Avery Rozar",
    "CriticalSecurity",
    "https://www.critical-sec.com",
    "Avery.Rozar@insecure-it.com"
}

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {
    "vuln",
    "safe"
}

portrule = shortport.port_or_service(22, "ssh")

action = function(host, port)

    local dh_g1_sha1 = "diffie-hellman-group1-sha1"
    local kex_algorithms = "kex_algorithms"
    local gibberish = "SSH-2.0-Nmap-SSH2-DH-G1-SHA1\r\n"

    local report = vulns.Report:new(SCRIPT_NAME, host, port)
    local vuln_table = {
        title = "The ssh2 server supports the diffie-hellman-group1-sha1 key exchange.",
        state = vulns.STATE.NOT_VULN,
        risk_factor = "Low",
        description = [[

        Based on the whitepaper (imperfect-forward-secrecy-ccs15.pdf) the author suggests that it is a
        possibility that state-level adversaries would have the resources to perform precomputations
        for at least a small number of 1024-bit Diffie-Hellman groups. This would allow them to break
        any key exchanges made with those groups in close to real time.

        Using the Logjam attack against the TLS protocol as a starting point, I added the
        'Temporal Score Metrics' of (E:U/RL:OF/RC:UC) to reach an Overall CVSS Score of 2.9.

        OpenSSH developers consider 1024-bit Diffie-Hellman groups 'legacy'.
    ]],
        references = {
            'https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2015-4000',
            'https://weakdh.org/imperfect-forward-secrecy-ccs15.pdf',
            'https://weakdh.org/',
            'https://www.openssh.com/legacy.html'
        }
    }

    local s = nmap.new_socket()
    local status = s:connect(host, port)

    if not status then
        return
    end

    status = s:receive_lines(1)
    if not status then
        s:close()
        return
    end

    status = s:send(gibberish)
    if not status then
        s:close()
        return
    end

    local ssh = ssh2.transport
    local pkt = ssh.build(ssh.kex_init())

    status = s:send(pkt)
    if not status then
        s:close()
        return
    end

    local status, response = ssh.receive_packet(s)

    s:close()

    if not status then
        return
    end


    local parse_kex_init = ssh.parse_kex_init(ssh.payload(response))

    if parse_kex_init[kex_algorithms] == dh_g1_sha1 then
        vuln_table.state = vulns.STATE.VULN
    end

    return report:make_output(vuln_table)
end