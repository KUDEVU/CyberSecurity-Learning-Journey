# Lab: DNS Exfiltration Detection Using TShark

## Scenario Overview
An alert flagged potential data exfiltration occurring over DNS queries within the network. The goal was to inspect the packet capture (`dns.cap`), identify anomalous query patterns, isolate the attacker's transaction identifiers, and reconstruct the exfiltrated payload.

## Key Investigation Steps
1. **Packet Identification & Initial Filtering:**
   * Examined total packet volume and filtered exclusively for DNS query frames using:
     `tshark -r dns.cap -Y "dns.flags.response == 0"`
   * Observed unusual subdomains under the apex domain `m4lwhere.org`.

2. **Identifying Suspicious Indicators:**
   * Found single-character subdomains being queried sequentially.
   * Isolated the suspicious stream using the transaction ID:
     `0xbeef`

3. **Data Extraction & Reconstruction:**
   * Extracted the individual domain prefixes in chronological order using TShark field filters:
     `tshark -r dns.cap -Y "dns.id == 0xbeef && dns.flags.response == 0" -T fields -e dns.qry.name`
   * Stripped the static base domain and concatenated the encoded character stream.

4. **Decoding & Verification:**
   * Stream analysis revealed Base32 encoding:
     `MZWGCZ33ORUDC427NFZV65BQOVTWQX3XNF2GQMDVG5PXI43IGRZGWII...`
   * Decoded the string to retrieve the hidden flag:
     `flag{th1s_is_t0ugh_with0u7_tsh4rk}`

## Key Commands Cheat Sheet
* Read PCAP with display filter:
  `tshark -r <file.pcap> -Y "<display_filter>"`
* Extract specific field values:
  `tshark -r <file.pcap> -T fields -e <field_name>`
* Filter by DNS query type:
  `tshark -r <file.pcap> -Y "dns.qry.type == 1"`
