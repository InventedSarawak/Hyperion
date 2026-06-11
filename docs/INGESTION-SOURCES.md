# Ingestion Sources for Hyperion

### 1. National Vulnerability Database (NVD)

The "gold standard" for CVE data maintained by NIST. It provides the official CVE ID, description, and CVSS (Common Vulnerability Scoring System) scores. This is usually the primary source for any vulnerability tool.

### 2. GitHub Advisory Database

Vital for modern software supply chain security. It includes vulnerabilities found in open-source projects hosted on GitHub, often mapping them to specific ecosystem packages (npm, Maven, PyPI, Go).

### 3. CISA Known Exploited Vulnerabilities (KEV) Catalog

Managed by the Cybersecurity and Infrastructure Security Agency. Unlike the NVD, which lists _all_ vulnerabilities, the KEV catalog specifically lists vulnerabilities that are **confirmed to be actively exploited in the wild**, helping users prioritize patching.

### 4. Exploit-DB (Offensive Security)

A CVE isn't always "real" to a developer until they see it working. Ingesting from Exploit-DB allows your platform to link a CVE to actual Proof-of-Concept (PoC) code, which is critical for your **CTF Copilot** feature.

### 5. MITRE CVE List

While the NVD adds analysis, MITRE is the root source where CVE IDs are actually assigned. Pulling directly from MITRE can sometimes give you a "first look" at a new ID before it is fully analyzed by NIST.

### 6. Vendor Security Advisories (VSA)

Major vendors (Microsoft, Red Hat, Cisco, AWS, Linux Kernel) publish their own security advisories. These are often more detailed than general CVE entries, providing specific version ranges, workarounds, and patch links for their specific products.

### 7. OSINT & Mailing Lists (e.g., Full Disclosure)

Many vulnerabilities are discussed in the "Full Disclosure" mailing list or on platforms like Twitter (X) and Mastodon by security researchers weeks before they receive a formal CVE ID. Scraping these or using an RSS feed can give your service a "Zero-Day" edge.

### 8. Package Manager Feeds (npm, PyPI, Rubygems)

To implement the **Blast Radius** feature effectively, you can ingest "metadata" from package managers. This isn't just about vulnerabilities, but about tracking library versions and dependency trees to see which packages are most commonly used and thus most dangerous if a flaw is found.

### 9. Shodan or Censys API

If you want to move from "intelligence" to "active scanning," these services provide data on internet-facing devices. Ingesting this allows you to tell a user: _"CVE-2024-XXXX was just released, and we see 5,000 servers currently running that vulnerable version on the open web."_

### 10. Global Security Database (GSD)

The GSD is a Cloud Security Alliance project that aims to be a faster, community-driven alternative to the traditional CVE system, often providing data in a more machine-readable (JSON) format.
