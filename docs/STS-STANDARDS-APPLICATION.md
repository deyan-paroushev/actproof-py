# Sovereign Tech Standards Network · Application

**Applicant:** Deyan Paroushev
**Organisation:** Advisa EOOD (Sofia, Bulgaria)
**Submission deadline:** 19 May 2026, 23:59 CEST

---

## Section 1 · Your work as an open source maintainer and the projects you maintain or contribute to

I maintain an open source family of projects built around verifiable evidence receipts. The work is solo. It consists of three artifacts.

**actproof-py** is an MIT-licensed Python library and CLI for canonicalising, hashing, timestamping, anchoring, and verifying evidence receipts. The current public release is v0.1.0 at github.com/deyan-paroushev/actproof-py. It implements RFC 8785 canonicalisation, RFC 3161 timestamp acquisition with a QTSP failover chain (QuoVadis EU as the primary qualified TSA, with Sectigo Qualified, Belgium TSA, and Izenpe as failover candidates plus DigiCert and freetsa as public fallbacks), Algorand ARC-2 disclosed-mode note construction for public-ledger anchoring, and end-to-end verification via a six-check engine that runs every check regardless of earlier failures so an auditor sees the full diagnostic picture. The library ships with 443 passing tests, a Click-based CLI with three commands (anchor, verify, validate), and a signer abstraction whose security contract is enforced at the class system level: any subclass that introduces a raw-byte signing method fails to import, so the prohibition lives in the type system rather than in documentation. The library is intentionally small. Roughly 6,000 lines of source. A single maintainer can hold all of it in their head.

**actproof-events** is the public catalogue of regulated act types that actproof-py validates manifests against. Licensed CC0 for the schema and Apache 2.0 for the reference verifier. v1.4-rc1 shipped on GitHub at github.com/deyan-paroushev/actproof-events with two production entries (EU NIS2 Article 20 management body approval, EU EUDR DDS preparation), computed test vectors, and a federation grammar reserved for v1.5. The catalogue is the load-bearing interoperability artifact: any regulator, audit firm, or downstream verifier can read the schema and reproduce verification without trusting any single platform.

**Quoruna and Klimat** are two downstream applications that consume the same actproof substrate. Quoruna is an AGPL reference web implementation for verifiable decisions in private companies. Klimat is a domain-specific deployment for the EU EUDR compliance pattern. Both supply real implementation pressure: real regulatory evidence patterns, real recipient-confidentiality concerns, real evidence-retention duties. In this application they are present as implementation contexts, not as projects in their own right.

I chose to factor actproof-py out as a separate library after concluding that the standards-implementing substrate is more useful to the open source ecosystem than another vertical web application around it. That decision matters here because it means the maintenance work is on the library and the catalogue, not on the application surfaces. What I maintain, in the sense this program asks about, is actproof-py and actproof-events.

A scale note. These projects are small. actproof-events v1.4-rc1 shipped less than two months ago. actproof-py reached v0.1.0 inside the last week. The maintenance work is genuinely active. The implementer perspective is genuinely missing from the relevant working group rooms. The application stands on those two facts.

## Section 2 · How your work relates to standards-based specifications

The projects implement three IETF artifacts and one Algorand Foundation standard in production code, and track two further IETF documents that are the natural next implementation step.

**RFC 8785, JSON Canonicalization Scheme.** The whole verifiability claim rests on it. A manifest is canonicalised, hashed, and the hash is what gets anchored to the public ledger and timestamped. The actproof-py implementation wraps the rfc8785 library (Trail of Bits) and adds strict-mode discipline on top: floats are rejected because they produce non-reproducible bytes across platforms; out-of-range integers are rejected because they do not survive JSON round-trips. Both failure modes would silently break the verification claim if allowed through. Catching them at canonicalize time, where the error is intelligible, is more useful than catching them at verify time, where the failure is opaque.

**RFC 3161, Internet X.509 Public Key Infrastructure Time-Stamp Protocol.** actproof-py acquires RFC 3161 timestamp tokens via a documented QTSP failover chain. The integration handles TSA-side failures, certificate chain validation, and the operational realities of binding a TSA token into a larger compliance receipt that also includes a blockchain anchor. The combination of an RFC 3161 token with a public-ledger anchor in the same receipt is not well-documented in the existing RFC 3161 literature. The typical use case there is a single timestamp attached to a single document, not a multi-source evidence record where the token is one component among several.

**ARC-2, Algorand transaction note format, disclosed mode.** ARC-2 defines how to encode application data in the 1,024-byte transaction note field. actproof-py builds disclosed-mode notes with explicit act-type tags so a third party can scan the chain for actproof anchors without needing access to the underlying manifest. ARC-2 is a small standard but it intersects directly with how public-ledger anchoring becomes interoperable across implementations.

**draft-ietf-scitt-architecture (RFC-to-be 9943, RFC Editor AUTH48).** The architecture defines an issuer, a signed statement, a transparency service, a receipt, and a verifier. actproof maps onto this architecture cleanly. The catalogue entry types the statement. actproof-py is the issuer-side tooling. The Algorand ledger plus the RFC 3161 TSA together act as the transparency service. The actproof receipt JSON is the receipt. actproof-py's verify command is the verifier. The architecture itself is late-stage and the venue for substantive normative change has closed, but the implementer ecosystem around it is exactly where field reports and interop findings are most useful in the next twelve months.

**draft-ietf-cose-merkle-tree-proofs (COSE Receipts).** The active WG document where SCITT receipt structures are specified. actproof-py currently emits JSON-canonical receipts and reserves discriminator slots for a future COSE_Sign1-based profile. The bridge from JSON receipts to COSE receipts is the largest standards-facing implementation step in the proposed work.

**draft-ietf-scitt-scrapi-09 (SCITT Reference APIs).** The active WG document at IESG evaluation. SCRAPI defines the REST surface for transparency-service interaction. actproof-py does not currently expose a SCRAPI-conformant surface. Producing one as a reference implementation that uses public-ledger anchoring as the underlying transparency mechanism is one of the proposed deliverables.

Where the implementer perspective is missing or underrepresented.

The SCITT Working Group is naturally strongest in software supply-chain contexts. Build provenance, container images, SBOMs, signed releases, vendor transparency services. The working group is populated by participants from large software vendors with operational teams and centralised transparency-service infrastructure. Three perspectives are largely absent from the conversation that I can identify.

The first is EU regulatory evidence exchanged between organisations where the verifier may be an auditor, regulator, insurer, lender, retailer, or future counterparty. These use cases add constraints that are easy to miss from software supply-chain examples: recipient confidentiality, legally careful signature language, external timestamp services with qualified-signature implications, evidence retention measured in years, correction and supersession semantics, and verification without platform accounts.

The second is public-permissionless-ledger anchoring as the transparency service. Most SCITT discussion assumes a centralised transparency service operated by a trusted party. A public ledger raises different questions about persistence, query patterns, note-encoding economics, cost model, and what conformance even means when the service is not operated by anyone in particular. The architecture is silent on whether public-ledger transparency services are acceptable and what their conformance requirements should be.

The third is the small-team and solo-maintainer perspective. Large-vendor SCITT participants design for fleets of services with operational teams and dedicated infrastructure. A solo maintainer cannot build a separate transparency service and must use commodity infrastructure: public QTSPs, public ledgers, public registries. The constraints this imposes on the architecture and on the receipt format are not currently being voiced by anyone in the WG that I can identify.

## Section 3 · What you would aim to work on within the relevant SDO if selected

The proposed work consists of four named deliverables. Primary SDO is the IETF. Primary working group is SCITT. Adjacent work is COSE receipts and SCRAPI.

**Deliverable 1: actproof SCITT implementation report submitted to the SCITT WG.** A written report documenting how actproof-py maps to the SCITT architecture, where the mapping is clean, and where the public-ledger-as-transparency-service pattern, the eIDAS-qualified-timestamp binding, and the EU regulatory-evidence use cases expose specification gaps. The report does not propose new spec text initially. It documents what an EU-compliance implementer perspective brings, in the form an implementer can react to.

**Deliverable 2: minimal COSE_Sign1 plus SCITT bridge prototype in actproof-py.** A working implementation that emits or verifies a minimal COSE_Sign1-compatible envelope or transparent-statement representation against draft-ietf-cose-merkle-tree-proofs. Explicit documentation of what is conformant and what remains profile-specific. Ships as a v2.0 release of actproof-py once draft-ietf-cose-merkle-tree-proofs is stable enough to implement against.

**Deliverable 3: public-ledger transparency-service profile note.** A short technical note explaining the external-ledger-as-transparency-layer pattern and how it interacts with SCITT receipts, RFC 3161 timestamping, receipt verification, and verifier privacy. Discusses Algorand mainnet as a concrete example and addresses the persistence, cost, and conformance questions that the architecture currently leaves open. First venue is the SCITT mailing list. Promotion to an Internet-Draft is a possible follow-on if the discussion warrants it.

**Deliverable 4: conformance vectors for RFC 8785 plus manifest hashing plus receipt verification.** A small conformance suite with NIS2 and EUDR and software-release examples, reproducible by any other implementer without coordination with actproof-py. Submitted to the SCITT WG as input to receipt-profile work and contributed back to the rfc8785 implementer community.

Realistic outputs within the twelve months. One implementation report submitted to the SCITT WG. At least three SCITT mailing-list contributions on architecture-implementer, receipts, and SCRAPI threads. The COSE_Sign1 bridge shipped as actproof-py v2.0. A reproducible conformance suite. One IETF meeting attended in person (IETF 126, Vienna, 18 to 24 July 2026). The next European IETF meeting (IETF 129, July 2027) attended in person if it falls within the engagement.

## Section 4 · Track record as a maintainer and technical authority

The track record below is what I currently hold. It is the basis on which the application asks to be evaluated.

**actproof-py.** MIT-licensed Python library and CLI. v0.1.0 currently on GitHub. 443 passing tests across 11 test modules. Production modules cover canonical-JSON hashing, manifest envelope construction, actproof-events catalogue loading and conformance validation, public-receipt and private-issuer-evidence artifacts with linked storage, RFC 3161 timestamp acquisition with QTSP failover, Algorand ARC-2 disclosed-mode note construction in three operational modes (draft, demo, production), a signer abstraction with class-system-enforced security contract, six-check end-to-end verification, and a Click CLI. Maintained solo.

**actproof-events.** CC0 schema, Apache 2.0 verifier reference. v1.4-rc1 on GitHub with two production catalogue entries (NIS2 Article 20 management body approval, EUDR DDS preparation) and computed test vectors. Schema design, the federation grammar reserved for v1.5, the spec document, and the deprecation path are all maintained solo.

**Quoruna.** AGPL reference web implementation. Implements RFC 8785, RFC 3161, and ARC-2 in production code. The anchoring layer that became the basis for actproof-py was originally built inside Quoruna. The full async-PostgreSQL migration across 73 Python files was completed solo. Maintained solo.

**Klimat.** EUDR-focused deployment of the actproof substrate. Maintained solo.

**Standards experience.** The maintenance work above is what supplies the implementation grounding. I do not have prior IETF participation. I have not previously contributed to an IETF working group or submitted an Internet-Draft. The Sovereign Tech Standards Network's published position is that prior standards experience is not required. The application stands as an implementer-feedback proposal supported by maintained code that already implements the standards in question.

**Academic context.** PhD candidate at Sofia University working on verifiability and governance questions adjacent to the actproof technical work.

## Section 5 · Capacity and availability

**Time commitment.** Ten hours per week on average across the twelve months of the program. actproof-py, actproof-events, Quoruna, and Klimat all consume the same standards surface (RFC 8785, RFC 3161, ARC-2, draft-ietf-scitt-architecture, draft-ietf-cose-merkle-tree-proofs, draft-ietf-scitt-scrapi). The standards engagement proposed in this application is not separate from the maintainer work. It is the mechanism by which the implementations become more interoperable.

**Travel.** Based in Sofia, Bulgaria. I can attend IETF 126 Vienna (18 to 24 July 2026) in person. If the program engagement extends into July 2027, I can attend IETF 129 in person at its European venue. Reimbursement under the program covers travel costs per the announced terms.

**Language.** Native Bulgarian. Fluent English (working language for all professional and academic activity). I do not speak German.

**Payment.** Freelance contractor option. Invoices issued from Advisa EOOD in euros, by bank transfer.

**Communication.** Responsive on email and signed mailing-list contributions. Available for the program's mentoring and community-building components.

## Section 6 · Conflicts and disclosures

No conflicts of interest with Sovereign Tech Agency, its program team, or the relevant working groups. No existing funding from Sovereign Tech for either myself or the projects I maintain.

I have submitted, separately and not in connection with this application, a proposal to the NGI0 Commons Fund for actproof-py development. The ScaleDem Horizon Europe Coordination and Support Action is reviewing a separate piloting application from my organisation. Both are public open source or open research programs whose work would be complementary to the standards engagement proposed here, not duplicative.

---

## Alignment with the program criteria

**Public interest relevance.** Independent verification of compliance evidence using open standards rather than proprietary vendor custody, demonstrated in working code at github.com/deyan-paroushev/actproof-py.

**Proposed work.** The four named deliverables in Section 3, anchored in draft-ietf-cose-merkle-tree-proofs, draft-ietf-scitt-scrapi-09, and the post-AUTH48 SCITT architecture implementer ecosystem.

**Representation gap.** The small-maintainer perspective, the EU regulatory-evidence perspective, and the public-permissionless-ledger transparency-service perspective. None of the three currently has an active voice in SCITT WG conversation.

**Expertise.** Maintained code already shipping at github.com/deyan-paroushev/actproof-py (443 passing tests) and github.com/deyan-paroushev/actproof-events (catalogue v1.4-rc1), implementing RFC 8785, RFC 3161, and ARC-2 in production.
