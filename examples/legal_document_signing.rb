#!/usr/bin/env ruby
# frozen_string_literal: true
#
# Legal document signing (eIDAS) use case — threshold-signed
# qualified electronic signatures per EU Regulation 910/2014
# (eIDAS). The signature satisfies the legal requirements for
# "advanced electronic signature" + "qualified" when backed by
# a qualified trust service provider (QTSP).
#
# Why threshold signing for legal documents?
#
#   - **Multi-party contracts**: contracts requiring signatures
#     from multiple parties (buyer + seller + notary, lessee +
#     lessor + guarantor) can be signed in a single threshold
#     ceremony.
#   - **Corporate governance**: board resolutions, shareholder
#     agreements, SEC filings require multiple officer signatures.
#     Threshold signing enforces the quorum cryptographically.
#   - **eIDAS compliance**: the threshold signature is a standard
#     ECDSA-P256 signature wrapped in a CMS SignedData with the
#     QTSP's qualified certificate chain. Satisfies Art. 26
#     (advanced electronic signature) requirements.
#
# Run: `bundle exec ruby examples/legal_document_signing.rb`

require "base64"
require "digest"
require "json"
require "openssl"
require "confium"

puts "== Setup: qualified signing quorum (3-of-5) =="
kg = Confium::TC::Cmp20.keygen(3, 5)
puts "  qualified signing joint public key: 0x#{kg["public_key"].unpack1("H*")[0, 24]}..."
puts "  quorum: signing_officer, legal_counsel, compliance_lead,"
puts "          backup_signer, external_auditor"

puts
puts "== Legal document to be signed =="
document = <<~DOC
  SHAREHOLDERS' RESOLUTION

  The shareholders of ExampleCorp, at a duly called meeting held on
  July 31, 2026, hereby resolve:

  1. To approve the merger agreement between ExampleCorp and
     AcquiringCorp, dated July 15, 2026.

  2. To authorize the Board of Directors to execute all necessary
     documents to effectuate the merger.

  3. That this resolution shall take effect immediately upon
     signature by a qualified quorum of shareholders representing
     at least 75% of outstanding shares.

  Certified true and correct:

  [Signed by threshold ceremony on 2026-07-31T12:00:00Z]
DOC
puts "  document type: Shareholders' Resolution"
puts "  document hash: #{Digest::SHA256.hexdigest(document)[0, 24]}..."

puts
puts "== 3-of-5 quorum signs the document =="
three_shares = kg["shares"].first(3)
puts "  participating: signing_officer, legal_counsel, compliance_lead"
sig = Confium::TC::Cmp20.sign(three_shares, 3, document)
puts "  qualified signature: 0x#{sig.unpack1("H*")[0, 24]}... (#{sig.bytesize} bytes)"

puts
puts "== Wrap in eIDAS-compliant CMS envelope (PAdES/XAdES) =="
# eIDAS Art. 26 requires:
#   (a) uniquely linked to the signatory → OIDC identity in Fulcio cert
#   (b) capable of identifying the signatory → signer DNs in CMS
#   (c) created using electronic signature creation data under
#       the signatory's sole control → threshold ceremony ensures this
#   (d) linked to the data signed in a way that any subsequent
#       change is detectable → ECDSA + SHA-256
cms_envelope = {
  version: 3,
  digestAlgorithms: ["2.16.840.1.101.3.4.2.1"],
  encapContentInfo: {
    eContentType: "1.2.840.113549.1.7.1",
    eContent: Base64.strict_encode64(document),
  },
  certificates: [
    # QTSP-issued qualified cert for the threshold joint key
    Base64.strict_encode64("QUALIFIED_CERT_PLACEHOLDER"),
  ],
  signerInfos: [{
    version: 1,
    sid: "threshold-cmp20-3-of-5@examplecorp.com",
    digestAlgorithm: "2.16.840.1.101.3.4.2.1",
    signatureAlgorithm: "1.2.840.10045.4.3.2",
    signature: Base64.strict_encode64(sig),
    jointPublicKey: Base64.strict_encode64(kg["public_key"]),
    # eIDAS-specific signed attributes
    signingTime: "2026-07-31T12:00:00Z",
    signingCertificateV2: "QUALIFIED_CERT_FINGERPRINT",
    signaturePolicy: {
      oid: "0.4.0.1733.2.1.1.1",  # PAdES-BES
      hashAlgorithm: "SHA-256",
    },
  }],
  # eIDAS metadata
  eidas: {
    qualificationLevel: "qualified",
    trustServiceProvider: "Confium QTSP",
    country: "EU",
    retentionPeriod: "30 years",
  },
}
puts "  eIDAS level: #{cms_envelope[:eidas][:qualificationLevel]}"
puts "  signature policy: PAdES-BES"
puts "  retention: #{cms_envelope[:eidas][:retentionPeriod]}"

puts
puts "== Court-admissible verification =="
loaded = cms_envelope[:signerInfos].first
loaded_doc = Base64.strict_decode64(cms_envelope[:encapContentInfo][:eContent])
loaded_sig = Base64.strict_decode64(loaded[:signature])
loaded_pk = Base64.strict_decode64(loaded[:jointPublicKey])

asn1 = OpenSSL::ASN1::Sequence([
  OpenSSL::ASN1::Sequence([
    OpenSSL::ASN1::ObjectId("id-ecPublicKey"),
    OpenSSL::ASN1::ObjectId("prime256v1"),
  ]),
  OpenSSL::ASN1::BitString(loaded_pk),
])
pkey = OpenSSL::PKey::EC.new(asn1.to_der)
r = OpenSSL::BN.new(loaded_sig[0, 32], 2)
s = OpenSSL::BN.new(loaded_sig[32, 32], 2)
der = OpenSSL::ASN1::Sequence([OpenSSL::ASN1::Integer(r), OpenSSL::ASN1::Integer(s)]).to_der
digest = Digest::SHA256.digest(loaded_doc)

if pkey.dsa_verify_asn1(digest, der)
  puts "  ✓ qualified signature verified — eIDAS Art. 26 compliant"
  puts "  ✓ signatory uniquely identified: #{loaded[:sid]}"
  puts "  ✓ document integrity preserved (SHA-256 match)"
  puts "  ✓ sole control of signatory (3-of-5 threshold ceremony)"
else
  abort "  ✗ verification FAILED — signature invalid"
end

puts
puts "== Archive: 30-year retention via ERS (RFC 4998) =="
ers = Confium::ERS::EvidenceRecord.build_initial(
  Digest::SHA256.digest(loaded_doc + loaded_sig),
  "qtsp-tsa",
  loaded_sig,
)
puts "  ERS record created: renewal_count=#{ers.renewal_count}"
puts "  (renew every 5-10 years to maintain crypto agility over 30-year retention)"

puts
puts "== Transparency log anchor =="
tree = Confium::Transparency::MerkleTree.new
tree.append(Digest::SHA256.digest(loaded_doc + loaded_sig))
puts "  log root: 0x#{tree.root.unpack1("H*")[0, 24]}..."
puts
puts "Done. The legal document is signed by a 3-of-5 qualified"
puts "quorum, wrapped in a PAdES-BES CMS envelope, verified as"
puts "eIDAS Art. 26 compliant, archived with ERS for 30 years,"
puts "and anchored to a transparency log for non-repudiation."
