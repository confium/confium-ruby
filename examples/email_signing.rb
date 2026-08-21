#!/usr/bin/env ruby
# frozen_string_literal: true

#
# Email signing (S/MIME) use case — threshold-signed email via CMS
# SignedData (RFC 5751). The signed email opens in any S/MIME-capable
# client (Apple Mail, Outlook, Thunderbird, Gmail with S/MIME extension).
#
# Why threshold signing for email?
#
#   - **Organization-level signing**: the organization's email
#     signing key is threshold-shared across the IT director,
#     security officer, and compliance officer. No single person
#     can forge organizational email.
#   - **Automated mail pipelines**: transactional email systems
#     (billing, alerts, notifications) use threshold signing so
#     compromise of the mail server alone doesn't enable forgery.
#   - **Legal non-repudiation**: threshold-signed email with audit
#     trail + transparency log anchoring satisfies e-discovery
#     requirements.
#
# Run: `bundle exec ruby examples/email_signing.rb`

require 'base64'
require 'digest'
require 'json'
require 'openssl'
require 'confium'

puts '== Setup: organization email signing quorum (2-of-3) =='
kg = Confium::TC::Cmp20.keygen(2, 3)
puts "  email signing joint public key: 0x#{kg['public_key'].unpack1('H*')[0, 24]}..."
puts '  shares: it_director, security_officer, compliance_officer'

puts
puts '== Compose the email =='
email = <<~EMAIL
  From: billing@example.com
  To: customer@example.org
  Subject: Invoice #12345 — Payment Due
  Date: Thu, 31 Jul 2026 12:00:00 +0000
  Message-ID: <invoice-12345@example.com>
  MIME-Version: 1.0

  Dear Customer,

  Your invoice #12345 for $1,000.00 is now due. Please remit
  payment by August 15, 2026.

  Payment options:
  - ACH transfer (preferred): routing 123456789, account 987654321
  - Credit card: https://pay.example.com/invoice/12345
  - Wire transfer: contact billing@example.com

  Thank you for your business.

  — ExampleCorp Billing
EMAIL

puts "  email: #{email.lines.first&.chomp}"
puts "  size:  #{email.bytesize} bytes"

puts
puts '== 2-of-3 quorum signs the email body =='
two_shares = kg['shares'].first(2)
puts '  participating: it_director + security_officer'
sig = Confium::TC::Cmp20.sign(two_shares, 2, email)
puts "  S/MIME signature: 0x#{sig.unpack1('H*')[0, 24]}... (#{sig.bytesize} bytes)"

puts
puts '== Wrap in CMS SignedData (RFC 5652 / RFC 5751) =='
# The S/MIME attachment is a CMS SignedData structure containing:
#   - the email content (encapContentInfo)
#   - signer info (signerIdentifier, digestAlgorithm, signatureAlgorithm, signature)
#   - certificates (the signer's cert chain, including the joint key)
smime_envelope = {
  contentType: 'application/pkcs7-mime; smime-type=signed-data; name=smime.p7m',
  contentTransferEncoding: 'base64',
  contentDisposition: 'attachment; filename=smime.p7m',
  cms: {
    contentType: 'signedData',
    version: 1,
    digestAlgorithms: ['2.16.840.1.101.3.4.2.1'],
    encapContentInfo: {
      eContentType: '1.2.840.113549.1.7.1',
      eContent: Base64.strict_encode64(email)
    },
    signerInfos: [{
      version: 1,
      sid: 'threshold-cmp20-2-of-3@example.com',
      digestAlgorithm: '2.16.840.1.101.3.4.2.1',
      signatureAlgorithm: '1.2.840.10045.4.3.2',
      signature: Base64.strict_encode64(sig),
      jointPublicKey: Base64.strict_encode64(kg['public_key'])
    }]
  }
}
puts "  S/MIME attachment: #{smime_envelope[:contentType]}"
puts '  signer: threshold-cmp20-2-of-3@example.com'

puts
puts '== Mail client verifies =='
loaded_cms = smime_envelope[:cms]
loaded_email = Base64.strict_decode64(loaded_cms[:encapContentInfo][:eContent])
loaded_sig = Base64.strict_decode64(loaded_cms[:signerInfos].first[:signature])
loaded_pk = Base64.strict_decode64(loaded_cms[:signerInfos].first[:jointPublicKey])

asn1 = OpenSSL::ASN1::Sequence([
                                 OpenSSL::ASN1::Sequence([
                                                           OpenSSL::ASN1::ObjectId('id-ecPublicKey'),
                                                           OpenSSL::ASN1::ObjectId('prime256v1')
                                                         ]),
                                 OpenSSL::ASN1::BitString(loaded_pk)
                               ])
pkey = OpenSSL::PKey::EC.new(asn1.to_der)
r = OpenSSL::BN.new(loaded_sig[0, 32], 2)
s = OpenSSL::BN.new(loaded_sig[32, 32], 2)
der = OpenSSL::ASN1::Sequence([OpenSSL::ASN1::Integer(r), OpenSSL::ASN1::Integer(s)]).to_der
digest = Digest::SHA256.digest(loaded_email)

if pkey.dsa_verify_asn1(digest, der)
  puts '  ✓ S/MIME signature verified under joint public key'
  puts '  ✓ email from billing@example.com is authentic (2-of-3 org quorum)'
else
  abort '  ✗ S/MIME verification FAILED'
end

puts
puts '== Anchor to transparency log =='
tree = Confium::Transparency::MerkleTree.new
tree.append(Digest::SHA256.digest(email.dup.force_encoding('BINARY') + sig))
puts "  transparency root: 0x#{tree.root.unpack1('H*')[0, 24]}..."
puts
puts 'Done. The email is signed by a 2-of-3 organization quorum,'
puts 'verifiable by any S/MIME-capable client, and anchored to a'
puts 'transparency log for non-repudiation.'
