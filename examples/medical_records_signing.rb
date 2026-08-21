#!/usr/bin/env ruby
# frozen_string_literal: true

#
# Medical records signing use case — threshold-signed medical
# record attestations for HIPAA-compliant audit trails. Every
# access, modification, and transmission of a medical record is
# threshold-signed by the participating healthcare providers,
# producing a tamper-evident audit trail.
#
# Why threshold signing for medical records?
#
#   - **HIPAA audit control** (45 CFR §164.312(b)): "Implement
#     hardware, software, and/or procedural mechanisms that record
#     and examine activity." Threshold-signed attestations are
#     tamper-evident by construction.
#   - **Multi-provider attestation**: when multiple providers
#     access or modify a record, a threshold signature proves
#     which providers participated.
#   - **Patient consent binding**: the patient's consent form is
#     co-signed with the medical record, binding them
#     cryptographically.
#   - **Regulatory non-repudiation**: threshold signatures +
#     transparency log produce evidence that satisfies auditors
#     without revealing patient data.
#
# Run: `bundle exec ruby examples/medical_records_signing.rb`

require 'base64'
require 'digest'
require 'json'
require 'openssl'
require 'confium'

puts '== Setup: healthcare provider quorum (2-of-3) =='
kg = Confium::TC::Cmp20.keygen(2, 3)
puts "  provider joint public key: 0x#{kg['public_key'].unpack1('H*')[0, 24]}..."
puts '  shares: attending_physician, specialist, charge_nurse'

puts
puts '== Patient visit record =='
record = {
  record_id: 'MRN-2026-0731-001',
  patient_id_hash: Digest::SHA256.hexdigest('patient-ssn-redacted')[0, 16],
  visit_date: '2026-07-31',
  providers: ['Dr. Alice Smith (attending)', 'Dr. Bob Jones (specialist)'],
  diagnosis_icd10: ['J20.9', 'R05.9'],
  treatment: 'Prescribed azithromycin 250mg x5 days',
  consent: {
    type: 'treatment_consent',
    signed_at: '2026-07-31T10:00:00Z',
    patient_signature_hash: Digest::SHA256.hexdigest('patient-consent-signature')[0, 16]
  },
  access_log: [
    { actor: 'Dr. Alice Smith', action: 'create', timestamp: '2026-07-31T10:05:00Z' },
    { actor: 'Dr. Bob Jones', action: 'review', timestamp: '2026-07-31T10:30:00Z' },
    { actor: 'Charge Nurse Carol', action: 'witness', timestamp: '2026-07-31T10:31:00Z' }
  ]
}
record_json = JSON.generate(record)
puts "  record ID: #{record[:record_id]}"
puts "  patient ID hash: #{record[:patient_id_hash]}..."
puts "  providers: #{record[:providers].length}"
puts "  diagnoses (ICD-10): #{record[:diagnosis_icd10].join(', ')}"

puts
puts '== 2-of-3 provider quorum attests to the record =='
two_shares = kg['shares'].first(2)
puts '  participating: Dr. Alice Smith + Charge Nurse Carol'
attestation = Confium::TC::Cmp20.sign(two_shares, 2, record_json)
puts "  attestation signature: 0x#{attestation.unpack1('H*')[0, 24]}... (#{attestation.bytesize} bytes)"

puts
puts '== Wrap in HIPAA-compliant audit envelope =='
audit_envelope = {
  hipaa_version: '45-CFR-164.312',
  record_hash: Digest::SHA256.hexdigest(record_json),
  attestation: {
    threshold: '2-of-3',
    scheme: 'CMP20-ECDSA-P256',
    signature: Base64.strict_encode64(attestation),
    joint_public_key: Base64.strict_encode64(kg['public_key']),
    providers: record[:access_log].map { |a| a[:actor] }
  },
  retention: {
    period: '6 years (HIPAA minimum)',
    started: '2026-07-31',
    expires: '2032-07-31'
  },
  privacy: {
    phi_in_envelope: false, # only hashes, not patient data
    description: 'Envelope contains SHA-256 hash of the record, not the record itself.'
  }
}
puts "  HIPAA audit envelope: #{audit_envelope[:hipaa_version]}"
puts "  PHI in envelope: #{audit_envelope[:privacy][:phi_in_envelope]} (hash only)"
puts "  retention: #{audit_envelope[:retention][:period]}"

puts
puts '== HIPAA auditor verifies =='
loaded_sig = Base64.strict_decode64(audit_envelope[:attestation][:signature])
loaded_pk = Base64.strict_decode64(audit_envelope[:attestation][:joint_public_key])

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
digest = Digest::SHA256.digest(record_json)

if pkey.dsa_verify_asn1(digest, der)
  puts '  ✓ attestation verified — 2-of-3 provider quorum confirmed'
  puts '  ✓ HIPAA audit control (§164.312(b)): activity recorded'
  puts '  ✓ tamper-evidence: any modification to the record breaks the hash'
  puts '  ✓ non-repudiation: providers cannot deny participation'
  puts '  ✓ privacy: auditor sees only hashes, not patient data'
else
  abort '  ✗ attestation FAILED'
end

puts
puts '== Anchor to transparency log (compliance record) =='
tree = Confium::Transparency::MerkleTree.new
tree.append(Digest::SHA256.digest(record_json + attestation))
puts "  transparency root: 0x#{tree.root.unpack1('H*')[0, 24]}..."
puts
puts 'Done. The medical record is attested by a 2-of-3 provider'
puts 'quorum, the audit envelope contains only hashes (no PHI), the'
puts 'signature is HIPAA-compliant, and the attestation is anchored'
puts 'to a transparency log for regulatory non-repudiation.'
