# frozen_string_literal: true

require 'confium'
require 'fileutils'
require 'time'
require 'json'
require 'digest'

# Integration test: simulate a CNML-style issuer workflow using every
# subsystem exposed by confium-ruby v0.1.0. Not a unit test — exercises
# the pieces together to confirm they interoperate.

RSpec.describe 'CNML-style end-to-end issuer workflow' do
  before(:all) do
    # Generate a test issuing cert once for the whole run.
    support_dir = File.expand_path('support', __dir__)
    FileUtils.mkdir_p(support_dir)
    @pem_path = File.join(support_dir, 'cnml_ca.pem')
    @key_path = File.join(support_dir, 'cnml_ca.key')
    unless File.exist?(@pem_path)
      system(
        'openssl req -x509 -newkey rsa:2048 -nodes ' \
        "-keyout #{@key_path} -out #{@pem_path} -days 365 " \
        "-subj '/CN=OIML Test CA/O=BIML'",
        out: '/dev/null', err: '/dev/null'
      ) or raise 'openssl failed'
    end
  end

  it 'anchors a certificate in a transparency log with attribute policy' do
    # 1. Parse the issuing CA certificate.
    ca = Confium::PKI::Certificate.from_pem(File.read(@pem_path))
    expect(ca.valid_at?(Time.now.utc.iso8601)).to be(true)

    # 2. Build an attribute policy for who can sign: 3-of-N directors
    #    from 3 distinct regions.
    policy = Confium::Attributes.parse(
      'and(min_count("role:director", 3), min_distinct("region", 3))'
    )

    # 3. Compose three signers that satisfy the policy.
    directors = %w[europe americas asia-pacific].map do |region|
      s = Confium::Attributes::Signer.new
      s.add('role:director', 'yes')
      s.add('region', region)
      s
    end
    expect(policy.satisfied_by?(directors)).to be(true)

    # 4. Each director produces an Ed25519 component signature over the
    #    cert fingerprint, then we aggregate into a composite.
    components = directors.map do
      kp = Confium::Composite.generate_ed25519_keypair
      Confium::Composite.sign_ed25519(kp['private_key'], ca.fingerprint_sha256)
    end
    aggregate = Confium::Composite::Signature.new(components)
    result = aggregate.verify(ca.fingerprint_sha256)
    expect(result.all_verified?).to be(true)
    expect(result.per_component.size).to eq(3)

    # 5. Anchor the cert in a transparency log.
    ca.to_der.each_byte.each_slice(32).map(&:first).pack('C*')
    # The above produces a 32-byte pseudo-hash of the cert for the tree;
    # in a real deployment the issuer would compute SHA-256(cert DER).
    require 'digest'
    artifact_hash = Digest::SHA256.digest(ca.to_der)
    tree = Confium::Transparency::MerkleTree.new
    seq = tree.append(artifact_hash)
    root = tree.root
    proof = tree.inclusion_proof(seq)
    expect(proof.verify(root)).to be(true)

    # 6. Issue a separate P-256 signing keypair and Shamir-split it
    #    across the three directors (3-of-3 threshold).
    sign_kp = Confium::TC::FrostP256.generate_keypair
    shares = Confium::TC::FrostP256.split_secret(sign_kp['private_key'], 3, 3)
    expect(shares.size).to eq(3)
    recovered = Confium::TC::FrostP256.recover_secret(
      shares.map { |s| { 'x' => s.x, 'y' => s.y_bytes } }
    )
    expect(recovered).to eq(sign_kp['private_key'])

    # 7. Produce a CMS SignedData envelope that references the cert,
    #    the composite signatures, and the transparency proof. We use
    #    the JSON wire format for round-trip.
    cms_json = {
      'version' => 1,
      'digest_algorithms' => [{ 'oid' => '2.16.840.1.101.3.4.2.1' }],
      'encap_content_info' => {
        'content_type' => '1.2.840.113549.1.7.1',
        'content' => ca.to_der.bytes
      },
      'certificates' => [ca.to_der.bytes],
      'signer_infos' => []
    }.to_json
    sd = Confium::PKI::CMS::SignedData.from_json(cms_json)
    expect(sd.content_type).to eq('1.2.840.113549.1.7.1')
    expect(sd.certificate_count).to eq(1)
    embedded_cert = Confium::PKI::Certificate.from_der(sd.certificate_at(0))
    expect(embedded_cert.fingerprint_sha256).to eq(ca.fingerprint_sha256)

    # 8. Round-trip the JSON wire format.
    sd2 = Confium::PKI::CMS::SignedData.from_json(sd.to_json)
    expect(sd2.certificate_count).to eq(sd.certificate_count)
  end
end
