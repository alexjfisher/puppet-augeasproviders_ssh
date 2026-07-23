# frozen_string_literal: true

require 'spec_helper'

provider_class = Puppet::Type.type(:sshkey).provider(:augeas)

describe provider_class do
  def hashed_entry_matches?(entry_value, hostname)
    require 'base64'
    _empty, _version, salt64, hash64 = entry_value.split('|')
    Base64.decode64(hash64) == OpenSSL::HMAC.digest('sha1', Base64.decode64(salt64), hostname)
  end

  context 'with empty file' do
    let(:tmptarget) { aug_fixture('empty') }
    let(:target) { tmptarget.path }

    it 'creates simple new hashed entry' do
      apply!(Puppet::Type.type(:sshkey).new(
               name: 'foo.example.com',
               type: 'ssh-rsa',
               key: 'DEADMEAT',
               hash_hostname: :true,
               target: target,
               provider: 'augeas',
             ))

      aug_open(target, 'Known_Hosts.lns') do |aug|
        aug.match('./*[label()!="#comment"]').size.should eq(1)
        aug.get('./1').should =~ %r{^\|1\|}
        aug.get('./1/type').should eq('ssh-rsa')
        aug.get('./1/key').should eq('DEADMEAT')
      end
    end

    it 'creates simple new hashed entry with aliases' do
      apply!(Puppet::Type.type(:sshkey).new(
               name: 'foo.example.com',
               type: 'ssh-rsa',
               key: 'DEADMEAT',
               hash_hostname: :true,
               host_aliases: %w[foo bar],
               target: target,
               provider: 'augeas',
             ))

      aug_open(target, 'Known_Hosts.lns') do |aug|
        aug.match('./*[label()!="#comment"]').size.should eq(3)
        aug.get('./1').should =~ %r{^\|1\|}
        aug.get('./1/type').should eq('ssh-rsa')
        aug.get('./1/key').should eq('DEADMEAT')
        aug.get('./2/key').should eq('DEADMEAT')
        aug.get('./3/key').should eq('DEADMEAT')
      end
    end

    it 'creates simple new clear entry' do
      apply!(Puppet::Type.type(:sshkey).new(
               name: 'bar.example.com',
               type: 'ssh-rsa',
               key: 'DEADMEAT',
               hash_hostname: :false,
               target: target,
               provider: 'augeas',
             ))

      aug_open(target, 'Known_Hosts.lns') do |aug|
        aug.match('./*[label()!="#comment"]').size.should eq(1)
        aug.get('./1').should eq('bar.example.com')
        aug.get('./1/type').should eq('ssh-rsa')
        aug.get('./1/key').should eq('DEADMEAT')
      end
    end

    it 'creates simple new clear entry with aliases' do
      apply!(Puppet::Type.type(:sshkey).new(
               name: 'bar.example.com',
               type: 'ssh-rsa',
               key: 'DEADMEAT',
               host_aliases: %w[foo bar],
               hash_hostname: :false,
               target: target,
               provider: 'augeas',
             ))

      aug_open(target, 'Known_Hosts.lns') do |aug|
        aug.match('./*[label()!="#comment"]').size.should eq(1)
        aug.get('./1').should eq('bar.example.com')
        aug.get('./1/type').should eq('ssh-rsa')
        aug.get('./1/alias[1]').should eq('foo')
        aug.get('./1/alias[2]').should eq('bar')
      end
    end
  end

  context 'with full file' do
    let(:tmptarget) { aug_fixture('full') }
    let(:target) { tmptarget.path }

    it 'lists instances' do
      allow(provider_class).to receive(:target).and_return(target)

      inst = provider_class.instances.map do |p|
        {
          name: p.get(:name),
          type: p.get(:type),
          key: p.get(:key),
          host_aliases: p.get(:host_aliases),
        }
      end

      expect(inst.size).to eq(1)
      expect(inst[0]).to eq(name: 'foo.example.com', type: 'ssh-rsa', key: 'AAAAB3NzaC1yc2EAAAADAQABAAABAQDl1Lw2S7Vgl36/TfP+oeHsoPei1UEl9E8DO2KmSLcf+8HFxPMd/9K0gJwJHKLdNBPwpi/YTsgY0hY7JmrWaZzv6CmrfKTYr/xpCP0yF6hKTv/2JX499CH4Q8rx2mqvI8jI/aQhtRSgWolNMc84jLMwdborGMWGXpIGuneF/hn9BkMTCCWSig8MYcR2IAHzb4rpva3wqH/RpczWRuEtCBPkcvoCFrdBbkpFNSihexIM+y1MPq2a18qA2IcCwl/KUfip16tyrCWkr7tMNBbjx6b1EDurlUX75Gk8KuOVNZcjdgYNQLAC+JeYQkynYz/0hQMBZaHDPrHjhz62WFNdGC+B', host_aliases: ['foo'])
    end

    it 'modifies clear value' do
      apply!(Puppet::Type.type(:sshkey).new(
               name: 'foo.example.com',
               type: 'ssh-rsa',
               key: 'DEADMEAT',
               target: target,
               provider: 'augeas',
             ))

      aug_open(target, 'Known_Hosts.lns') do |aug|
        aug.get('./2/key').should eq('DEADMEAT')
      end
    end

    it 'modifies aliases of clear value' do
      apply!(Puppet::Type.type(:sshkey).new(
               name: 'foo.example.com',
               host_aliases: %w[foo bar],
               target: target,
               provider: 'augeas',
             ))

      aug_open(target, 'Known_Hosts.lns') do |aug|
        aug.match('./2/alias').size.should eq(2)
        aug.get('./2/alias[1]').should eq('foo')
        aug.get('./2/alias[2]').should eq('bar')
      end
    end

    it 'modifies hashed value' do
      apply!(Puppet::Type.type(:sshkey).new(
               name: 'bar.example.com',
               type: 'ssh-rsa',
               key: 'DEADMEAT',
               target: target,
               provider: 'augeas',
             ))

      aug_open(target, 'Known_Hosts.lns') do |aug|
        aug.get('./1/key').should eq('DEADMEAT')
      end
    end

    it 'adds an alias to hashed value' do
      apply!(Puppet::Type.type(:sshkey).new(
               name: 'bar.example.com',
               type: 'ssh-rsa',
               key: 'DEADMEAT',
               host_aliases: ['foo'],
               target: target,
               provider: 'augeas',
             ))

      aug_open(target, 'Known_Hosts.lns') do |aug|
        # Should not add an alias node
        aug.match('./1/alias').size.should eq(0)
        # Should add a new entry
        aug.match('./*[label()!="#comment"]').size.should eq(4)
        aug.get('./4/key').should eq('DEADMEAT')
      end
    end

    it 'updates alias of hashed value' do
      apply!(Puppet::Type.type(:sshkey).new(
               name: 'bar.example.com',
               type: 'ssh-rsa',
               key: 'ABCDE',
               host_aliases: ['qux'],
               target: target,
               provider: 'augeas',
             ))

      aug_open(target, 'Known_Hosts.lns') do |aug|
        aug.match('./*[label()!="#comment"]').size.should eq(3)
        aug.get('./1/key').should eq('ABCDE')
        aug.get('./3/key').should eq('ABCDE')
      end
    end

    it 'hashes existing clear value' do
      apply!(Puppet::Type.type(:sshkey).new(
               name: 'foo.example.com',
               ensure: 'hashed',
               target: target,
               provider: 'augeas',
             ))

      aug_open(target, 'Known_Hosts.lns') do |aug|
        aug.match('./*[label()!="#comment"]').size.should eq(4)
        aug.get('./2').should =~ %r{^\|1\|}
        aug.get('./2/type').should eq('ssh-rsa')
        aug.get('./2/key').should =~ %r{^AAAAB3NzaC1yc2}
        aug.match('./2/alias').size.should eq(0)
        aug.get('./4').should =~ %r{^\|1\|}
        aug.get('./4/type').should eq('ssh-rsa')
        aug.get('./4/key').should =~ %r{^AAAAB3NzaC1yc2}
        expect(hashed_entry_matches?(aug.get('./2'), 'foo.example.com')).to be true
        expect(hashed_entry_matches?(aug.get('./4'), 'foo')).to be true
      end
    end

    it 'removes clear entry' do
      apply!(Puppet::Type.type(:sshkey).new(
               name: 'foo.example.com',
               ensure: 'absent',
               target: target,
               provider: 'augeas',
             ))

      aug_open(target, 'Known_Hosts.lns') do |aug|
        aug.match('./*[label()!="#comment"]').size.should eq(2)
      end
    end

    it 'manages multiple entries in one transaction' do
      apply!(
        Puppet::Type.type(:sshkey).new(
          name: 'foo.example.com',
          type: 'ssh-rsa',
          key: 'DEADMEAT',
          target: target,
          provider: 'augeas',
        ),
        Puppet::Type.type(:sshkey).new(
          name: 'new.example.com',
          type: 'ssh-rsa',
          key: 'FEEDFACE',
          target: target,
          provider: 'augeas',
        ),
        Puppet::Type.type(:sshkey).new(
          name: 'bar.example.com',
          ensure: 'absent',
          host_aliases: ['qux'],
          target: target,
          provider: 'augeas',
        ),
      )

      aug_open(target, 'Known_Hosts.lns') do |aug|
        expect(aug.match('./*[label()!="#comment"]').size).to eq(2)
        expect(aug.get("./*[.='foo.example.com']/key")).to eq('DEADMEAT')
        expect(aug.get("./*[.='new.example.com']/key")).to eq('FEEDFACE')
      end
    end

    it 'removes hashed entry with aliases' do
      apply!(Puppet::Type.type(:sshkey).new(
               name: 'bar.example.com',
               ensure: 'absent',
               host_aliases: ['qux'],
               target: target,
               provider: 'augeas',
             ))

      aug_open(target, 'Known_Hosts.lns') do |aug|
        aug.match('./*[label()!="#comment"]').size.should eq(1)
      end
    end
  end

  context 'with malformed hashed entries' do
    let(:tmptarget) { aug_fixture('malformed') }
    let(:target) { tmptarget.path }

    it 'indexes only well-formed version-1 hashed entries' do
      aug_open(target, 'Known_Hosts.lns') do |aug|
        aug.defvar('target', "/files#{target}")
        index = provider_class.build_entry_index(aug)
        expect(index[:clear].keys).to eq(['foo.example.com'])
        expect(index[:hashed].size).to eq(1)
      end
    end

    it 'manages valid entries and leaves malformed ones alone' do
      apply!(Puppet::Type.type(:sshkey).new(
               name: 'foo.example.com',
               type: 'ssh-rsa',
               key: 'DEADMEAT',
               target: target,
               provider: 'augeas',
             ))

      aug_open(target, 'Known_Hosts.lns') do |aug|
        expect(aug.match('./*[label()!="#comment"]').size).to eq(6)
        expect(aug.get("./*[.='foo.example.com']/key")).to eq('DEADMEAT')
        expect(aug.get("./*[.='|1|dHJ1bmNhdGVk']/key")).to eq('TRUNCATEDKEY')
      end
    end
  end

  describe '.reload_file' do
    around do |example|
      saved = provider_class.instance_variable_get(:@aug_handler)
      example.run
      provider_class.instance_variable_set(:@aug_handler, saved)
      provider_class.instance_variable_set(:@aug, nil)
    end

    def handle_with(path, configured:)
      aug = instance_double(Augeas)
      allow(aug).to receive(:match).with("/augeas/load/Known_Hosts/incl[.='#{path}']")
                                   .and_return(configured ? ['/augeas/load/Known_Hosts/incl'] : [])
      aug
    end

    it 'reloads a file configured in the handle' do
      aug = handle_with('/tmp/foo', configured: true)
      provider_class.instance_variable_set(:@aug_handler, aug)
      allow(aug).to receive(:rm)
      allow(aug).to receive(:load!)

      provider_class.reload_file('/tmp/foo')

      expect(aug).to have_received(:rm).with('/files/tmp/foo')
      expect(aug).to have_received(:load!)
    end

    it 'leaves unconfigured files alone' do
      aug = handle_with('/tmp/foo', configured: false)
      provider_class.instance_variable_set(:@aug_handler, aug)
      provider_class.reload_file('/tmp/foo')
    end

    it 'does nothing when no handle is open' do
      provider_class.instance_variable_set(:@aug_handler, nil)
      expect { provider_class.reload_file('/tmp/foo') }.not_to raise_error
    end

    it 'fails when an old augeasproviders_core has the file configured' do
      provider_class.instance_variable_set(:@aug_handler, nil)
      provider_class.instance_variable_set(:@aug, handle_with('/tmp/foo', configured: true))
      expect { provider_class.reload_file('/tmp/foo') }.to raise_error(Puppet::Error, %r{augeasproviders_core})
    end

    it 'ignores an old-core handle without the file' do
      provider_class.instance_variable_set(:@aug_handler, nil)
      provider_class.instance_variable_set(:@aug, handle_with('/tmp/foo', configured: false))
      expect { provider_class.reload_file('/tmp/foo') }.not_to raise_error
    end
  end

  context 'when sharing a file with the parsed provider' do
    let(:tmptarget) { aug_fixture('empty') }
    let(:target) { tmptarget.path }

    before do
      # The spec harness has no filebucket to back the file up to
      allow(Puppet::Type.type(:sshkey).provider(:parsed)).to receive(:backup_target)
    end

    it 'preserves entries the parsed provider writes mid-run' do
      apply!(
        Puppet::Type.type(:sshkey).new(
          name: 'a1.example.com',
          type: 'ssh-rsa',
          key: 'AAAA_A1',
          target: target,
          provider: 'augeas',
        ),
        Puppet::Type.type(:sshkey).new(
          name: 'p1.example.com',
          type: 'ssh-rsa',
          key: 'AAAA_P1',
          target: target,
          provider: 'parsed',
        ),
        Puppet::Type.type(:sshkey).new(
          name: 'a2.example.com',
          type: 'ssh-rsa',
          key: 'AAAA_A2',
          target: target,
          provider: 'augeas',
        ),
      )

      aug_open(target, 'Known_Hosts.lns') do |aug|
        expect(aug.match('./*[label()!="#comment"]').size).to eq(3)
        expect(aug.get("./*[.='p1.example.com']/key")).to eq('AAAA_P1')
        expect(aug.get("./*[.='a2.example.com']/key")).to eq('AAAA_A2')
      end
    end
  end

  context 'with a file the parsed provider repairs mid-run' do
    # The fixture has an OpenSSH-legal trailing comment the lens rejects,
    # so the augeas provider cannot load it until the parsed provider
    # rewrites the entry
    let(:tmptarget) { aug_fixture('fixable') }
    let(:target) { tmptarget.path }

    before do
      # The spec harness has no filebucket to back the file up to
      allow(Puppet::Type.type(:sshkey).provider(:parsed)).to receive(:backup_target)
    end

    it 'reloads and manages the file once it parses again' do
      apply(
        Puppet::Type.type(:sshkey).new(
          name: 'probe.example.com',
          ensure: 'absent',
          type: 'ssh-rsa',
          target: target,
          provider: 'augeas',
        ),
        Puppet::Type.type(:sshkey).new(
          name: 'fixme.example.com',
          type: 'ssh-rsa',
          key: 'NEWKEY',
          target: target,
          provider: 'parsed',
        ),
        Puppet::Type.type(:sshkey).new(
          name: 'after.example.com',
          type: 'ssh-rsa',
          key: 'AFTERKEY',
          target: target,
          provider: 'augeas',
        ),
      )

      aug_open(target, 'Known_Hosts.lns') do |aug|
        expect(aug.get("./*[.='fixme.example.com']/key")).to eq('NEWKEY')
        expect(aug.get("./*[.='after.example.com']/key")).to eq('AFTERKEY')
      end
    end
  end

  context 'with broken file' do
    let(:tmptarget) { aug_fixture('broken') }
    let(:target) { tmptarget.path }

    it 'fails to load' do
      txn = apply(Puppet::Type.type(:sshkey).new(
                    name: 'foo.example.com',
                    key: 'DEADMEAT',
                    target: target,
                    provider: 'augeas',
                  ))

      expect(txn.any_failed?).not_to eq(nil)
      expect(@logs.first.level).to eq(:err)
      expect(@logs.first.message.include?(target)).to eq(true)
    end
  end
end
