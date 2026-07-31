# frozen_string_literal: true

require 'spec_helper'

provider_class = Puppet::Type.type(:sshkey).provider(:augeas)

describe provider_class do
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

  context 'with multiple key types for one host' do
    let(:tmptarget) { aug_fixture('multiple_types') }
    let(:target) { tmptarget.path }

    it 'reports a distinct title and type for each entry' do
      allow(provider_class).to receive(:target).and_return(target)

      expect(provider_class.instances.map(&:title)).to eq(
        [
          'dual.example.com@ssh-rsa',
          'dual.example.com@ssh-ed25519',
          'single.example.com@ssh-rsa',
        ],
      )
    end
  end

  # If another provider for this type is loaded before this module is, Puppet
  # builds the type's feature checks without one for hashed_hostnames, and the
  # hash_hostname parameter gets dropped. Which provider loads first varies by
  # installation and CI happens to get the lucky order, so remove the check to
  # reproduce the unlucky one.
  context 'when the type has no check for the hashed_hostnames feature' do
    around do |example|
      mod = Puppet::Type.type(:sshkey).const_get(:FeatureModule)
      original = mod.instance_method(:hashed_hostnames?) if mod.method_defined?(:hashed_hostnames?)
      mod.send(:remove_method, :hashed_hostnames?) if original
      begin
        example.run
      ensure
        mod.send(:define_method, :hashed_hostnames?, original) if original
      end
    end

    it 'still reports the feature as supported' do
      expect(provider_class.feature?(:hashed_hostnames)).to be true
    end

    it 'keeps the hash_hostname parameter' do
      resource = Puppet::Type.type(:sshkey).new(
        name: 'foo.example.com',
        type: 'ssh-rsa',
        key: 'DEADMEAT',
        hash_hostname: true,
        provider: 'augeas',
      )

      expect(resource[:hash_hostname]).to be true
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
