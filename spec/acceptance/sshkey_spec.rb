# frozen_string_literal: true

require 'spec_helper_acceptance'

describe 'sshkey provider' do
  hosts.each do |host|
    context "on host #{host}" do
      context 'clear entry with aliases' do
        let(:target) { '/etc/ssh/acceptance_known_hosts_clear' }

        let(:manifest) do
          <<-EOM
            sshkey { 'clear.example.com':
              ensure       => present,
              type         => 'ssh-rsa',
              key          => 'AAAACLEARKEY',
              host_aliases => ['clearalias.example.com'],
              target       => '#{target}',
              provider     => 'augeas',
            }
          EOM
        end

        it 'creates the entry' do
          on host, "rm -f #{target}"
          apply_manifest_on(host, manifest, catch_failures: true)
          on host, "grep '^clear.example.com,clearalias.example.com ssh-rsa AAAACLEARKEY$' #{target}"
        end

        it 'is idempotent' do
          apply_manifest_on(host, manifest, catch_changes: true)
        end
      end

      context 'removing entries' do
        let(:target) { '/etc/ssh/acceptance_known_hosts_remove' }

        let(:present_manifest) do
          <<-EOM
            sshkey { 'keep.example.com':
              ensure   => present,
              type     => 'ssh-rsa',
              key      => 'AAAAKEEPKEY',
              target   => '#{target}',
              provider => 'augeas',
            }
            sshkey { 'remove.example.com':
              ensure   => present,
              type     => 'ssh-rsa',
              key      => 'AAAAREMOVEKEY',
              target   => '#{target}',
              provider => 'augeas',
            }
          EOM
        end

        let(:absent_manifest) do
          <<-EOM
            sshkey { 'keep.example.com':
              ensure   => present,
              type     => 'ssh-rsa',
              key      => 'AAAAKEEPKEY',
              target   => '#{target}',
              provider => 'augeas',
            }
            sshkey { 'remove.example.com':
              ensure   => absent,
              target   => '#{target}',
              provider => 'augeas',
            }
          EOM
        end

        it 'removes only the absent entry' do
          on host, "rm -f #{target}"
          apply_manifest_on(host, present_manifest, catch_failures: true)
          apply_manifest_on(host, absent_manifest, catch_failures: true)
          on host, "grep 'keep.example.com' #{target}"
          on host, "grep 'remove.example.com' #{target}", acceptable_exit_codes: [1]
        end

        it 'is idempotent' do
          apply_manifest_on(host, absent_manifest, catch_changes: true)
        end
      end

      # Purging builds its list of existing keys from the provider, so it only
      # works if each entry reports which key type it is for. Uses the default
      # target, because that is the file purging looks at.
      context 'purging unmanaged entries' do
        let(:target) { '/etc/ssh/ssh_known_hosts' }

        let(:manifest) do
          <<-EOM
            sshkey { 'keep.example.com':
              ensure   => present,
              type     => 'ssh-rsa',
              key      => 'AAAAKEEPKEY',
              provider => 'augeas',
            }
            resources { 'sshkey': purge => true }
          EOM
        end

        it 'removes the unmanaged entry and keeps the declared one' do
          on host, "printf '%s\\n' 'keep.example.com ssh-rsa AAAAKEEPKEY' 'purge.example.com ssh-rsa AAAAPURGEKEY' > #{target}"
          apply_manifest_on(host, manifest, catch_failures: true)
          on host, "grep '^keep.example.com ssh-rsa AAAAKEEPKEY$' #{target}"
          on host, "grep 'purge.example.com' #{target}", acceptable_exit_codes: [1]
        end

        it 'is idempotent' do
          apply_manifest_on(host, manifest, catch_changes: true)
        end
      end

      context 'hashed entry' do
        let(:target) { '/etc/ssh/acceptance_known_hosts_hashed' }

        let(:manifest) do
          <<-EOM
            sshkey { 'hashed.example.com':
              ensure        => present,
              type          => 'ssh-rsa',
              key           => 'AAAAHASHEDKEY',
              hash_hostname => true,
              target        => '#{target}',
              provider      => 'augeas',
            }
          EOM
        end

        it 'creates the entry hashed' do
          on host, "rm -f #{target}"
          apply_manifest_on(host, manifest, catch_failures: true)
          on host, "grep '^|1|.* ssh-rsa AAAAHASHEDKEY$' #{target}"
          on host, "grep 'hashed.example.com' #{target}", acceptable_exit_codes: [1]
        end

        # ssh-keygen -F recomputes the HMAC from the entry's salt, so it only
        # finds the entry if the hash really is of this hostname
        it 'creates a hash that ssh resolves to the hostname' do
          on host, "ssh-keygen -F hashed.example.com -f #{target}"
          on host, "ssh-keygen -F other.example.com -f #{target}", acceptable_exit_codes: [1]
        end

        it 'is idempotent' do
          apply_manifest_on(host, manifest, catch_changes: true)
        end
      end

      context 'converting a clear entry to hashed' do
        let(:target) { '/etc/ssh/acceptance_known_hosts_convert' }

        let(:clear_manifest) do
          <<-EOM
            sshkey { 'convert.example.com':
              ensure       => present,
              type         => 'ssh-rsa',
              key          => 'AAAACONVERTKEY',
              host_aliases => ['convertalias.example.com'],
              target       => '#{target}',
              provider     => 'augeas',
            }
          EOM
        end

        let(:hashed_manifest) { clear_manifest.sub('present', 'hashed') }

        it 'hashes the entry and its alias' do
          on host, "rm -f #{target}"
          apply_manifest_on(host, clear_manifest, catch_failures: true)
          apply_manifest_on(host, hashed_manifest, catch_failures: true)
          expect(on(host, "grep -c '^|1|.* ssh-rsa AAAACONVERTKEY$' #{target}").stdout.to_i).to eq(2)
          on host, "grep 'convert' #{target}", acceptable_exit_codes: [1]
          on host, "ssh-keygen -F convert.example.com -f #{target}"
          on host, "ssh-keygen -F convertalias.example.com -f #{target}"
        end

        it 'is idempotent' do
          apply_manifest_on(host, hashed_manifest, catch_changes: true)
        end
      end

      # This module monkeypatches the shared sshkey type, so prove the stock
      # parsed provider still works with the module loaded
      context 'entries managed with the parsed provider' do
        let(:target) { '/etc/ssh/acceptance_known_hosts_parsed' }

        let(:manifest) do
          <<-EOM
            sshkey { 'parsed.example.com':
              ensure   => present,
              type     => 'ssh-rsa',
              key      => 'AAAAPARSEDKEY',
              target   => '#{target}',
              provider => 'parsed',
            }
          EOM
        end

        let(:modified_manifest) { manifest.sub('AAAAPARSEDKEY', 'AAAAMODIFIEDKEY') }

        let(:absent_manifest) do
          <<-EOM
            sshkey { 'parsed.example.com':
              ensure   => absent,
              type     => 'ssh-rsa',
              target   => '#{target}',
              provider => 'parsed',
            }
          EOM
        end

        it 'creates the entry' do
          on host, "rm -f #{target}"
          apply_manifest_on(host, manifest, catch_failures: true)
          on host, "grep '^parsed.example.com ssh-rsa AAAAPARSEDKEY$' #{target}"
        end

        it 'is idempotent' do
          apply_manifest_on(host, manifest, catch_changes: true)
        end

        it 'modifies the entry' do
          apply_manifest_on(host, modified_manifest, catch_failures: true)
          on host, "grep '^parsed.example.com ssh-rsa AAAAMODIFIEDKEY$' #{target}"
        end

        it 'removes the entry' do
          apply_manifest_on(host, absent_manifest, catch_failures: true)
          on host, "grep 'parsed.example.com' #{target}", acceptable_exit_codes: [1]
        end
      end
    end
  end
end
