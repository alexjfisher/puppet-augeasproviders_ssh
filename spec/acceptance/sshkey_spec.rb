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
