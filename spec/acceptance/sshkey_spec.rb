# frozen_string_literal: true

require 'spec_helper_acceptance'
require 'benchmark'

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

        let(:hashed_manifest) do
          <<-EOM
            sshkey { 'convert.example.com':
              ensure       => hashed,
              type         => 'ssh-rsa',
              key          => 'AAAACONVERTKEY',
              host_aliases => ['convertalias.example.com'],
              target       => '#{target}',
              provider     => 'augeas',
            }
          EOM
        end

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

      # Both providers write the same file format, so an entry created by one
      # must be in sync for the other
      context 'augeas-created entries applied with the parsed provider' do
        let(:target) { '/etc/ssh/acceptance_known_hosts_handoff' }

        let(:augeas_manifest) do
          <<-EOM
            sshkey { 'handoff.example.com':
              ensure       => present,
              type         => 'ssh-rsa',
              key          => 'AAAAHANDOFFKEY',
              host_aliases => ['handoffalias.example.com'],
              target       => '#{target}',
              provider     => 'augeas',
            }
          EOM
        end

        let(:parsed_manifest) { augeas_manifest.sub("'augeas'", "'parsed'") }

        it 'creates the entry with augeas' do
          on host, "rm -f #{target}"
          apply_manifest_on(host, augeas_manifest, catch_failures: true)
        end

        it 'is in sync for the parsed provider' do
          apply_manifest_on(host, parsed_manifest, catch_changes: true)
        end
      end

      context 'parsed and augeas providers sharing a target file' do
        let(:target) { '/etc/ssh/acceptance_known_hosts_mixed' }

        let(:manifest) do
          <<-EOM
            sshkey { 'mixedclear.example.com':
              ensure   => present,
              type     => 'ssh-rsa',
              key      => 'AAAAMIXEDCLEAR',
              target   => '#{target}',
              provider => 'parsed',
            }
            sshkey { 'mixedhashed.example.com':
              ensure        => present,
              type          => 'ssh-rsa',
              key           => 'AAAAMIXEDHASHED',
              hash_hostname => true,
              target        => '#{target}',
              provider      => 'augeas',
            }
          EOM
        end

        it 'creates one entry with each provider' do
          on host, "rm -f #{target}"
          apply_manifest_on(host, manifest, catch_failures: true)
          on host, "grep '^mixedclear.example.com ssh-rsa AAAAMIXEDCLEAR$' #{target}"
          on host, "ssh-keygen -F mixedhashed.example.com -f #{target}"
        end

        it 'is idempotent' do
          apply_manifest_on(host, manifest, catch_changes: true)
        end
      end

      # Timings are reported, not asserted: sshkey catalogs of this size have
      # been unusably slow (issue #106), and these numbers make the provider's
      # performance visible in the test output on every run
      context 'with 2000 sshkey resources' do
        let(:count) { 2000 }
        let(:target) { '/etc/ssh/acceptance_known_hosts_perf' }

        let(:manifest) do
          <<-EOM
            Integer[1, #{count}].each |$i| {
              sshkey { "host${i}.perf.example.com":
                ensure   => present,
                type     => 'ssh-rsa',
                key      => "AAAAPERFKEY${i}",
                target   => '#{target}',
                provider => 'augeas',
              }
            }
          EOM
        end

        it 'creates all entries' do
          on host, "rm -f #{target}"
          seconds = Benchmark.realtime do
            apply_manifest_on(host, manifest, catch_failures: true)
          end
          logger.notify(format('sshkey perf: initial apply of %d resources: %.1fs', count, seconds))
          expect(on(host, "wc -l < #{target}").stdout.to_i).to eq(count)
        end

        it 'applies in-sync resources without changes' do
          seconds = Benchmark.realtime do
            apply_manifest_on(host, manifest, catch_changes: true)
          end
          logger.notify(format('sshkey perf: no-op apply of %d resources: %.1fs', count, seconds))
        end
      end
    end
  end
end
