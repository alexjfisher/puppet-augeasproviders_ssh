# frozen_string_literal: true

# Alternative Augeas-based providers for Puppet
#
# Copyright (c) 2015-2020 Raphaël Pinson
# Licensed under the Apache License, Version 2.0

require 'puppet/parameter/boolean'

# Patch sshkey type to add feature and associated param
class Puppet::Type::Sshkey
  feature :hashed_hostnames,
          'The provider supports hashed hostnames.'

  # If another provider loaded first, the type's memoized feature module
  # already exists without the hashed_hostnames? predicate, and Puppet would
  # silently strip the hash_hostname parameter. Add the missing predicate,
  # the same way Puppet::Util::ProviderFeatures#feature_module builds it.
  unless feature_module.method_defined?(:hashed_hostnames?)
    hashed_feature = provider_feature(:hashed_hostnames)
    feature_module.send(:define_method, :hashed_hostnames?) do
      (is_a?(Class) ? declared_feature?(:hashed_hostnames) : self.class.declared_feature?(:hashed_hostnames)) || hashed_feature.available?(self)
    end
  end

  newparam(:hash_hostname, parent: Puppet::Parameter::Boolean, boolean: true, required_features: :hashed_hostnames) do
    defaultto false
  end
end

# Patch sshkey's ensure parameter to add hashed value
class Puppet::Type::Sshkey::Ensure
  newvalue(:hashed) do
    current = retrieve
    if current == :absent
      provider.create
    elsif !provider.hashed?
      provider.force_hash
    end
  end

  def insync?(is)
    return true if should == :hashed && is == :present && provider.hashed?

    super
  end
end

raise('Missing augeasproviders_core dependency') if Puppet::Type.type(:augeasprovider).nil?

Puppet::Type.type(:sshkey).provide(:augeas, parent: Puppet::Type.type(:augeasprovider).provider(:default)) do
  desc 'Uses Augeas API to update SSH known_hosts entries'

  has_features :hashed_hostnames

  default_file { '/etc/ssh/ssh_known_hosts' }

  lens { 'Known_Hosts.lns' }

  confine feature: :augeas
  defaultfor feature: :augeas

  def self.instances
    augopen do |aug, _path|
      resources = []
      aug.match('$target/*[label()!="#comment"]').each do |spath|
        name = aug.get(spath)
        # We only list non-hashed entries
        next if hashed?(name)

        aliases = aug.match("#{spath}/alias").map { |apath| aug.get(apath) }
        resources << new(ensure: :present,
                         name: name,
                         type: aug.get("#{spath}/type"),
                         key: aug.get("#{spath}/key"),
                         host_aliases: aliases,
                         hash_hostname: false,
                         target: target)
      end
      resources
    end
  end

  # Read the state of all managed entries in one pass per target file, so
  # that reading each property doesn't have to reopen Augeas and locate the
  # entry again. The property getters fall back to live Augeas lookups when
  # prefetch hasn't run.
  def self.prefetch(resources)
    resources.values.group_by { |resource| target(resource) }.each_value do |group|
      augopen(group.first) do |aug|
        group.each do |resource|
          entry = find_resource(aug, resource[:name])
          resource.provider = if entry.nil?
                                new(ensure: :absent)
                              elsif hashed?(aug.get(entry))
                                prefetched_hashed(aug, resource)
                              else
                                prefetched_clear(aug, resource, entry)
                              end
        end
      end
    rescue Puppet::Error
      # The file failed to load; leave the resources unprefetched so the
      # error is reported per resource, as it is without prefetching
      nil
    end
  end

  def self.prefetched_clear(aug, resource, entry)
    new(ensure: :present,
        name: resource[:name],
        type: aug.get("#{entry}/type"),
        key: aug.get("#{entry}/key"),
        host_aliases: aug.match("#{entry}/alias").map { |apath| aug.get(apath) },
        hashed: false,
        target: target(resource))
  end

  def self.prefetched_hashed(aug, resource)
    # joined_value keeps prefetch reporting exactly what the live getters
    # would, so prefetching only changes performance, not decisions
    type, key = %w[type key].map { |label| joined_value(aug, resource, label) }
    new(ensure: :present,
        name: resource[:name],
        type: type,
        key: key,
        host_aliases: (resource[:host_aliases] || []).select { |a| find_resource(aug, a) },
        hashed: true,
        target: target(resource))
  end

  # A hashed resource is backed by one file entry per hostname (the hashed
  # format allows only one hostname per entry), each duplicating type and
  # key. Report the value shared by all of the entries: if any entry
  # disagrees or is missing, the AND-joined string cannot match the catalog
  # value. For key, a property, the failed insync? comparison then makes the
  # setter re-sync every entry. (type is a namevar parameter in sshkeys_core,
  # so its joined value is only ever reported, never synced.) Shared by the
  # live getter and prefetch so the two cannot drift.
  def self.joined_value(aug, resource, label)
    [resource[:name], resource[:host_aliases]].flatten.compact.map do |h|
      aug.get("#{find_resource(aug, h)}/#{label}")
    end.uniq.join(' AND ')
  end

  # Override self.setvars to set $resource
  def self.setvars(aug, resource = nil)
    aug.set('/augeas/context', "/files#{target(resource)}")
    aug.defnode('target', "/files#{target(resource)}", nil)
    return unless resource

    # HACK: set to /non/existent so that exists? is happy
    path = find_resource(aug, resource[:name]) || '/non/existent'
    aug.defvar('resource', path)
  end

  # Index of the entries of the current target file, memoized so that
  # find_resource doesn't rescan every entry on each lookup. Must be expired
  # (see expire_entry_index) whenever entries are added, removed or renamed,
  # and when the tree is saved: saving reloads it, renumbering entry paths.
  def self.entry_index(aug)
    @entry_index ||= {}
    @entry_index[aug.get('/augeas/context')] ||= build_entry_index(aug)
  end

  def self.build_entry_index(aug)
    index = { clear: {}, hashed: [], resolved: {} }
    aug.match('$target/*[label()!="#comment"]').each_with_index do |entry, position|
      hostnames = aug.get(entry)
      next if hostnames.nil?

      if hashed?(hostnames)
        salt, hostname_digest = decode_hashed_hostname(hostnames)
        next if salt.nil?

        index[:hashed] << [position, entry, salt, hostname_digest]
      else
        # Only the first occurrence of a hostname can match
        index[:clear][hostnames.split(',')[0]] ||= [position, entry]
      end
    end
    index
  end

  # A hashed hostname is |1|base64(salt)|base64(HMAC-SHA1(salt, hostname)).
  # Return nil for anything else - unknown versions, truncated entries,
  # invalid Base64, digests that cannot be an HMAC-SHA1 - so the entry is
  # left alone instead of misinterpreted
  def self.decode_hashed_hostname(hostnames)
    require 'base64'
    fields = hostnames.split[0].split('|')
    return nil unless fields.length == 4 && fields[0] == '' && fields[1] == '1'

    salt = Base64.strict_decode64(fields[2])
    digest = Base64.strict_decode64(fields[3])
    return nil unless digest.bytesize == 20

    [salt, digest]
  rescue ArgumentError
    nil
  end

  # With a path, only that file's entries are forgotten; without one,
  # everything is
  def self.expire_entry_index(path = nil)
    if path
      @entry_index&.delete("/files#{path}")
    else
      @entry_index = nil
    end
  end

  # Instance-side helper for the mutating methods below. Always clears
  # every target's index, unlike the class method's optional path argument;
  # the plural name marks that wider effect.
  def expire_entry_indexes
    self.class.expire_entry_index
  end

  # Resolutions are memoized because matching a hostname against hashed
  # entries costs an HMAC per entry, and each managed hostname is looked
  # up several times per run
  def self.find_resource(aug, hostname)
    index = entry_index(aug)
    return index[:resolved][hostname] if index[:resolved].key?(hostname)

    index[:resolved][hostname] = first_matching_entry(index, hostname)
  end

  # The first entry in file order that matches the hostname wins, whether
  # clear or hashed, just as when scanning the file entry by entry
  def self.first_matching_entry(index, hostname)
    clear_position, clear_entry = index[:clear][hostname]

    index[:hashed].each do |position, entry, salt, hostname_digest|
      break if clear_position && position > clear_position
      return entry if hostname_digest == OpenSSL::HMAC.digest('sha1', salt, hostname)
    end
    clear_entry
  end

  # Saving reloads the tree, which renumbers the entry paths
  def flush
    expire_entry_indexes
    super
  end

  # Is the file configured in the handle's transform? That is the test for
  # "this provider has state about the file": a file that failed to parse
  # is configured but has no tree, and must still be reloaded once another
  # writer has rewritten it.
  def self.transform_includes?(aug, path)
    lens_name = lens[%r{[^.]+}]
    !aug.match("/augeas/load/#{lens_name}/incl[.='#{path}']").empty?
  end

  # Discard everything known about a file another writer has rewritten:
  # saving the stale loaded tree would clobber that writer's changes, and
  # cached load errors would outlive the rewrite. @aug_handler is the
  # shared handle augeasproviders_core 4.x caches on this class; when it
  # isn't open, or the file isn't configured in it, there is no stale
  # state and the next augopen reads the file fresh.
  def self.reload_file(path)
    if @aug_handler.nil?
      # Before 4.0.0, augeasproviders_core cached the handle as @aug, which
      # this method cannot reload. metadata.json requires 4.0.0, but if an
      # older version is used anyway, fail loudly - only for a file the old
      # handle actually has - so the unsupported combination surfaces here
      # instead of as a later save silently discarding the other writer's
      # changes.
      raise(Puppet::Error, "augeasproviders_core >= 4.0.0 is required to reload #{path} after another provider has written it") if !@aug.nil? && transform_includes?(@aug, path)

      expire_entry_index(path)
      return
    end
    unless transform_includes?(@aug_handler, path)
      expire_entry_index(path)
      return
    end

    expire_entry_index
    # Removing the tree first forces the re-parse: load! alone skips files
    # whose recorded mtime looks unchanged, and mtimes have one-second
    # granularity
    @aug_handler.rm("/files#{path}")
    @aug_handler.load!
  end

  # The shared Augeas handle is closed after each Puppet run
  def self.post_resource_eval
    expire_entry_index
    super
  end

  def self.hashed?(string)
    string&.start_with?('|')
  end

  def resource_hashed?(aug)
    self.class.hashed?(aug.get('$resource'))
  end

  def hashed?
    return @property_hash[:hashed] if @property_hash.key?(:hashed)

    augopen do |aug|
      resource_hashed?(aug)
    end
  end

  def exists?
    return @property_hash[:ensure] == :present if @property_hash.key?(:ensure)

    super
  end

  def self.new_hash(hostname)
    require 'securerandom'
    require 'base64'
    salt = SecureRandom.random_bytes(20)
    salt_b64 = Base64.encode64(salt).strip
    hostname_b64 = Base64.encode64(OpenSSL::HMAC.digest('sha1', salt, hostname)).strip
    "|1|#{salt_b64}|#{hostname_b64}"
  end

  def create_entry(aug, name, type, key, hash_hostname, aliases = [])
    seq = next_seq(aug.match('$target/*[label()!="#comment"]'))
    path = "$target/#{seq}"

    if hash_hostname
      aug.defnode('resource', path, self.class.new_hash(name))
    else
      aug.defnode('resource', path, name)
      (aliases || []).each do |a|
        aug.set('$resource/alias[last()+1]', a)
      end
    end
    expire_entry_indexes

    set_value(aug, 'type', type)
    set_value(aug, 'key', key)
  end

  def create
    augopen! do |aug|
      if resource.hash_hostname?
        [resource[:name], resource[:host_aliases]].flatten.compact.each do |h|
          create_entry(aug, h, resource[:type], resource[:key], true)
        end
      else
        create_entry(aug, resource[:name], resource[:type], resource[:key], false, resource[:host_aliases])
      end
    end
  end

  def destroy
    augopen! do |aug|
      if resource_hashed?(aug)
        resource[:host_aliases].each do |a|
          aug.rm(self.class.find_resource(aug, a))
        end
      end
      aug.rm('$resource')
      expire_entry_indexes
    end
  end

  def force_hash
    augopen! do |aug|
      aug.set('$resource', self.class.new_hash(resource[:name]))
      expire_entry_indexes

      # Get existing values
      type = aug.get('$resource/type')
      key = aug.get('$resource/key')

      # Careful: create_entry redefines $resource!
      aliases = aug.match('$resource/alias').map { |apath| aug.get(apath) }
      aug.rm('$resource/alias')

      aliases.each do |a|
        create_entry(aug, a, type, key, true)
      end
    end
  end

  def host_aliases
    return @property_hash[:host_aliases] if @property_hash.key?(:host_aliases)

    augopen do |aug|
      if resource_hashed?(aug)
        # We cannot know about unmanaged aliases when hashed
        resource[:host_aliases].select { |a| self.class.find_resource(aug, a) }
      else
        aug.match('$resource/alias').map do |a|
          aug.get(a)
        end
      end
    end
  end

  def host_aliases=(values)
    augopen! do |aug|
      if resource_hashed?(aug)
        values.each do |v|
          create_entry(aug, v, resource[:type], resource[:key], true) unless self.class.find_resource(aug, v)
        end
      else
        aug.rm('$resource/alias')
        values.each do |v|
          aug.insert('$resource/type', 'alias', true)
          aug.set('$resource/alias[last()]', v)
        end
      end
    end
  end

  def get_value(aug, label)
    if resource_hashed?(aug)
      self.class.joined_value(aug, resource, label)
    else
      aug.get("$resource/#{label}")
    end
  end

  def set_value(aug, label, value)
    raise(Puppet::Error, "#{label} is mandatory") unless value

    aug.set("$resource/#{label}", value.to_s)

    return unless resource_hashed?(aug) && resource[:host_aliases]

    resource[:host_aliases].each do |h|
      aug.set("#{self.class.find_resource(aug, h)}/#{label}", value.to_s)
    end
  end

  def type
    return @property_hash[:type] if @property_hash.key?(:type)

    augopen do |aug|
      get_value(aug, 'type')
    end
  end

  def type=(value)
    augopen! do |aug|
      set_value(aug, 'type', value)
    end
  end

  def key
    return @property_hash[:key] if @property_hash.key?(:key)

    augopen do |aug|
      get_value(aug, 'key')
    end
  end

  def key=(value)
    augopen! do |aug|
      set_value(aug, 'key', value)
    end
  end
end

# Both sshkey providers can manage entries in the same file. The parsed
# provider rewrites the whole file on flush, so any tree the augeas provider
# has loaded for that file goes stale, and saving it would silently discard
# the entries the parsed provider just wrote.
module AugeasprovidersSsh
  # Makes the augeas sshkey provider reload its view of a file after the
  # parsed provider (a ParsedFile provider) has rewritten it
  module SshkeyParsedFlushHook
    def flush_target(target)
      result = super
      Puppet::Type.type(:sshkey).provider(:augeas).reload_file(target)
      result
    end
  end
end

sshkey_parsed = Puppet::Type.type(:sshkey).provider(:parsed)
if sshkey_parsed
  singleton = sshkey_parsed.singleton_class
  singleton.prepend(AugeasprovidersSsh::SshkeyParsedFlushHook) unless singleton.include?(AugeasprovidersSsh::SshkeyParsedFlushHook)
end
