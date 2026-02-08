#!/usr/bin/env ruby
# frozen_string_literal: true

require "ipaddr"
require "optparse"

options = {
  config: "config.toml"
}

OptionParser.new do |opts|
  opts.banner = "Usage: validate_config.rb [options]"
  opts.on("-c", "--config PATH", "Config TOML (default: config.toml)") do |value|
    options[:config] = value
  end
end.parse!

module TomlLite
  module_function

  def parse(path)
    data = {}
    current = data
    File.readlines(path, chomp: true).each do |raw|
      line = raw.split("#", 2).first
      next if line.nil?
      line = line.strip
      next if line.empty?

      if line.start_with?("[") && line.end_with?("]")
        section = line[1..-2].strip
        current = (data[section] ||= {})
        next
      end

      key, value = line.split("=", 2).map(&:strip)
      next if key.nil? || value.nil?
      current[key] = parse_value(value)
    end
    data
  end

  def parse_value(raw)
    return "" if raw.nil?
    value = raw.strip
    if value.start_with?("\"") && value.end_with?("\"")
      return value[1..-2]
    end
    if value.start_with?("[") && value.end_with?("]")
      inner = value[1..-2].strip
      return [] if inner.empty?
      return split_array(inner).map { |item| parse_value(item) }
    end
    return true if value == "true"
    return false if value == "false"
    return value.to_f if value.match?(/\A-?\d+\.\d+\z/)
    return value.to_i if value.match?(/\A-?\d+\z/)

    value
  end

  def split_array(value)
    items = []
    current = +""
    in_quotes = false
    escaped = false

    value.each_char do |char|
      if escaped
        current << char
        escaped = false
        next
      end
      if char == "\\"
        escaped = true
        current << char
        next
      end
      if char == "\""
        in_quotes = !in_quotes
        current << char
        next
      end
      if char == "," && !in_quotes
        items << current.strip
        current = +""
        next
      end
      current << char
    end
    items << current.strip unless current.strip.empty?
    items
  end
end

def validate!(data)
  errors = []

  targets = data.fetch("targets", {})
  allowlist = Array(targets["allowlist"])
  include_targets = Array(targets["include"])
  cidrs = Array(targets["cidrs"])

  if allowlist.empty?
    errors << "targets.allowlist is required"
  else
    allowlist.each do |entry|
      begin
        IPAddr.new(entry.to_s)
      rescue IPAddr::InvalidAddressError
        errors << "Invalid allowlist entry: #{entry}"
      end
    end
  end

  if include_targets.empty? && cidrs.empty?
    errors << "targets.include or targets.cidrs must be set"
  end

  max_hosts = targets["max_hosts"].to_i
  errors << "targets.max_hosts must be >= 1" if max_hosts < 1

  scan = data.fetch("scan", {})
  ports = Array(scan["ports"])
  errors << "scan.ports must contain at least one port" if ports.empty?
  ports.each do |port|
    port_i = port.to_i
    errors << "scan.ports contains invalid port: #{port}" if port_i < 1 || port_i > 65_535
  end

  timeout = scan["timeout_seconds"].to_f
  errors << "scan.timeout_seconds must be > 0" if timeout <= 0

  concurrency = scan["concurrency"].to_i
  errors << "scan.concurrency must be >= 1" if concurrency < 1

  banner_bytes = scan["banner_bytes"].to_i
  errors << "scan.banner_bytes must be >= 0" if banner_bytes < 0

  output = data.fetch("output", {})
  %w[inventory_file report_file report_text_file report_csv_file summary_csv_file].each do |field|
    errors << "output.#{field} is required" if output[field].to_s.empty?
  end

  inference = data.fetch("inference", {})
  errors << "inference.rules_file is required" if inference["rules_file"].to_s.empty?

  errors
end

begin
  data = TomlLite.parse(options[:config])
rescue Errno::ENOENT
  warn "Config file not found: #{options[:config]}"
  exit 2
end

errors = validate!(data)
if errors.empty?
  puts "Config OK: #{options[:config]}"
  exit 0
end

warn "Config errors:"
errors.each { |err| warn "- #{err}" }
exit 2
