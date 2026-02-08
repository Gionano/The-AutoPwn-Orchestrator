#!/usr/bin/env ruby
# frozen_string_literal: true

require "json"
require "optparse"
require "set"
require "time"

options = {
  old: nil,
  new: nil,
  format: "text"
}

OptionParser.new do |opts|
  opts.banner = "Usage: inventory_diff.rb --old OLD.json --new NEW.json [options]"
  opts.on("--old PATH", "Old inventory.json") { |value| options[:old] = value }
  opts.on("--new PATH", "New inventory.json") { |value| options[:new] = value }
  opts.on("--format FORMAT", "Output format: text or json (default: text)") { |value| options[:format] = value }
end.parse!

if options[:old].nil? || options[:new].nil?
  warn "Both --old and --new are required."
  exit 2
end

old_inventory = JSON.parse(File.read(options[:old], encoding: "utf-8"))
new_inventory = JSON.parse(File.read(options[:new], encoding: "utf-8"))

def index_inventory(inventory)
  targets = inventory.fetch("targets", [])
  index = {}
  targets.each do |entry|
    target = entry.fetch("target", {})
    ip = target.fetch("ip", "")
    index[ip] = entry
  end
  index
end

old_index = index_inventory(old_inventory)
new_index = index_inventory(new_inventory)

old_hosts = old_index.keys
new_hosts = new_index.keys

new_only = new_hosts - old_hosts
removed = old_hosts - new_hosts
shared = old_hosts & new_hosts

changes = shared.map do |ip|
  old_entry = old_index.fetch(ip)
  new_entry = new_index.fetch(ip)
  old_ports = old_entry.fetch("open_ports", [])
  new_ports = new_entry.fetch("open_ports", [])
  old_set = old_ports.map { |p| [p.fetch("port", 0).to_i, p.fetch("service", "")] }.to_set
  new_set = new_ports.map { |p| [p.fetch("port", 0).to_i, p.fetch("service", "")] }.to_set
  added = new_set - old_set
  removed_ports = old_set - new_set
  next if added.empty? && removed_ports.empty?
  {
    "ip" => ip,
    "host" => new_entry.fetch("target", {}).fetch("host", ""),
    "added_ports" => added.map { |port, service| { "port" => port, "service" => service } },
    "removed_ports" => removed_ports.map { |port, service| { "port" => port, "service" => service } }
  }
end.compact

diff = {
  "generated_at" => Time.now.utc.iso8601,
  "old" => options[:old],
  "new" => options[:new],
  "new_hosts" => new_only.map { |ip| { "ip" => ip, "host" => new_index.fetch(ip).fetch("target", {}).fetch("host", "") } },
  "removed_hosts" => removed.map { |ip| { "ip" => ip, "host" => old_index.fetch(ip).fetch("target", {}).fetch("host", "") } },
  "changed_hosts" => changes
}

if options[:format] == "json"
  puts JSON.pretty_generate(diff)
  exit 0
end

puts "Inventory Diff"
puts "Old: #{options[:old]}"
puts "New: #{options[:new]}"
puts ""
puts "New hosts: #{diff["new_hosts"].length}"
diff["new_hosts"].each do |host|
  puts "- #{host["ip"]} (#{host["host"]})"
end
puts ""
puts "Removed hosts: #{diff["removed_hosts"].length}"
diff["removed_hosts"].each do |host|
  puts "- #{host["ip"]} (#{host["host"]})"
end
puts ""
puts "Changed hosts: #{diff["changed_hosts"].length}"
diff["changed_hosts"].each do |host|
  puts "- #{host["ip"]} (#{host["host"]})"
  host["added_ports"].each do |port|
    puts "  + port #{port["port"]} #{port["service"]}"
  end
  host["removed_ports"].each do |port|
    puts "  - port #{port["port"]} #{port["service"]}"
  end
end
