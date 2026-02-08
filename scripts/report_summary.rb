#!/usr/bin/env ruby
# frozen_string_literal: true

require "json"
require "optparse"

options = {
  input: "output/report.json"
}

OptionParser.new do |opts|
  opts.banner = "Usage: report_summary.rb [options]"
  opts.on("-i", "--input PATH", "Input report.json (default: output/report.json)") do |value|
    options[:input] = value
  end
end.parse!

report = JSON.parse(File.read(options[:input], encoding: "utf-8"))
summary = report.fetch("summary", {})
findings = report.fetch("findings", [])

counts = Hash.new(0)
findings.each do |finding|
  severity = finding.fetch("severity", "unknown").to_s.downcase
  counts[severity] += 1
end

puts "Summary"
puts "Targets: #{summary.fetch("targets", 0)}"
puts "Open ports: #{summary.fetch("open_ports", 0)}"
puts "Findings: #{summary.fetch("findings", 0)}"
puts "Findings by severity: critical #{counts["critical"] || 0}, high #{counts["high"] || 0}, medium #{counts["medium"] || 0}, low #{counts["low"] || 0}, info #{counts["info"] || 0}, unknown #{counts["unknown"] || 0}"
