#!/usr/bin/env ruby
# frozen_string_literal: true

require "csv"
require "json"
require "optparse"

options = {
  input: "output/report.json",
  report_csv: "output/report.csv",
  summary_csv: "output/summary.csv"
}

OptionParser.new do |opts|
  opts.banner = "Usage: report_to_csv.rb [options]"
  opts.on("-i", "--input PATH", "Input report.json (default: output/report.json)") do |value|
    options[:input] = value
  end
  opts.on("--report-csv PATH", "Output findings CSV (default: output/report.csv)") do |value|
    options[:report_csv] = value
  end
  opts.on("--summary-csv PATH", "Output summary CSV (default: output/summary.csv)") do |value|
    options[:summary_csv] = value
  end
end.parse!

report = JSON.parse(File.read(options[:input], encoding: "utf-8"))
findings = report.fetch("findings", [])
summary = report.fetch("summary", {})

def severity_counts(findings)
  counts = Hash.new(0)
  findings.each do |finding|
    severity = finding.fetch("severity", "unknown").to_s.downcase
    counts[severity] += 1
  end
  %w[critical high medium low info unknown].map { |sev| [sev, counts[sev] || 0] }.to_h
end

CSV.open(options[:report_csv], "w", write_headers: true, headers: [
  "id",
  "title",
  "severity",
  "confidence",
  "host",
  "ip",
  "port",
  "service",
  "description",
  "remediation",
  "banner"
]) do |csv|
  findings.each do |finding|
    target = finding.fetch("target", {})
    evidence = finding.fetch("evidence", {})
    csv << [
      finding.fetch("id", ""),
      finding.fetch("title", ""),
      finding.fetch("severity", ""),
      finding.fetch("confidence", ""),
      target.fetch("host", ""),
      target.fetch("ip", ""),
      target.fetch("port", ""),
      target.fetch("service", ""),
      finding.fetch("description", ""),
      finding.fetch("remediation", ""),
      evidence.fetch("banner", "")
    ]
  end
end

counts = severity_counts(findings)

CSV.open(options[:summary_csv], "w", write_headers: true, headers: [
  "generated_at",
  "targets",
  "open_ports",
  "findings",
  "critical",
  "high",
  "medium",
  "low",
  "info",
  "unknown"
]) do |csv|
  csv << [
    report.fetch("generated_at", ""),
    summary.fetch("targets", 0),
    summary.fetch("open_ports", 0),
    summary.fetch("findings", 0),
    counts.fetch("critical", 0),
    counts.fetch("high", 0),
    counts.fetch("medium", 0),
    counts.fetch("low", 0),
    counts.fetch("info", 0),
    counts.fetch("unknown", 0)
  ]
end

puts "Findings CSV written to: #{options[:report_csv]}"
puts "Summary CSV written to: #{options[:summary_csv]}"
