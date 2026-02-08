#!/usr/bin/env ruby
# frozen_string_literal: true

require "cgi"
require "json"
require "optparse"
require "time"

options = {
  input: "output/report.json",
  output: "output/report.html",
  title: "Auto-Pwn Orchestrator Report"
}

OptionParser.new do |opts|
  opts.banner = "Usage: report_to_html.rb [options]"
  opts.on("-i", "--input PATH", "Input report.json (default: output/report.json)") do |value|
    options[:input] = value
  end
  opts.on("-o", "--output PATH", "Output HTML file (default: output/report.html)") do |value|
    options[:output] = value
  end
  opts.on("-t", "--title TITLE", "Report title") do |value|
    options[:title] = value
  end
end.parse!

def severity_rank(value)
  mapping = {
    "unknown" => 0,
    "info" => 0,
    "low" => 1,
    "medium" => 2,
    "high" => 3,
    "critical" => 4
  }
  return 0 if value.nil?
  mapping.fetch(value.downcase, 0)
end

def severity_counts(findings)
  counts = Hash.new(0)
  findings.each do |finding|
    severity = finding.fetch("severity", "unknown").to_s.downcase
    counts[severity] += 1
  end
  %w[critical high medium low info unknown].map { |sev| [sev, counts[sev] || 0] }.to_h
end

def safe(value)
  CGI.escapeHTML(value.to_s)
end

report = JSON.parse(File.read(options[:input], encoding: "utf-8"))
summary = report.fetch("summary", {})
findings = report.fetch("findings", [])
counts = severity_counts(findings)

sorted_findings = findings.sort_by do |finding|
  target = finding.fetch("target", {})
  [
    -severity_rank(finding.fetch("severity", "")),
    target.fetch("ip", ""),
    target.fetch("port", 0).to_i
  ]
end

rows = sorted_findings.map do |finding|
  target = finding.fetch("target", {})
  evidence = finding.fetch("evidence", {})
  severity = finding.fetch("severity", "unknown").to_s.downcase
  <<~HTML
    <tr class="severity-#{safe(severity)}">
      <td>#{safe(finding.fetch("id", ""))}</td>
      <td>#{safe(finding.fetch("title", ""))}</td>
      <td>#{safe(finding.fetch("severity", ""))}</td>
      <td>#{safe(finding.fetch("confidence", ""))}</td>
      <td>#{safe(target.fetch("host", ""))}</td>
      <td>#{safe(target.fetch("ip", ""))}</td>
      <td>#{safe(target.fetch("port", ""))}</td>
      <td>#{safe(target.fetch("service", ""))}</td>
      <td>#{safe(evidence.fetch("banner", ""))}</td>
      <td>#{safe(finding.fetch("remediation", ""))}</td>
    </tr>
  HTML
end.join

generated_at = report.fetch("generated_at", Time.now.utc.iso8601)

html = <<~HTML
  <!doctype html>
  <html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>#{safe(options[:title])}</title>
    <style>
      :root {
        color-scheme: light;
        --bg: #f4f1eb;
        --surface: #ffffff;
        --ink: #1d1c1a;
        --muted: #6c6a66;
        --accent: #0b7a75;
        --critical: #7f1d1d;
        --high: #9f2d2d;
        --medium: #b45309;
        --low: #1d4ed8;
        --info: #0f766e;
        --unknown: #4b5563;
      }
      body {
        margin: 0;
        font-family: "Source Serif 4", "Iowan Old Style", "Georgia", serif;
        background: radial-gradient(circle at top, #fffaf2, var(--bg));
        color: var(--ink);
      }
      header {
        padding: 32px 24px 12px;
      }
      h1 {
        font-size: 2rem;
        margin: 0 0 8px;
        color: var(--accent);
      }
      .meta {
        color: var(--muted);
        font-size: 0.95rem;
      }
      .summary {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
        gap: 16px;
        padding: 12px 24px 24px;
      }
      .card {
        background: var(--surface);
        border-radius: 16px;
        padding: 16px;
        box-shadow: 0 8px 20px rgba(17, 17, 17, 0.08);
      }
      .card h3 {
        margin: 0 0 6px;
        font-size: 1rem;
        color: var(--muted);
      }
      .card .value {
        font-size: 1.6rem;
        font-weight: 600;
      }
      .counts {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
        gap: 12px;
      }
      .count-pill {
        padding: 10px 12px;
        border-radius: 999px;
        background: #f2eee6;
        text-align: center;
        font-size: 0.9rem;
      }
      main {
        padding: 0 24px 32px;
      }
      table {
        width: 100%;
        border-collapse: collapse;
        background: var(--surface);
        border-radius: 16px;
        overflow: hidden;
        box-shadow: 0 8px 20px rgba(17, 17, 17, 0.08);
      }
      th, td {
        text-align: left;
        padding: 12px 14px;
        border-bottom: 1px solid #eee8dd;
        font-size: 0.92rem;
      }
      th {
        font-size: 0.85rem;
        text-transform: uppercase;
        letter-spacing: 0.06em;
        color: var(--muted);
        background: #faf7f1;
      }
      tr:last-child td {
        border-bottom: none;
      }
      tr.severity-critical td { color: var(--critical); font-weight: 600; }
      tr.severity-high td { color: var(--high); }
      tr.severity-medium td { color: var(--medium); }
      tr.severity-low td { color: var(--low); }
      tr.severity-info td { color: var(--info); }
      tr.severity-unknown td { color: var(--unknown); }
      @media (max-width: 720px) {
        table, thead, tbody, th, td, tr {
          display: block;
        }
        thead {
          display: none;
        }
        tr {
          margin-bottom: 16px;
          border-radius: 12px;
          background: var(--surface);
          box-shadow: 0 6px 14px rgba(17, 17, 17, 0.08);
        }
        td {
          border: none;
          padding: 10px 14px;
        }
        td::before {
          content: attr(data-label);
          display: block;
          font-size: 0.75rem;
          text-transform: uppercase;
          color: var(--muted);
          margin-bottom: 4px;
        }
      }
    </style>
  </head>
  <body>
    <header>
      <h1>#{safe(options[:title])}</h1>
      <div class="meta">Generated at: #{safe(generated_at)}</div>
    </header>
    <section class="summary">
      <div class="card">
        <h3>Targets</h3>
        <div class="value">#{summary.fetch("targets", 0)}</div>
      </div>
      <div class="card">
        <h3>Open Ports</h3>
        <div class="value">#{summary.fetch("open_ports", 0)}</div>
      </div>
      <div class="card">
        <h3>Total Findings</h3>
        <div class="value">#{summary.fetch("findings", 0)}</div>
      </div>
      <div class="card counts">
        <div class="count-pill">Critical: #{counts.fetch("critical", 0)}</div>
        <div class="count-pill">High: #{counts.fetch("high", 0)}</div>
        <div class="count-pill">Medium: #{counts.fetch("medium", 0)}</div>
        <div class="count-pill">Low: #{counts.fetch("low", 0)}</div>
        <div class="count-pill">Info: #{counts.fetch("info", 0)}</div>
        <div class="count-pill">Unknown: #{counts.fetch("unknown", 0)}</div>
      </div>
    </section>
    <main>
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>Title</th>
            <th>Severity</th>
            <th>Confidence</th>
            <th>Host</th>
            <th>IP</th>
            <th>Port</th>
            <th>Service</th>
            <th>Banner</th>
            <th>Remediation</th>
          </tr>
        </thead>
        <tbody>
          #{rows}
        </tbody>
      </table>
    </main>
  </body>
  </html>
HTML

output_path = options[:output]
File.write(output_path, html, mode: "w", encoding: "utf-8")
puts "HTML report written to: #{output_path}"
