#!/usr/bin/env ruby
root = File.dirname(__FILE__)
$:.unshift(File.join(root, 'lib'))

require 'pry'
require 'vulnerability'
require 'acunetixparser'
require 'rubyXL'

report = RubyXL::Workbook.new

ARGV.each do |arg|
	xml = File.open(arg, 'r')
	parser = Acunetixparser.new(xml)
	worksheet = report.add_worksheet(parser.vulnerabilities[0].asset_identifier)

	# Set Header Rows
	worksheet.add_cell(0, 0, "Weakness Name")
	worksheet.add_cell(0, 1, "Weakness Description")
	worksheet.add_cell(0, 2, "Asset Identifier")
	worksheet.add_cell(0, 3, "Original Detection Date")
	worksheet.add_cell(0, 4, "CVSS 2.0")
	worksheet.add_cell(0, 5, "CVSS 3.0")
	worksheet.add_cell(0, 6, "Original Risk Rating")
	worksheet.add_cell(0, 7, "Adjusted Risk Rating")
	worksheet.add_cell(0, 8, "Deviation Rationale")
	worksheet.add_cell(0, 9, "Comments")
	worksheet.add_cell(0, 10, "Recommendation")
	worksheet.add_cell(0, 11, "PRB Created")

	# Set column widths
	worksheet.change_row_bold(0, true)
	worksheet.change_column_width(0, 50)
	worksheet.change_column_width(1, 50)
	worksheet.change_column_width(2, 20)
	worksheet.change_column_width(3, 20)
	worksheet.change_column_width(4, 20)
	worksheet.change_column_width(5, 20)
	worksheet.change_column_width(6, 20)
	worksheet.change_column_width(7, 20)
	worksheet.change_column_width(8, 50)
	worksheet.change_column_width(9, 50)
	worksheet.change_column_width(10, 50)
	worksheet.change_column_width(11, 20)

	parser.vulnerabilities.each_with_index do |vuln, x|
		worksheet.add_cell(x+1, 0, vuln.name)
		worksheet.add_cell(x+1, 1, vuln.description)
		worksheet.add_cell(x+1, 2, vuln.asset_identifier)
		worksheet.add_cell(x+1, 4, vuln.cvss2)
		worksheet.add_cell(x+1, 5, vuln.cvss3)
		worksheet.add_cell(x+1, 6, vuln.severity)
		worksheet.add_cell(x+1, 7, vuln.severity)
		worksheet.add_cell(x+1, 10, vuln.recommendation)
		worksheet[x+1][0].change_text_wrap(true)
		worksheet[x+1][1].change_text_wrap(true)
		worksheet[x+1][10].change_text_wrap(true)
	end
end


report.write("./output.xlsx")
