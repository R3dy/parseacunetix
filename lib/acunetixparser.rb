require 'nokogiri'
class Acunetixparser

	attr_accessor :vulnerabilities, :xml

	def initialize(xml)
		@xml = Nokogiri::XML(xml)
		@vulnerabilities = []
		parse_vulnerabilities
	end

	def uniq_vulns
		@vulnerabilities.map { |v| v[:name].text }.uniq
	end

	private
	def parse_vulnerabilities(container=[])
		@xml.css('ReportItem').map { |vuln|
			hash = {}
			hash[:name] = vuln.css('Name').text
			hash[:description] = vuln.css('Description').text
			hash[:recommendation] = vuln.css('Recommendation').text
			hash[:severity] = set_severity(vuln.attr('color'))
			hash[:cvss] = vuln.css('CVSS').text
			begin
				#host = vuln.css('Request').text.split('Host: ')[1].split('.')[0]
				host = xml.css('StartURL').text.split('.')[0].split('/')[-1]
			rescue
				host = "unknown"
			end
			hash[:asset_identifier] = set_family(host)
			container << hash
		}
		container.uniq.each { |vuln| @vulnerabilities << Vulnerability.new(vuln) }
	end

	def set_severity(color)
		case color
		when "orange"
			return "Medium"
		when "blue"
			return "Low"
		when "red"
			return "High"
		else
			return "Informational"
		end
	end

	def set_family(host)
		case host
		when "genevafedramp1"
			return "Istanbul"
		when "fujifedramp1"
			return "Fuji"
		when "prodsecfedramphelsinki"
			return "Helsinki"
		when "prodsecfedrampistanbul"
			return "Istanbul"
		when "prodsecfedrampjakarta"
			return "Jakarta"
		else
			return "Unknown"
		end
	end



end
