description = [[
Blah Blah
]]

author = "Rajeev R Menon"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe","discovery"}

local http = require "http"

portrule = function(host,port)
	return (port.number == 80 or port.number == 443)
	and port.protocol == "tcp"
	and (port.service == "http" or port.service == "https")
end


action = function(host,port)
	local response = http.get(host,port,"/xmldata?item=all")
	--print(response["body"])
	if response["status"] == "404"
		or string.match(response["body"], '<RIMP>') == nil
	then
		return "ilo not found"
	end
	return "ilo found"
end
