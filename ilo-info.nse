description = [[
Blah Blah
]]

author = "Rajeev R Menon"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe","discovery","default"}

local http = require "http"
local slaxml = require "slaxml"
local stdnse = require "stdnse"

portrule = function(host,port)
	return (port.number == 80 or port.number == 443)
	and port.protocol == "tcp"
	and (port.service == "http" or port.service == "https")
	and port.state == "open"
end

function getTag(table,tag)
	for _,n in ipairs(table.kids) do
		if n.type == "element" and n.name == tag then
			return n
		elseif n.type == "element" then
			local ret =  getTag(n,tag)
			if ret ~= nil then return ret end
		end
	end
	return nil
end

function parseXML(dom)
	local response = {}
	local info = {}
	info['ServerType '] = getTag(dom,"SPN")
	info['ProductID  '] = getTag(dom,"PRODUCTID")
	info['UUID       '] = getTag(dom,"cUUID")
	info['ILOType    '] = getTag(dom,"PN")
   	info['ILOFirmware'] = getTag(dom,"FWRI")
	for key,_ in pairs(info) do
		if info[key] ~= nil then
			table.insert(response,tostring(key).." : "..info[key].kids[1].value)
		end
	end
	local nicdom = getTag(dom,"NICS")
	if nicdom ~= nil then
		local nics = {}
		nics['name'] = "NICs:"
		local count = 1
		for _,n in ipairs(nicdom.kids) do
			local nic = {}
			info = {}
			nic['name'] = "NIC "..tostring(count)..":"
			count = count + 1
			for k,m in ipairs(n.kids) do
				if m.name == "DESCRIPTION" then
					info["Description"] = m.kids[1].value
				elseif m.name == "MACADDR" then
					info["Mac Address"] = m.kids[1].value
				elseif m.name == "IPADDR" then
					info["IP Address "] = m.kids[1].value
				elseif m.name == "STATUS" then
					info["Status     "] = m.kids[1].value
				end
			end
			for key,_ in pairs(info) do
				table.insert(nic,tostring(key).." : "..info[key])
			end
			table.insert(nics,nic)

		end
		table.insert(response,nics)
	end
	return response
end

action = function(host,port)
	local response = http.get(host,port,"/xmldata?item=all")
	if response["status"] == "404"
		or string.match(response["body"], '<RIMP>') == nil
		or string.match(response["body"], 'iLO') == nil
	then
		return
	end
	local domtable = slaxml.parseDOM(response["body"],{stripWhitespace=true})
	return stdnse.format_output(true, parseXML(domtable))
end
