-- local pdns = require('pdns')
local socket = require("posix.sys.socket")
local unistd = require("posix.unistd")
local ltn12 = require("ltn12")

local ONNX_INFERENCE_UNIX_SOCKET_EGRESS = "/run/onnx-inference-out.sock"
local ONNX_INFERENCE_UNIX_SOCKET_INGRESS = "/run/onnx-inference-in.sock"

local function preresolve()
end

-- Domain packlist for dynamic domainn blacklist on dns serverf via sinholed location to the DNS server 


local function handler()
    local domains = {"t.bleed.io", "sliver.bleed.io", "dnscat2.bleed.io"}
    for i = 1, #domains, 1 do
        if domains[i] == string.reverse(domains[i]) then
            print('match domain reverse ')
        end
        if string.match(domains[i], "arpa") then
            print("a reverse domain ptr request for domain resolution")
        end
        vv = string.gmatch(string.lower(domains[i]), ".")
        print(vv)
    end
end

local blacklistPdnsCache = {}

local function isDomainBlacklistCache(domain) 
    if blacklistPdnsCache[domain] then
        return true 
    end 
    return false 
end 
 
local function slice(tbl, first, last, step)
    local sliced = {}
    for i = first or 1, last or #tbl, step or 1 do
      sliced[#sliced+1] = tbl[i]
    end
    return table.concat(sliced, '.')
end

local function EntropyLabel(domain)
    local charMap = {} 
    for chars in string.gmatch(domain ,"%a") do 
        if charMap[chars] then 
            charMap[chars] = charMap[chars] + 1 
        else 
            charMap[chars] = 1 
        end 
    end

    local entropy = 0.0
    local ln = #domain
    for k,v in pairs(charMap) do
        p = v / ln
        entropy = entropy - (p * math.log(p, 2))
    end
    return entropy
end

local function extractFeatures(domain)
    local dnsFeatures = {}
    local dnsLabels = {}

    local total_chars = 0 
    local tld = 0
    local TotalCharsInSubdomain = 0 
    local UCaseCount = 0 
    local NumberCount = 0 
    local PeriodsInSubDomain = 0 
    local LongestLabelDomain = 0 

    for label in string.gmatch(domain, '%w+') do
        table.insert(dnsLabels, label)
        local labelLength = 0 
        for _ in string.gmatch(label, '%a') do
            total_chars = total_chars + 1
            labelLength = labelLength + 1
        end 
        LongestLabelDomain = math.max(LongestLabelDomain, labelLength)
        if tld >= 2 then
            TotalCharsInSubdomain = TotalCharsInSubdomain + 1
            for str in string.gmatch(label, '%a') do
                if str.match(str, "%d") then
                    NumberCount = NumberCount + 1
                else if str.match(str, '%u') then
                    UCaseCount = UCaseCount + 1 
                end 
                end
                labelLength = labelLength + 1 
            end
            PeriodsInSubDomain = PeriodsInSubDomain + 1
        end 
        tld = tld + 1
    end 

    dnsFeatures['Fqdn'] = domain 
    dnsFeatures['Tld'] = slice(dnsLabels, #dnsLabels - 1 ,#dnsLabels)
    dnsFeatures['Subdomain'] = slice(dnsLabels, 0 ,#dnsLabels - 2)

    dnsFeatures['TotalChars'] = total_chars
    dnsFeatures['TotalCharsInSubdomain'] = #dnsFeatures['Subdomain']

    dnsFeatures['NumberCount'] = NumberCount
    dnsFeatures['UCaseCount'] = UCaseCount
    dnsFeatures['Entropy'] = EntropyLabel(dnsFeatures['Fqdn'])

    dnsFeatures['Periods'] = #dnsLabels - 1
    dnsFeatures['PeriodsInSubDomain'] = PeriodsInSubDomain - 1
    dnsFeatures['LongestLabelDomain'] = LongestLabelDomain
    dnsFeatures['AverageLabelLength'] = dnsFeatures['LongestLabelDomain'] / #dnsLabels


    print(dnsFeatures['AverageLabelLength'], dnsFeatures['Entropy'])
    return dnsFeatures
end


local tt = extractFeatures("cloud.apple.com")




