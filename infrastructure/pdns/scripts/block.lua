-- local pdns = require('pdns')
local socket = require("posix.sys.socket")
local unistd = require("posix.unistd")
local ltn12 = require("ltn12")
local cjson = require("cjson")

local ONNX_INFERENCE_UNIX_SOCKET_EGRESS = "/tmp/onnx-inference-out.sock"
local ONNX_INFERENCE_UNIX_SOCKET_INGRESS = "/tmp/onnx-inference-in.sock"
local EGRESS_INFER_ROUTE = "/onnx/dns"
local INGRESS_INFER_ROUTE = "/onnx/dns/ing"

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

    return { dnsFeatures }
end


local function generateModelFLoatVectors(features)
    local inferenceRequest = {}

    inferenceRequest['Features'] = {}
    local tld = ""; local root = "";
    for _, feature in pairs(features) do
        local indFeature = {}
        table.insert(indFeature, feature['TotalChars'])
        table.insert(indFeature, feature['TotalCharsInSubdomain'])
        table.insert(indFeature, feature['NumberCount'])
        table.insert(indFeature, feature['UCaseCount'])
        table.insert(indFeature, feature['Entropy'])
        table.insert(indFeature, feature['PeriodsInSubDomain'])
        table.insert(indFeature, feature['LongestLabelDomain'])
        table.insert(indFeature, feature['AverageLabelLength'])
        tld = indFeature['Tld']
        root = ""
        table.insert(inferenceRequest['Features'], indFeature)
    end
    return inferenceRequest
end

local DEBUG = false


local function read_json(response)
    local response_data = table.concat(response)
    local json_start = response_data:find("{")
    if json_start then
        local json_response = response_data:sub(json_start)
        local decoded_response, decode_err = cjson.decode(json_response)

        if decoded_response then
            return json_response
        else
            print("Failed to decode JSON:", decode_err)
            return {}
        end
    else
        print("No JSON data found in response")
        return {}
    end
end


local function sendInferenceRequest(inference_request, isEgress)
    local sock_egress_fd = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM, 0)

    if not sock_egress_fd then
        error("Error creating egress socket")
    end

    local success, err = socket.connect(sock_egress_fd, {family = socket.AF_UNIX, path = ONNX_INFERENCE_UNIX_SOCKET_EGRESS})
    if not success then
        error("Failed to connect to socket: " .. err)
    end

    print('connected to sock ', socket)

    local inference_request_payload = cjson.encode(inference_request)

    local request = "POST /onnx/dns HTTP/1.1\r\n" ..
                    "Host: localhost\r\n" ..
                    "Content-Type: application/json\r\n" ..
                    "Content-Length: " .. #inference_request_payload .. "\r\n" ..
                    "\r\n" ..
                    inference_request_payload


    local bytes_sent, send_err = socket.send(sock_egress_fd, request)
    if not bytes_sent then
        error("Failed to send data: " .. send_err)
    end
    local response = {}
    while true do
        local chunk, recv_err = unistd.read(sock_egress_fd, 1024)
        if not chunk or #chunk == 0 then
            break
        end
        table.insert(response, chunk)
        if DEBUG then
            for k, v in pairs(response) do
                print('val inference is ', k, v)
            end
        end
        print(read_json(response))
    end
    unistd.close(sock_egress_fd)
end


local function extractFeaturesAndGetremoteInference(qname)

    local tt = extractFeatures("www.amazon.com")
    local inference_request = generateModelFLoatVectors(tt)

    -- add support for this later
    inference_request['Tld'] = ""
    inference_request['Root'] = ""

    if DEBUG then
        for k, v in pairs(inference_request["Features"]) do
            for _, xx in pairs(v) do
                print(xx)
            end
        end
    end
    return sendInferenceRequest(inference_request, true)
end

local function isDomainBlacklistCache(domain)
    return blacklistPdnsCache[domain] ~= nil
end

sf_grp = newDS()

function getSLD(domain)
    local dn = newDN(domain)
    while dn:countLabels() > 2 do
        dn:chopOff()
    end
    return dn
end


function preresolve(dq)
    local qname = dq.qname:toString()
    --extractFeaturesAndGetremoteInference(qname)
    sf_grp:add(getSLD(qname))
    if dq.isTcp then
        pdnslog("Received query over TCP", pdns.loglevels.Info)
    else
        pdnslog("Received DNS query over recursor for: " .. qname, pdns.loglevels.Info)
    end

    if sf_grp:check(getSLD(qname)) then
     	dq.rcode = pdns.NXDOMAIN
        return true 
    end

    return false
end