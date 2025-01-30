-- Domain packlist for dynamic domainn blacklist on dns serverf via sinholed location to the DNS server 


local function handler()
    domains = {"t.bleed.io", "sliver.bleed.io", "dnscat2.bleed.io"}
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


handler()

