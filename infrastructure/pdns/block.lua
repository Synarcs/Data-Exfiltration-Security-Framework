-- Domain packlist for dynamic domainn blacklist on dns serverf via sinholed location to the DNS server 


function handler()
    domains = {"t.bleed.io", "sliver.bleed.io", "dnscat2.bleed.io"}
    for i = 1, #domains, 1 do
        for dom in string.gmatch(string.lower(domains[i]), ".") do 
            print(dom)
        end 
    end
end


handler()



