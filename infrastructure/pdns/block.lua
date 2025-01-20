-- Domain packlist for dynamic domainn blacklist on dns serverf via sinholed location to the DNS server 


function handler()
    domains = {"t.bleed.io", "sliver.bleed.io", "dnscat2.bleed.io"}
    for i = 1, #domains, 1 do
        for dom in string.gmatch(string.lower(domains[i]), ".") do 
            print(dom)
        end
    end
end


function handler ()
    local tt = {}
    for i = 1, 100 do 
        tt[i] = coroutine.create(function (i)
            print("running routine thread" .. i)
            return math.max(i)
        end)
    end 

    for i = 1, 100 do 
        local vv = coroutine.resume(tt[i] , i) 
        print(coroutine.status(tt[i]))
    end 


    local process = {}

    for i =  1, (1 << 19), 2  do 
        process[i] = 1 << i
    end 

    for key, val in pairs(process) do
        if key % 2 == 0  then
            table.remove(process, key) 
        end
    end

end

handler() 
