ipbus = Proto("ipbus", "IPBus HAL")
local PROTOCOLS = {[0x1F] = "Byte Order Transaction", [0x3] = "Read", [0x8] = "Non-Incremental Read", [0x4] = "Write", [0x9] = "Non-Incremental Write", [0x5] = "RMW", [0x6] = "RMW Sum", [0x1E] = "Reserved Address Information"}
local DIRECTION = {[0] = "Controller-To-Slave", [1] = "Slave-To-Controller"}
local LENGTH_CS = {[0x1F] = nil, [0x3] = 1, [0x8] = 1, [0x4] = 2, [0x9] = 0, [0x5] = 3, [0x6] = 2, [0x1E] = nil}
local LENGTH_SC = {[0x1F] = nil, [0x3] = 1, [0x8] = 0, [0x4] = nil, [0x9] = nil, [0x5] = 1, [0x6] = 1, [0x1E] = nil}
local ADDR_TABLE = {[0x1F] = nil, [0x3] = 0, [0x8] = 0, [0x4] = 1, [0x9] = 0, [0x5] = 0, [0x6] = 0, [0x1E] = nil}

function ipbus.dissector(buffer, pinfo, tree)
    local ipbtree = tree:add(ipbus, buffer(), "IPBus Frame")
    local offset = 0
    local endbuf = buffer:len()
    local bit = require("bit")

    repeat
        local word = buffer(offset, 4):le_uint()
        local fr_type = bit.rshift(bit.band(word, 0xF8), 3)
        if PROTOCOLS[fr_type] == nil then
            return 0
        end
        local fr_dir = bit.rshift(bit.band(word, 0x4), 2)
        local length = bit.rshift(bit.band(word, 0x1FF00), 8)
        local tr_id = bit.rshift(bit.band(word, 0xFFE0000), 17)
        local fr_vers = bit.rshift(bit.band(word, 0xF0000000), 28)
        local data_length = 0
        local transaction_length = 0
        
        if fr_dir == 0 then
            data_length = tonumber(LENGTH_CS[fr_type])
        else
            data_length = tonumber(LENGTH_SC[fr_type])
        end

        if data_length ~= nil then
            transaction_length = 4 + data_length * 4
        else
            transaction_length = 4
        end

        local subtree = ipbtree:add(ipbus, buffer(offset, transaction_length), PROTOCOLS[fr_type].." Access. Length: " .. transaction_length)
        subtree:add(buffer(offset,1) , "Frame type: " .. PROTOCOLS[fr_type] .. " (" .. fr_type .. ")  (mask 0xf8)")
        subtree:add(buffer(offset,1) , "Frame direction: " .. DIRECTION[fr_dir] .. " (" .. fr_dir .. ")  (mask 0x4)")
        subtree:add(buffer(offset + 3, 1), "Frame version: " .. fr_vers .. "  (mask 0xF0)")
        subtree:add(buffer(offset + 2, 2), "Transaction ID: " .. tr_id .. "  (mask 0x0FFE)")
        subtree:add(buffer(offset + 1, 2), "Length: " .. length .. "  (mask 0x01FF)")

        local address = 0
        if data_length ~= nil then
            if data_length == 0 then
                data_length = length
            end
            for i = 1,data_length do
                offset = offset + 4
                local wordtype = "DATA: "
                if offset < endbuf then
                    word = buffer(offset, 4):le_uint()
                    if i == 1 and ADDR_TABLE[fr_type] ~= nil and fr_dir == 0 then
                        wordtype = "ADDR: "
                        address = word
                    else
                        wordtype = "DATA: "
                    end
                    local subsubtree = subtree:add(buffer(offset, 4), wordtype .. "0x" .. string.format("%08x", word))
                end
            end
        end 
        offset = offset + 4
    until (offset + 4) > endbuf
    return 0
end

udp_table = DissectorTable.get("udp.port")
udp_table:add(50001, ipbus)
