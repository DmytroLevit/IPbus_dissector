ipbus = Proto("ipbus", "IPBus HAL")

-- IPbus v. 1
local PROTOCOLS = {
 [0x1F] = "Byte Order Transaction",
 [0x3] = "Read",
 [0x8] = "Non-Incremental Read",
 [0x4] = "Write",
 [0x9] = "Non-Incremental Write",
 [0x5] = "RMW",
 [0x6] = "RMW Sum",
 [0x1E] = "Reserved Address Information"}
local DIRECTION = {
 [0] = "Controller-To-Slave",
 [1] = "Slave-To-Controller"}
local LENGTH_CS = {
 [0x1F] = nil,
 [0x3] = 1,
 [0x8] = 1,
 [0x4] = 2,
 [0x9] = 0,
 [0x5] = 3,
 [0x6] = 2,
 [0x1E] = nil}
local LENGTH_SC = {
 [0x1F] = nil,
 [0x3] = 1,
 [0x8] = 0,
 [0x4] = nil,
 [0x9] = nil,
 [0x5] = 1,
 [0x6] = 1,
 [0x1E] = nil}
local ADDR_TABLE = {
 [0x1F] = nil,
 [0x3] = 0,
 [0x8] = 0,
 [0x4] = 1,
 [0x9] = 0,
 [0x5] = 0,
 [0x6] = 0,
 [0x1E] = nil}

-- IPbus v. 2
local PACKET_TYPE = {
 [0x0] = "Control",
 [0x1] = "Status",
 [0x2] = "Re-send request"}
local INFO_CODE = {
 [0x0] = "Request successful",
 [0x1] = "Bad header",
 [0x4] = "Bus error on read",
 [0x5] = "Bus error on write",
 [0x6] = "Bus timeout on read",
 [0x7] = "Bus timeout on write",
 [0xF] = "Outbound request"}
local TYPE_ID = {
 [0x0] = "Read",
 [0x1] = "Write",
 [0x2] = "Non-incrementing read",
 [0x3] = "Non-incrementing write",
 [0x4] = "Read/Modify/Write bits",
 [0x5] = "Read/Modify/Write sum",
 [0x6] = "Configuration space read",
 [0x7] = "Configuration space write"}

function ipbus.dissector(buffer, pinfo, tree)
    local ipbtree = tree:add(ipbus, buffer(), "IPBus Frame")
    local offset = 0
    local endbuf = buffer:len()
    local bit = require("bit")

    repeat
        local word = buffer(offset, 4):le_uint()
        local fr_type = bit.rshift(bit.band(word, 0xF8), 3)

        -- check if transaction consistent with IPbus protocol
        if PROTOCOLS[fr_type] == nil then
            return 0
        end

        local fr_vers = bit.rshift(bit.band(word, 0xF0000000), 28)
        if fr_vers == 0x1 then
        -- IPbus v. 1
            local fr_dir = bit.rshift(bit.band(word, 0x4), 2)
            local length = bit.rshift(bit.band(word, 0x1FF00), 8)
            local tr_id = bit.rshift(bit.band(word, 0xFFE0000), 17)
            local payload_length = 0
            local transaction_length = 0
            
            -- get payload length.
            -- depends on transaction type and direction.
            if fr_dir == 0 then
                payload_length = tonumber(LENGTH_CS[fr_type])
            else
                payload_length = tonumber(LENGTH_SC[fr_type])
            end

            if payload_length ~= nil then
                transaction_length = 4 + payload_length * 4
            else
                transaction_length = 4
            end

            -- print transaction information
            local subtree = ipbtree:add(ipbus, buffer(offset, transaction_length), "Version: 1. "..PROTOCOLS[fr_type].." Access. Length: " .. transaction_length)
            subtree:add(buffer(offset,1) , "Frame type: " .. PROTOCOLS[fr_type] .. " (" .. fr_type .. ")  (mask 0xf8)")
            subtree:add(buffer(offset,1) , "Frame direction: " .. DIRECTION[fr_dir] .. " (" .. fr_dir .. ")  (mask 0x4)")
            subtree:add(buffer(offset + 3, 1), "Frame version: " .. fr_vers .. "  (mask 0xF0)")
            subtree:add(buffer(offset + 2, 2), "Transaction ID: " .. tr_id .. "  (mask 0x0FFE)")
            subtree:add(buffer(offset + 1, 2), "Length: " .. length .. "  (mask 0x01FF)")

            -- payload decoding
            local address = 0
            if payload_length ~= nil then
                if payload_length == 0 then
                    payload_length = length
                end
                for i = 1,payload_length do
                    offset = offset + 4
                    local wordtype = "DATA: "
                    if offset < endbuf then
                        word = buffer(offset, 4):le_uint()
                        -- Address only for controller -> slave
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
        else
        -- IPbus v. 2

            local packet_type = bit.rshift(bit.band(word, 0xF), 0)
            local byte_order_qualifier = bit.rshift(bit.band(word, 0xF0), 4)
            local packet_id = bit.rshift(bit.band(word, 0xFFFF00), 8)

            local frame_header_tree = ipbtree:add(ipbus, buffer(offset, transaction_length), "Version 2.")
            frame_header_tree:add(buffer(offset, 1), "Packet type: " .. PACKET_TYPE[packet_type] .. " ("..packet_type..") (mask 0xF)")
            frame_header_tree:add(buffer(offset + 1, 2), "Packet ID: " .. packet_id)

            repeat
                offset = offset + 4
                if offset < endbuf then
                    word = buffer(offset, 4):le_uint()
                    -- Control packet
                    if packet_type == 0x0 then
                        protocol_version = bit.rshift(bit.band(word, 0xF0000000), 28)
                        local transaction_id = bit.rshift(bit.band(word, 0x0FFF0000), 16)
                        local transaction_length = bit.rshift(bit.band(word, 0x0000FF00), 8)
                        local type_id = bit.rshift(bit.band(word, 0x000000F0), 4)
                        local info_code = bit.rshift(bit.band(word, 0x0000000F), 0)
                        if protocol_version ~= 2 then
                            -- print error here
                        end
                        local transaction_header_tree = frame_header_tree:add(buffer(offset, 4), TYPE_ID[type_id] .. " " .. INFO_CODE[info_code])
                        transaction_header_tree:add(buffer(offset + 2, 2), "ID: " .. transaction_id)
                        transaction_header_tree:add(buffer(offset + 1, 1), "Length: " .. transaction_length)
                        transaction_header_tree:add(buffer(offset + 0, 1), "Type id: " .. TYPE_ID[type_id] .. " (" .. type_id ..")")
                        transaction_header_tree:add(buffer(offset + 0, 1), "Info code: " .. INFO_CODE[info_code] .. " (" .. info_code ..")")
                        
                        -- Read transaction
                        if type_id == 0x0 or type_id == 0x2 or type_id == 0x6 then
                            if info_code == 0x0 then
                                for i = 1, transaction_length do
                                    offset = offset + 4
                                    local wordtype = "DATA: "
                                    if offset < endbuf then
                                        word = buffer(offset, 4):le_uint()
                                        wordtype = "DATA: "
                                        local data_tree = transaction_header_tree:add(buffer(offset, transaction_length * 4), "Transaction")
                                        data_tree:add(buffer(offset, 4), "Data: 0x" .. string.format("%08x", word))
                                    end
                                end
                            end

                            if info_code == 0xF then
                                offset = offset + 4
                                if offset < endbuf then
                                    word = buffer(offset, 4):le_uint()
                                    transaction_header_tree:add(buffer(offset, 4), "Address: 0x" .. string.format("%08x", word))
                                end
                            end
                        end 
                        
                        -- Write transaction
                        if type_id == 0x1 or type_id == 0x3 or type_id == 0x7 then
                            if info_code == 0xF then
                                offset = offset + 1
                                if offset < endbuf then
                                    word = buffer(offset, 4):le_uint()
                                    local data_tree = transaction_header_tree:add(buffer(offset, 4 + transaction_length * 4), "Transaction")
                                    data_tree:add(buffer(offset, 4), "Address: 0x" .. string.format("%08x", word))
                                    for i = 1, transaction_length do
                                        offset = offset + 4
                                        if offset < endbuf then
                                            word = buffer(offset, 4):le_uint()
                                            data_tree:add(buffer(offset, 4), "Data: 0x" .. string.format("%08x", word))
                                        end
                                    end
                                end
                            end
                        end 

                        -- RMW bits
                        if type_id == 0x4 and info_code == 0xF then
                            if (offset + 12) < endbuf then
                                offset = offset + 4
                                word = buffer(offset, 4):le_uint()
                                local data_tree = transaction_header_tree:add(buffer(offset, 12), "Transaction")
                                data_tree:add(buffer(offset, 4), "Address: " .. "0x" .. string.format("%08x", word))
                                offset = offset + 4
                                word = buffer(offset, 4):le_uint()
                                data_tree:add(buffer(offset, 4), "AND: " .. "0x" .. string.format("%08x", word))
                                offset = offset + 4
                                word = buffer(offset, 4):le_uint()
                                data_tree:add(buffer(offset, 4), "OR : " .. "0x" .. string.format("%08x", word))
                            end
                        end

                        -- RMW sum
                        if type_id == 0x5 and info_code == 0xF then
                            if (offset + 8) < endbuf then
                                offset = offset + 4
                                word = buffer(offset, 4):le_uint()
                                local data_tree = transaction_header_tree:add(buffer(offset, 8), "Transaction")
                                data_tree:add(buffer(offset, 4), "Address: " .. "0x" .. string.format("%08x", word))
                                offset = offset + 4
                                word = buffer(offset, 4):le_uint()
                                data_tree:add(buffer(offset, 4), "ADDEND: " .. "0x" .. string.format("%08x", word))
                            end
                        end

                        -- RMW response
                        if (type_id == 0x4 or type_id == 0x5) and info_code == 0x0 then
                            offset = offset + 4
                            if offset < endbuf then
                                word = buffer(offset, 4):le_uint()
                                local data_tree = transaction_header_tree:add(buffer(offset, 4), "Register before modification: " .. "0x" .. string.format("%08x", word))
                            end
                        end 

                    end
                end 
            until (offset + 4) > endbuf
        end
    until (offset + 4) > endbuf
    return 0
end

udp_table = DissectorTable.get("udp.port")
udp_table:add(50001, ipbus)
