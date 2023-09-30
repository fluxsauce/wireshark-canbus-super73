local super73_proto = Proto("Super73", "Super73 RX CAN Bus")

local fields = {
    id = ProtoField.uint32("super73.id", "ID", base.HEX),
    device_name = ProtoField.string("super73.device", "Device"),
    subdevice_name = ProtoField.string("super73.subdevice", "Subdevice"),
    data_1 = ProtoField.uint8("super73.data_1", "D1", base.HEX),
    data_2 = ProtoField.uint8("super73.data_2", "D2", base.HEX),
    data_3 = ProtoField.uint8("super73.data_3", "D3", base.HEX),
    data_4 = ProtoField.uint8("super73.data_4", "D4", base.HEX),
    data_5 = ProtoField.uint8("super73.data_5", "D5", base.HEX),
    data_6 = ProtoField.uint8("super73.data_6", "D6", base.HEX),
    data_7 = ProtoField.uint8("super73.data_7", "D7", base.HEX),
    data_8 = ProtoField.uint8("super73.data_8", "D8", base.HEX),
    data_ascii = ProtoField.string("super73.data_ascii", "Data ASCII"),
    data_1_2_sum = ProtoField.uint16("super73.data_1_2_sum", "D1D2 Sum", base.DEC),
    data_3_4_sum = ProtoField.uint16("super73.data_3_4_sum", "D3D4 Sum", base.DEC),
    data_5_6_sum = ProtoField.uint16("super73.data_5_6_sum", "D5D6 Sum", base.DEC),
    data_7_8_sum = ProtoField.uint16("super73.data_7_8_sum", "D7D8 Sum", base.DEC),
    speed = ProtoField.string("super73.speed", "Speed"),
    brake = ProtoField.string("super73.brake", "Brake"),
    data_decoded = ProtoField.string("super73.data_decoded", "Data Decoded")
}

local devices = {
    [0x200] = { device = "Controller", subdevice = "Range or ODO?" },
    [0x201] = { device = "Controller", subdevice = "Speed, Brake" },
    [0x202] = { device = "Controller", subdevice = "TBD" },
    [0x210] = {
        request = "Request Data",
        requestor = "Display",
        response = "Response Data",
        respondor = "Controller"
    },
    [0x222] = { device = "Controller", subdevice = "Throttle" },
    [0x300] = { device = "Display", subdevice = "Stats" },
    [0x302] = { device = "Display", subdevice = "TBD" },
    [0x400] = { device = "Battery", subdevice = "Charge Status" },
    [0x401] = { device = "Battery", subdevice = "Voltage, Amperage" },
    [0x402] = { device = "Battery", subdevice = "State of Charge" },
    [0x403] = { device = "Battery", subdevice = "???" },
    [0x404] = { device = "Battery", subdevice = "Temperature" },
    [0x410] = { device = "Battery", subdevice = "Part Number" },
    [0x411] = { device = "Battery", subdevice = "Serial Number" },
    [0x412] = { device = "Battery", subdevice = "Error Statuses" },
    [0x423] = { device = "Battery", subdevice = "Power Off" },
    [0x466] = { device = "Battery", subdevice = "???" },
    [0x64a] = { device = "Controller", subdevice = "?Brake?" },
    [0x74a] = { device = "Aux", subdevice = "???" }
}

local f_can_id = Field.new("can.id")
local f_can_len = Field.new("can.len")

super73_proto.fields = fields

function is_request(frame_length)
    return frame_length == 0
end

function super73_proto.dissector(tvb, pinfo, tree)
    local id = f_can_id().value
    local frame_length = f_can_len().value
    local frame_is_request = is_request(frame_length)

    local data
    
    -- Special case; read padding as data.
    if (frame_is_request) then
        -- TODO: access can.padding somehow
    else
        data = tvb(0, frame_length)
    end

    local subtree = tree:add(super73_proto, tvb)
    subtree:add(fields.id, id)

    local device = devices[id]
    if device then
        -- Device and Subdevice
        if (frame_is_request) then
            subtree:add(fields.device_name, device.request)
            subtree:add(fields.subdevice_name, device.requestor)
        else
            if (device.device) then
                subtree:add(fields.device_name, device.device)
                subtree:add(fields.subdevice_name, device.subdevice)
            else
                -- Response
                subtree:add(fields.device_name, device.response)
                subtree:add(fields.subdevice_name, device.respondor)
            end
        end

        -- Data: ASCII
        if (not frame_is_request) then
            subtree:add(fields.data_ascii, tostring(data:string()))
        end
        -- Data: Hex and Pair Sums
        for i = 1, frame_length do
            subtree:add(fields["data_" .. i], data(i-1, 1))
            if i % 2 == 1 and i < frame_length then -- Check if i is odd and there is a next byte
                local sum = data(i-1, 1):uint() + data(i, 1):uint()
                subtree:add(fields["data_" .. i .. "_" .. i+1 .. "_sum"], sum)
            end
        end

        -- Data: Decoded
        if (id == 0x201) then
            local speed = data(0, 2):le_uint() / 100;
            subtree:add(fields.speed, speed)
            local brake_value = data(4, 1):uint();
            if (brake_value == 0x60) then
                brake = "Off"
            elseif (brake_value == 0x64) then
                brake = "On"
            else
                brake = "Unknown"
            end
            subtree:add(fields.brake, brake)
            subtree:add(fields.data_decoded, "Speed: " .. speed .. " Brake: " .. brake)
        end
    else
        subtree:add(fields.device_name, "Unknown")
        subtree:add(fields.subdevice_name, "Unknown")
    end


end

for id in pairs(devices) do
    DissectorTable.get("can.id"):add(id, super73_proto)
end