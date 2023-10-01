local super73_proto = Proto("Super73", "Super73 RX CAN Bus")
local super73_canpad_proto = Proto("Super73CANPadding", "Super73 CAN Padding")

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
    data_1_2_le = ProtoField.uint16("super73.data_1_2_le", "D1D2 LE", base.DEC),
    data_3_4_le = ProtoField.uint16("super73.data_3_4_le", "D3D4 LE", base.DEC),
    data_5_6_le = ProtoField.uint16("super73.data_5_6_le", "D5D6 LE", base.DEC),
    data_7_8_le = ProtoField.uint16("super73.data_7_8_le", "D7D8 LE", base.DEC),
    speed = ProtoField.string("super73.speed", "Speed"),
    brake = ProtoField.string("super73.brake", "Brake"),
    throttle_threshold = ProtoField.uint16("super73.throttle_threshold", "Throttle Threshold", base.DEC),
    throttle_raw = ProtoField.uint16("super73.throttle_raw", "Throttle Raw", base.DEC),
    throttle_percent = ProtoField.string("super73.throttle_percent", "Throttle Percent"),
    data_decoded = ProtoField.string("super73.data_decoded", "Data Decoded"),
    can_padding = ProtoField.string("super73.can_padding", "CAN Padding")
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
local f_can_padding = Field.new("can.padding")

-- variables to persist across all packets
local can_data = {} -- indexed per packet
can_data.padding = {}

super73_proto.fields = fields

function is_request(frame_length)
    return frame_length == 0
end

function super73_proto.dissector(tvb, pinfo, tree)
    local id = f_can_id().value
    local frame_length = f_can_len().value
    local frame_is_request = is_request(frame_length)

    local data

    local subtree = tree:add(super73_proto, tvb)
    subtree:add(fields.id, id)

    -- Special case; read padding as data.
    if (frame_is_request) then
        data = can_data.padding[pinfo.number]:tvb()
        -- For debugging.
        -- subtree:add(fields.can_padding, tostring(can_data.padding[pinfo.number]))
        frame_length = 8
    else
        data = tvb(0, frame_length)
    end

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
        if (frame_is_request) then
            local hex_string = tostring(can_data.padding[pinfo.number])
            local ascii = ""
            for i = 1, #hex_string, 2 do
                local hex_pair = hex_string:sub(i, i + 1)
                ascii = ascii .. string.char(tonumber(hex_pair, 16))
            end
            subtree:add(fields.data_ascii, ascii)
        else
            subtree:add(fields.data_ascii, tostring(data:string()))
        end

        -- Data: Hex and Little Endian
        for i = 1, frame_length do
            subtree:add(fields["data_" .. i], data(i-1, 1))
            if i % 2 == 1 and i < frame_length then -- Check if i is odd and there is a next byte
                subtree:add(fields["data_" .. i .. "_" .. i+1 .. "_le"], data(i-1, 2):le_uint())
            end
        end

        -- Data: Decoded
        if (id == 0x201) then
            -- Speed and Brake
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
        elseif (id == 0x222) then
            -- Throttle
            local threshold = data(0, 2):le_uint();
            subtree:add(fields.throttle_threshold, threshold)

            local throttle_raw = data(2, 2):le_uint();
            subtree:add(fields.throttle_raw, throttle_raw)

            local throttle_percent = (throttle_raw - threshold) / (3800 - threshold) * 100;
            if throttle_percent < 0 then
                throttle_percent = 0
            elseif throttle_percent > 100 then
                throttle_percent = 100
            end
            throttle_percent = string.format("%.1f", throttle_percent)
            subtree:add(fields.throttle_percent, throttle_percent)
        end
    else
        subtree:add(fields.device_name, "Unknown")
        subtree:add(fields.subdevice_name, "Unknown")
    end
end

for id in pairs(devices) do
    DissectorTable.get("can.id"):add(id, super73_proto)
end

-- Thanks to chuckc for assistance on this.
function super73_canpad_proto.dissector(tvb, pinfo, tree)
    if f_can_padding() ~= nil then
        can_data.padding[pinfo.number] = f_can_padding().value
    else
        can_data.padding[pinfo.number] = nil
    end
end

register_postdissector(super73_canpad_proto)
