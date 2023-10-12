-- canbus-super73.lua
-- By Jon Peck, jpeck@fluxsauce.com
-- https://github.com/fluxsauce/wireshark-canbus-super73

set_plugin_info({
    version = "0.1.0",
    author = "Jon Peck",
    description = "Super73 CAN Bus Dissector",
})

local super73_proto = Proto("Super73", "Super73 CAN Bus")
local super73_canpad_proto = Proto("Super73CANPadding", "Super73 CAN Padding")

local fields = {
    id = ProtoField.uint32("super73.id", "ID", base.HEX),
    device_name = ProtoField.string("super73.device", "Device"),
    subdevice_name = ProtoField.string("super73.subdevice", "Subdevice"),
    data_1 = ProtoField.uint8("super73.data_1", "D1", base.HEX),
    data_1_bitflag = ProtoField.bool("super73.data_1_bitflag", "D1 Bitflag"),
    data_2 = ProtoField.uint8("super73.data_2", "D2", base.HEX),
    data_2_bitflag = ProtoField.bool("super73.data_2_bitflag", "D2 Bitflag"),
    data_3 = ProtoField.uint8("super73.data_3", "D3", base.HEX),
    data_3_bitflag = ProtoField.bool("super73.data_3_bitflag", "D3 Bitflag"),
    data_4 = ProtoField.uint8("super73.data_4", "D4", base.HEX),
    data_4_bitflag = ProtoField.bool("super73.data_4_bitflag", "D4 Bitflag"),
    data_5 = ProtoField.uint8("super73.data_5", "D5", base.HEX),
    data_5_bitflag = ProtoField.bool("super73.data_5_bitflag", "D5 Bitflag"),
    data_6 = ProtoField.uint8("super73.data_6", "D6", base.HEX),
    data_6_bitflag = ProtoField.bool("super73.data_6_bitflag", "D6 Bitflag"),
    data_7 = ProtoField.uint8("super73.data_7", "D7", base.HEX),
    data_7_bitflag = ProtoField.bool("super73.data_7_bitflag", "D7 Bitflag"),
    data_8 = ProtoField.uint8("super73.data_8", "D8", base.HEX),
    data_8_bitflag = ProtoField.bool("super73.data_8_bitflag", "D8 Bitflag"),
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
    can_padding = ProtoField.string("super73.can_padding", "CAN Padding"),
    battery_voltage = ProtoField.string("super73.battery_voltage", "Battery Voltage"),
    charger_amperage = ProtoField.string("super73.charger_amperage", "Charger Amperage"),
    drive_mode = ProtoField.string("super73.drive_mode", "Drive Mode"),
    headlamp = ProtoField.string("super73.headlamp", "Headlamp"),
    pas_sensitivity = ProtoField.uint8("super73.pas_sensitivity", "PAS Sensitivity", base.DEC),
    previous_frame = ProtoField.uint8("super73.previous_frame", "Previous Frame", base.DEC),
    changed = ProtoField.bool("super73.changed", "Changed"),
    battery_io = ProtoField.string("super73.battery_io", "Battery I/O"),
    battery_temp_c = ProtoField.string("super73.battery_temp_c", "Battery Temp C"),
}

local devices = {
    [0x200] = { device = "Controller", subdevice = "Range or ODO?" },
    [0x201] = { device = "Controller", subdevice = "Speed, Brake" },
    [0x202] = { device = "Controller", subdevice = "TBD 0x202" },
    [0x203] = { device = "Controller", subdevice = "TBD 0x203" },
    [0x204] = { device = "Controller", subdevice = "TBD 0x204" },
    [0x210] = {
        request = "Request Data",
        requestor = "Display",
        response = "Response Data",
        respondor = "Controller"
    },
    [0x211] = {
        request = "Request Data",
        requestor = "Display",
        response = "Response Data",
        respondor = "Controller"
    },
    [0x212] = {
        request = "Request Data",
        requestor = "Display",
        response = "Response Data",
        respondor = "Controller"
    },
    [0x222] = { device = "Controller", subdevice = "Throttle" },
    [0x265] = { device = "Controller", subdevice = "TBD 0x265" },
    [0x266] = { device = "Controller", subdevice = "TBD 0x266" },
    [0x300] = { device = "Display", subdevice = "Stats" },
    [0x302] = { device = "Display", subdevice = "TBD" },
    [0x400] = { device = "Battery", subdevice = "I/O Status" },
    [0x401] = { device = "Battery", subdevice = "Battery Voltage, Charger Amperage" },
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
local history = {}
local prev_frames = {}

function init()
    history = {}
    prev_frames = {}
end

super73_proto.fields = fields

function is_request(frame_length)
    return frame_length == 0
end

function is_bitflag(value)
    local hex_values = {
        0x40, -- equivalent to binary 1000000
        0x20, -- equivalent to binary 0100000
        0x10, -- equivalent to binary 0010000
        0x08, -- equivalent to binary 0001000
        0x04, -- equivalent to binary 0000100
        0x02, -- equivalent to binary 0000010
        0x01, -- equivalent to binary 0000001
        0x00, -- equivalent to binary 0000000
    }

    for i = 1, #hex_values do
      if value == hex_values[i] then
        return true
      end
    end

    return false
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
        data = history[id][pinfo.number].padding:tvb()
        subtree:add(fields.can_padding, tostring(history[id][pinfo.number].padding))
        frame_length = 8
    else
        data = tvb(0, frame_length)
    end

    -- Previous frame number
    local prev_frame = history[id][pinfo.number].previous_frame
    if prev_frame ~= nil then
        subtree:add(fields.previous_frame, prev_frame)
        local previous_data = history[id][pinfo.number].previous_data
        local changed = false
        if (tostring(data) ~= previous_data) then
            changed = true
        end
        if (changed) then
            subtree:add(fields.changed, changed)
        end
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
            local hex_string = tostring(history[id][pinfo.number].padding)
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
            local bit = data(i-1, 1);
            subtree:add(fields["data_" .. i], bit)
            subtree:add(fields["data_" .. i .. "_bitflag"], is_bitflag(bit:uint()))
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
        elseif (id == 0x300) then
            local drive_mode_raw = data(0, 1)
            subtree:add(fields.drive_mode, tostring(drive_mode_raw))

            local headlamp_raw = data(2, 1):uint();
            local headlamp
            if (headlamp_raw == 0x00) then
                headlamp = "Off"
            elseif (headlamp_raw == 0x01) then
                headlamp = "On"
            else
                headlamp = "Unknown"
            end
            subtree:add(fields.headlamp, headlamp)

            local pas_sensitivity_raw = data(4, 1):uint();
            local pas_sensitivity
            if (pas_sensitivity_raw == 0x00) then
                pas_sensitivity = 0
            elseif (pas_sensitivity_raw == 0x0F) then
                pas_sensitivity = 1
            elseif (pas_sensitivity_raw == 0x19) then
                pas_sensitivity = 2
            elseif (pas_sensitivity_raw == 0x2D) then
                pas_sensitivity = 3
            elseif (pas_sensitivity_raw == 0x64) then
                pas_sensitivity = 4
            end
            subtree:add(fields.pas_sensitivity, pas_sensitivity)
        elseif (id == 0x400) then
            local d3 = data(2, 1):uint();
            local d4 = data(3, 1):uint();
            local battery_io
            if (d3 == 0x08 and d4 == 0x00) then
                battery_io = "Normal"
            elseif (d3 == 0x8C and d4 == 0x80) then
                battery_io = "Charging"
            elseif (d3 == 0x00 and d4 == 0x10) then
                battery_io = "BMS Blocked"
            else
                battery_io = "Unknown"
            end
            if (battery_io) then
                subtree:add(fields.battery_io, battery_io)
            end
        elseif (id == 0x401) then
            -- Voltage and Amperage
            local battery_voltage = data(0, 2):le_uint()/1000;
            subtree:add(fields.battery_voltage, battery_voltage)
            local charger_amperage = data(4, 2):le_uint()/1000;
            subtree:add(fields.charger_amperage, charger_amperage)
        elseif (id == 0x404) then
            -- Temperature
            local temperature = data(2, 2):le_uint()/10;
            subtree:add(fields.battery_temp_c, temperature)
        end
    else
        subtree:add(fields.device_name, "Unknown")
        subtree:add(fields.subdevice_name, "Unknown")
    end

    return tree
end

for id in pairs(devices) do
    DissectorTable.get("can.id"):add(id, super73_proto)
end

function super73_canpad_proto.dissector(tvb, pinfo, tree)
    if not pinfo.visited then
        -- Invalid frame; abort.
        if f_can_id() == nil then
            return
        end

        -- Device ID.
        local id = f_can_id().value

       -- Initialize history for this ID.
        if history[id] == nil then
            history[id] = {}
        end
        if history[id][pinfo.number] == nil then
            history[id][pinfo.number] = {}
        end

        local frame_length = f_can_len().value
        local frame_is_request = is_request(frame_length)

        -- Store frame data and padding to history.
        if frame_is_request and f_can_padding() ~= nil then
            history[id][pinfo.number].padding = f_can_padding().value
        else
            history[id][pinfo.number].padding = nil
        end

        if frame_is_request ~= nil then
            local prev_frame = prev_frames[id]
            if prev_frame ~= nil then
                history[id][pinfo.number].previous_frame = prev_frame.number
                history[id][pinfo.number].previous_data = prev_frame.data
            end
            -- Set new previous frame.
            prev_frames[id] = {
                number = pinfo.number,
                data = tostring(tvb(24, frame_length)),
            }
        end
    end
end

register_postdissector(super73_canpad_proto)
