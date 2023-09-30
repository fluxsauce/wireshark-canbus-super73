local super73_subdissector = Proto("Super73", "Super73 RX CAN Bus")

local fields = {
    id = ProtoField.uint32("super73.id", "ID", base.HEX),
    device_name = ProtoField.string("super73.device", "Device"),
    subdevice_name = ProtoField.string("super73.subdevice", "Subdevice")
}

local devices = {
    [0x200] = { device = "Controller", subdevice = "Range or ODO?" },
    [0x201] = { device = "Controller", subdevice = "Speed, Brake, ..." },
    [0x202] = { device = "Controller", subdevice = "TBD" },
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

super73_subdissector.fields = fields

function super73_subdissector.dissector(buffer, pinfo, tree)
    local id = f_can_id().value
    local data = buffer(4) -- Get the data frame (everything after the ID)

    local subtree = tree:add(super73_subdissector, buffer)
    subtree:add(fields.id, id)

    local device = devices[id]
    if device then
        subtree:add(fields.device_name, device.device)
        subtree:add(fields.subdevice_name, device.subdevice)
    else
        subtree:add(fields.device_name, "Unknown")
        subtree:add(fields.subdevice_name, "Unknown")
    end
end

for id in pairs(devices) do
    DissectorTable.get("can.id"):add(id, super73_subdissector)
end