-- Define the CAN bus protocol
local canbus_proto = Proto("Super73CANBUS", "Super73 CAN Bus Protocol")

-- Fields of the CAN bus protocol
local canbus_fields = {
  ascii_data = ProtoField.string("canbus.ascii_data", "ASCII"),
  decimal_data = ProtoField.string("canbus.decimal_data", "Hex pairs to Decimal"),
  device_name = ProtoField.string("canbus.device_data", "Device")
}

-- Lookup table of CAN IDs and device names
local canbus_device_lookup = {
    [400] = "Battery",
    [500] = "Motor",
    [600] = "Controller",
    -- ...
  }

canbus_proto.fields = canbus_fields

-- Dissector function for CAN bus packets
function canbus_proto.dissector(buffer, pinfo, tree)
    length = buffer:len()
    if length == 0 then return end

    -- Create a subtree in the packet details
    local subtree = tree:add(canbus_proto, buffer(), "Super73 CAN Bus Data")
    
    -- Extract the ASCII values
    local ascii_data = ""
    for i = 0, buffer:len() - 1 do
        local byte_value = buffer(i, 1):uint()
        ascii_data = ascii_data .. string.char(byte_value)
    end

    -- Add ASCII data to the subtree
    subtree:add(canbus_fields.ascii_data, buffer(), ascii_data)

    local decimal_data = {}

    -- Combine two byte pairs and convert to decimal values
    for i = 0, buffer:len() - 1 do
        local byte_value = buffer(i, 1):uint()
        decimal_data[#decimal_data + 1] = string.format("%03d", byte_value)
    end

    -- Add hex pairs to decimal data to the subtree
    local decimal_data_str = table.concat(decimal_data, " ")
    subtree:add(canbus_fields.decimal_data, buffer(), decimal_data_str)

    -- Add device data to the subtree
    local can_id = pinfo.columns["interface_id"]
    local device_name = canbus_device_lookup[can_id]
    
    if device_name == nil then
        device_name = "Nope"
        util.dumptable(pinfo)
    end

    subtree:add(canbus_fields.device_name, buffer(), device_name)
end

-- Register the dissector
canbus_proto_table = DissectorTable.get("can.subdissector")
canbus_proto_table:add_for_decode_as(canbus_proto)