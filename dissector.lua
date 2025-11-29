-- Lua dissector for a MobiFlight USB protocol
-- Written by Wei Shuai <cpuwolf@gmail.com> 2025-Nov-29

-- Create a new protocol
local my_usb_proto = Proto("MF", "MobiFlight Serial Protocol")

-- Define fields for the protocol
local field_group = {}
--field_group[1] = ProtoField.uint8("myusb.field1", "Field 1", base.HEX)
field_group[1] = ProtoField.string("myusb.field1", "Field 2")
field_group[2] = ProtoField.string("myusb.field2", "Field 2")

my_usb_proto.fields = field_group

function mfsplit(inputString)
    local result = {}
    -- Pattern matches sequences of characters that are not ',' or ';'
    for match in inputString:gmatch("([^%;,]+)") do
        table.insert(result, match)
    end
    return result
end

-- Dissector function
function my_usb_proto.dissector(buffer, pinfo, tree)
    local subtree = tree:add(my_usb_proto, buffer(), "MobiFlight cpuwolf Protocol")

    -- Check for specific conditions (e.g., endpoint, vendor ID, or data pattern)
    -- to determine if this dissector should be applied.
    -- For demonstration, let's assume it's applied to all USB data for now.
    local parts = mfsplit(buffer():string())
    for i, v in ipairs(parts) do
        print(v)
        subtree:add(field_group[i], v)
    end
    -- Extract and add fields to the dissection tree
    --subtree:add(field_group[1], buffer(0, 1))           -- Assuming Field 1 is 1 byte at offset 0
    --subtree:add(field_group[2], buffer(1, 10):string()) -- Assuming Field 2 is a string of 10 bytes at offset 1

    pinfo.cols.protocol = "USB MF"                 -- Set the protocol column in Wireshark
end

-- Register the dissector to be called for USB bulk transfers
-- The '0xFF' is a placeholder and would need to be replaced with the relevant
-- value for the specific USB endpoint or interface.
DissectorTable.get("usb.bulk"):add(0xFF, my_usb_proto)
